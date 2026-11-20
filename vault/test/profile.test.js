// The vault's own profile (profile.js): N, D, W, K_min and A embedded in the page, every /status
// compared with it, a DEPLOY reveal that waits N blocks of that profile, and a refused DEPLOY whose
// burnt notes come back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { deployEnv, fr, mockVerifier, spend, tx as helperTx } from '../../indexer/test/helpers.js';
import { PROFILE } from '../src/profile.js';
import { REPORTED, crossCheck, profileCheck, profileDiff, refusalAgreed } from '../src/consensus.js';
import { ANCHOR_MAX_AGE, REFUSAL_DEPTH, anchor, deploySchedule, refusedSpend } from '../src/send.js';
import { IndexerApi } from '../src/api.js';
import { Vault } from '../src/keys.js';
import { Sync } from '../src/sync.js';
import { memoryCache } from '../src/cache.js';
import { frHex } from '../src/fr.js';

const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
// the page's code, every module of it (app.js and src/ui/)
const page = () => ['app.js', ...readdirSync(new URL('../src/ui/', import.meta.url)).sort().map((f) => `ui/${f}`)].map(src).join('\n');
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};
// what an honest indexer on the reference profile reports in /status (indexer/src/api.js)
const honest = () => ({
  network: DEFAULT_PROFILE.network, height: 20, digest: 'd'.repeat(64), activationHeight: DEFAULT_PROFILE.activationHeight,
  deployBurn: String(DEFAULT_PROFILE.deployBurn), deployMaturity: DEFAULT_PROFILE.deployMaturity, anchorWindow: DEFAULT_PROFILE.anchorWindow,
  genesis: DEFAULT_PROFILE.genesis.ticker,
});
const ix = (base, status, token = null) => ({
  base,
  status: async () => {
    if (!status) throw new Error('connection refused');
    return status;
  },
  token: async () => token,
});

test('1. the vault embeds its profile: N = 6, D = 1000, W, K_min and A of DEFAULT_PROFILE, and reads none of them from /status', () => {
  assert.deepEqual({ ...PROFILE }, {
    network: 'signet', activationHeight: DEFAULT_PROFILE.activationHeight, deployBurn: 1000n, deployMaturity: 6,
    anchorWindow: DEFAULT_PROFILE.anchorWindow, anchorMinDepth: DEFAULT_PROFILE.anchorMinDepth, genesis: 'SH20',
  });
  assert.ok(Object.isFrozen(PROFILE));
  assert.match(src('profile.js'), /from '\.\.\/\.\.\/indexer\/src\/constants\.js'/, 'the same constants as the reference indexer, not a copy');

  // no module takes a profile value from an indexer: consensus.js only compares them (profileDiff)
  for (const f of readdirSync(new URL('../src/', import.meta.url)).filter((x) => x.endsWith('.js') && x !== 'consensus.js').concat(readdirSync(new URL('../src/ui/', import.meta.url)).map((x) => `ui/${x}`))) {
    assert.doesNotMatch(src(f), /status\??\.(deployBurn|deployMaturity|anchorWindow|anchorMinDepth|activationHeight)\b/, f);
  }
  assert.doesNotMatch(page(), /st\.profiles\b|profileOf\(/, 'no profile kept from the indexers');

  // W and K_min decide the anchor of every spend
  const sync = { height: 100, tree: { root: 7n } };
  assert.equal(ANCHOR_MAX_AGE, PROFILE.anchorWindow - 10);
  assert.deepEqual(anchor(sync, 100), { anchorHeight: 100, root: 7n });
  assert.throws(() => anchor(sync, 100 + ANCHOR_MAX_AGE + 1), /blocks old: sync again/);
  assert.throws(() => anchor(sync, 100 - PROFILE.anchorMinDepth), /less than K_min/, 'a tree ahead of the tip by K_min or more');
});

test('2. every value of /status is compared with that profile: an indexer that differs is named with what differs, and nothing is done', async () => {
  assert.deepEqual(REPORTED, ['network', 'activationHeight', 'deployBurn', 'deployMaturity', 'anchorWindow', 'genesis']);
  assert.deepEqual(profileDiff(honest()), []);
  assert.deepEqual(profileDiff({ ...honest(), deployBurn: 1000 }), [], 'a number or a string, the same value');
  for (const k of REPORTED) {
    assert.deepEqual(profileDiff({ ...honest(), [k]: undefined }), [`${k} not reported (the vault has ${PROFILE[k]})`], `${k} missing`);
    assert.match(profileDiff({ ...honest(), [k]: 'other' }).join(), new RegExp(`^${k} other, the vault has `), `${k} different`);
  }
  for (const bad of ['1e3', '01000', '1000.0', 999]) assert.equal(profileDiff({ ...honest(), deployBurn: bad }).length, 1, `deployBurn ${bad}`);

  // one indexer differs: it is named, with what differs; one that does not answer is not compared
  let r = await profileCheck([ix('http://a', honest()), ix('http://b', { ...honest(), anchorWindow: 1000 }), ix('http://c', null)]);
  assert.deepEqual(r, { answered: 2, problems: ['http://b follows another profile: anchorWindow 1000, the vault has 100'] });
  r = await profileCheck([ix('http://a', null)]);
  assert.deepEqual(r.problems, ['no indexer answered']);

  // a mint: crossCheck refuses it
  const token = { ticker: 'SH20', genesis: true };
  const c = await crossCheck([ix('http://a', honest(), token), ix('http://b', { ...honest(), activationHeight: 77 }, token)], 'SH20', { sleep: async () => {} });
  assert.deepEqual([c.agreed, c.problems], [0, [`http://b follows another profile: activationHeight 77, the vault has ${PROFILE.activationHeight}`]]);

  // the page asks every indexer again before acting: a DEPLOY (sendDeploy, carry), its reveal (broadcastDeployReveal,
  // processDeploys), a burn, a LIST or a transfer (carry), a TAKE, a cancel or a CLAIM (sendFunded)
  const p = page();
  const body = (name) => p.slice(p.indexOf(name), p.indexOf('\n}\n', p.indexOf(name)));
  assert.match(src('ui/context.js'), /export async function requireProfile\(\) \{\s*st\.profile = await profileCheck\(indexers\);\s*if \(st\.profile\.problems\.length\) throw/);
  for (const f of ['async function carryOnce(', 'async function sendFunded(', 'export async function broadcastDeployReveal(', 'async function sendDeploy(']) {
    assert.match(body(f), /await requireProfile\(\);/, f);
  }
  const carry = body('async function carryOnce(');
  assert.ok(carry.indexOf('await requireProfile();') < carry.indexOf('await plan()'), 'before anything is proved or signed');
  const fund = body('async function sendFunded(');
  assert.ok(fund.indexOf('await requireProfile();') < fund.indexOf('signFunded('));
  for (const f of ['async function sendTake(', 'async function sendCancel(', 'async function sendClaim(']) assert.match(body(f), /await sendFunded\(/, f);
  for (const f of ['async function sendBurn(', 'async function sendList(', 'async function sendTransfer(']) assert.match(body(f), /await carry\(/, f);
  const deploys = body('export async function processDeploys(');
  assert.ok(deploys.indexOf('profileCheck(indexers)') < deploys.indexOf('await broadcastDeployReveal(p)'), 'a due reveal waits while an indexer differs');
  assert.match(body('function deployBurn('), /if \(pr\.problems\.length\) return \{ D: null/, 'the deploy screen offers nothing');
});

test('3. a DEPLOY reveal waits N blocks of the embedded profile, whatever the record or the indexers say', () => {
  // a record written from an indexer that said N = 0 and W = 10,000
  const p = { deploy: { N: 0, W: 10000 }, anchorHeight: 10 };
  assert.deepEqual(deploySchedule(p, { commitHeight: 100, tip: 100 }), { state: 'waiting', blocks: 5 }, 'mined at 100: the reveal may land at 106, not 101');
  assert.deepEqual(deploySchedule(p, { commitHeight: 100, tip: 104 }), { state: 'waiting', blocks: 1 });
  assert.deepEqual(deploySchedule(p, { commitHeight: 100, tip: 105 }), { state: 'ready', blocks: 0 });
  assert.equal(deploySchedule(p, { commitHeight: 100, tip: 109 }).state, 'ready', 'lands at 110 = anchor + W of the profile');
  assert.equal(deploySchedule(p, { commitHeight: 100, tip: 110 }).state, 'expired', 'W of the profile, not the record\'s');
  assert.deepEqual(deploySchedule({ deploy: {} }, { commitHeight: null, tip: 100 }), { state: 'unconfirmed', blocks: null });

  // the page schedules every reveal with deploySchedule, and never reads N or W from a record or a /status
  const pg = page();
  assert.doesNotMatch(pg, /revealSchedule\(/);
  assert.equal([...pg.matchAll(/deploySchedule\(p, /g)].length, 2, 'processDeploys and broadcastDeployReveal');
  assert.doesNotMatch(pg, /p\.deploy\.(N|W)\b|deploy\.N\b/);
  assert.match(pg, /const N = PROFILE\.deployMaturity;/);
});

// blocks from A on (indexer/test/helpers.js chain() starts at 1)
function chainFrom(indexer, start) {
  let h = start;
  return { block: (...txs) => indexer.applyBlock({ height: h++, hash: `h${h}`, txs }), get next() { return h; } };
}

/** A vault holding one SH20 note of D, and a DEPLOY that burns it, mined `age` blocks after its commit. */
async function deployBurning(age) {
  const idx = new Indexer({ profile: { activationHeight: PROFILE.activationHeight }, verifier: mockVerifier() }); // the reference profile: D = 1000, N = 6
  const c = chainFrom(idx, PROFILE.activationHeight);
  c.block();
  const v = await Vault.create(memStorage());
  const o = await v.reserveNote();
  const mint = c.block(helperTx({ env: { type: 'MINT', ticker: 'SH20', npk: o.npk } }));
  const note = await v.addNote({ index: o.index, ticker: 'SH20', v: PROFILE.deployBurn, txid: null, status: 'in tree', pos: mint.events[0].pos });
  const nf = await v.nullifier(note);
  const sp = spend(c.next - 1);
  sp.nf = [nf, fr()];
  const H = c.next;
  const revealTxid = 'ab'.repeat(32);
  const r = c.block(helperTx({ env: deployEnv({ ticker: 'SNIP', start: H + 20, unlock: H + 20, spend: sp }), id: revealTxid, prevHeight: H - age }));
  for (let i = 1; i < REFUSAL_DEPTH; i++) c.block();
  const pid = await v.addPending({ kind: 'DEPLOY', inputs: [note.id], revealTxid });
  await v.updatePending(pid, { status: 'broadcast' });
  return { idx, v, note, nf, r, H, pid, mintHeight: mint.height };
}

/** The vault's sync, and the spent status of its notes as notes-panel.js checkOwned sets it. */
async function synced(idx, v) {
  const server = await listen(idx, { port: 0 });
  try {
    const s = new Sync(memoryCache(), 'profile');
    await s.sync(new IndexerApi(`http://127.0.0.1:${server.address().port}`));
    for (const n of v.state.notes) {
      const at = s.spentAt(frHex(await v.nullifier(n)));
      await v.updateNote(n.id, { pathAt: s.height, spent: at === undefined ? 'unknown' : at === null ? 'no' : `block ${at}` });
    }
    return s;
  } finally {
    server.close();
  }
}

test('4. a refused DEPLOY records no nullifier, and the vault gives back the notes it had reserved', async () => {
  // refused: its commit is one block old, not N
  const { idx, v, note, nf, r, H, pid, mintHeight } = await deployBurning(1);
  assert.deepEqual(r.rejected.map((x) => x.reason), [`DEPLOY commit confirmed less than ${PROFILE.deployMaturity} blocks before`]);
  assert.equal(idx.nullifiers.has(frHex(nf)), false, 'no nullifier recorded: the SH20 are not burnt');
  assert.equal(idx.token('SH20').burned, 0n);
  assert.equal(v.state.notes[0].status, 'spending', 'reserved by the DEPLOY');
  const s = await synced(idx, v);
  const p = v.state.pending.find((x) => x.id === pid);
  assert.equal(v.state.notes[0].spent, 'no', 'the vault does not count it as spent');
  const at = { revealHeight: H, syncHeight: s.height, nullifiersKnown: s.nullifiersKnown };
  assert.equal(refusedSpend(p, v.state.notes, at), true);
  assert.equal(refusedSpend(p, v.state.notes, { ...at, syncHeight: H + REFUSAL_DEPTH - 2 }), false, 'not before the reveal is REFUSAL_DEPTH deep');
  assert.equal(refusedSpend(p, v.state.notes, { ...at, nullifiersKnown: false }), false, 'not without the full nullifier list');
  assert.equal(refusedSpend(p, v.state.notes, { ...at, revealHeight: null }), false, 'not while the reveal is unconfirmed');
  assert.equal(refusedSpend({ ...p, status: 'waiting maturity' }, v.state.notes, at), false);
  await v.releaseInputs(p.inputs);
  assert.equal(v.state.notes.find((n) => n.id === note.id).status, 'in tree', 'back in the balance and spendable');

  // accepted (its commit is N blocks old): the nullifier is recorded, and the note stays spent
  const ok = await deployBurning(PROFILE.deployMaturity);
  assert.deepEqual(ok.r.rejected, []);
  assert.equal(ok.idx.nullifiers.has(frHex(ok.nf)), true);
  const s2 = await synced(ok.idx, ok.v);
  assert.equal(ok.v.state.notes[0].spent, `block ${ok.H}`);
  assert.equal(refusedSpend(ok.v.state.pending[0], ok.v.state.notes, { revealHeight: ok.H, syncHeight: s2.height, nullifiersKnown: true }), false);

  // not on the primary's word alone: every configured indexer must say so, from its full nullifier list
  const refusedAt = { from: mintHeight, atLeast: H + REFUSAL_DEPTH - 1 }; // from the block that created the note
  const servers = await Promise.all([idx, idx, ok.idx].map((x) => listen(x, { port: 0 })));
  try {
    const [a, b, c] = servers.map((x) => new IndexerApi(`http://127.0.0.1:${x.address().port}`));
    assert.deepEqual(await refusalAgreed([a, b], [frHex(nf)], refusedAt), { ok: true, why: null });
    // an indexer that saw the DEPLOY accepted (another chain of events): the notes stay reserved
    const spent = await refusalAgreed([a, c], [frHex(ok.nf), frHex(nf)], refusedAt);
    assert.equal(spent.ok, false);
    assert.match(spent.why, new RegExp(`${c.base} has its nullifier spent at block ${ok.H}`));
    const down = { base: 'http://down', status: async () => { throw new Error('connection refused'); }, nullifiers: async () => [] };
    assert.deepEqual(await refusalAgreed([a, down], [frHex(nf)], refusedAt), { ok: false, why: 'http://down did not answer' });
    const other = { base: 'http://other', status: async () => ({ ...(await a.status()), deployMaturity: 0 }), nullifiers: async () => [] };
    assert.match((await refusalAgreed([a, other], [frHex(nf)], refusedAt)).why, /^http:\/\/other follows another profile: deployMaturity 0/);
    assert.match((await refusalAgreed([a], [frHex(nf)], { ...refusedAt, atLeast: H + 50 })).why, /not yet/);
    assert.deepEqual(await refusalAgreed([], [frHex(nf)], refusedAt), { ok: false, why: 'no indexer configured' });
    // the note spent by an earlier spend, before this reveal: the list since the note's block shows it
    const E = H - 1; // a block before the reveal's
    const earlier = { base: 'http://earlier', status: () => a.status(), nullifiers: async (f) => (f <= E ? [{ nullifier: frHex(nf), height: E }] : []) };
    assert.deepEqual(await refusalAgreed([a, earlier], [frHex(nf)], refusedAt), { ok: false, why: `http://earlier has its nullifier spent at block ${E}` });
    assert.equal((await refusalAgreed([a, earlier], [frHex(nf)], { ...refusedAt, from: H })).ok, true, 'what a list since the reveal alone would miss');
    assert.match((await refusalAgreed([a], [frHex(nf)], { ...refusedAt, from: -1 })).why, /heights are unknown/);
  } finally {
    for (const x of servers) x.close();
  }

  // the page: after every sync, refused spends give their notes back, once every indexer agrees, and say so
  const pg = page();
  const sn = pg.slice(pg.indexOf('export async function syncNotes('));
  assert.ok(sn.indexOf('await checkOwned(s);') < sn.indexOf('refused = await settleRefused(s);'), 'once the notes\' spends are known');
  const settle = pg.slice(pg.indexOf('async function settleRefused('), pg.indexOf('export async function syncNotes('));
  const order = ['if (!refusedSpend(p, v.state.notes,', 'const from = Math.min(...inputs.map((n) => s.leafHeights[n.pos] ?? -1));',
    'const agreed = await refusalAgreed(indexers, nfs, { from,', 'if (!agreed.ok) {', 'await v.releaseInputs(p.inputs);'].map((x) => settle.indexOf(x));
  assert.ok(order.every((x, k) => x > 0 && (k === 0 || x > order[k - 1])), `refused, every indexer since the note's block, then released: ${order}`);
});

test('5. every indexer lying together on N and D: the vault refuses to mint, deploy, burn or spend, names each, and still waits N', async () => {
  const liars = () => [ix('http://a', { ...honest(), deployMaturity: 0, deployBurn: '0' }, { ticker: 'SH20', genesis: true }),
    ix('http://b', { ...honest(), deployMaturity: 0, deployBurn: '0' }, { ticker: 'SH20', genesis: true })];
  const each = ['http://a', 'http://b'].map((b) => `${b} follows another profile: deployBurn 0, the vault has 1000; deployMaturity 0, the vault has 6`);
  // they agree with each other: compared with the vault, not with each other
  const r = await profileCheck(liars());
  assert.deepEqual(r, { answered: 2, problems: each });
  const c = await crossCheck(liars(), 'SH20', { sleep: async () => {} });
  assert.deepEqual([c.agreed, c.problems], [0, each], 'the mint is refused');
  // whatever they say, a reveal waits N = 6 of the profile
  assert.equal(deploySchedule({ deploy: { N: 0 }, anchorHeight: null }, { commitHeight: 100, tip: 101 }).state, 'waiting');
});
