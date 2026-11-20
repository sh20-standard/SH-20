// The vault's own profile (profile.js): N, D, W, K_min and A embedded in the page, every /status
// compared with it, and a DEPLOY reveal that waits N blocks of that profile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { PROFILE } from '../src/profile.js';
import { REPORTED, crossCheck, profileCheck, profileDiff } from '../src/consensus.js';
import { ANCHOR_MAX_AGE, anchor, deploySchedule } from '../src/send.js';

const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
// the page's code, every module of it (app.js and src/ui/)
const page = () => ['app.js', ...readdirSync(new URL('../src/ui/', import.meta.url)).sort().map((f) => `ui/${f}`)].map(src).join('\n');
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
