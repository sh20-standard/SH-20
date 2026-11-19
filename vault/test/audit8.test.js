// The findings of docs/AUDIT.md §8 (a reading of the vault's cryptography), one test or more each:
// every test here fails on the code the reading was made on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { ownOrigins } from '../src/isolation.js';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { chain, deployEnv, tx as helperTx } from '../../indexer/test/helpers.js';
import { nodeProver, WASM } from './prover-node.js';
import { NOTE_SCHEME } from '../src/notekeys.js';
import { Sync } from '../src/sync.js';
import { memoryCache } from '../src/cache.js';
import { IndexerApi } from '../src/api.js';
import { proveSpend, planCarrier, revealFor } from '../src/send.js';
import { planList, listOutputs, listingFromChain, offerTerms, signOffer, offerValid } from '../src/market.js';
import { parseTx, serializeTx, txid as txidOf, scriptToAddress } from '../src/btc.js';
import { parseEnvelope, serializeEnvelope, NoteTree } from '../src/sh20.js';
import { fromHex, toHex } from '../src/bytes.js';
import { frHex } from '../src/fr.js';
import { listingCheck, TAKE_QUORUM } from '../src/consensus.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
/** The page's code: app.js and the panels of src/ui/ (one module per screen or flow). */
const page = () => [src('app.js'), ...readdirSync(new URL('../src/ui/', import.meta.url)).filter((f) => f.endsWith('.js')).sort().map((f) => src(`ui/${f}`))].join('\n');
const cv = JSON.parse(readFileSync(new URL('../../circuit/js/vectors.json', import.meta.url), 'utf8'));
const WPKH = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Runs `fn` with globalThis.location at `url`, as the page has it. */
async function at(url, fn) {
  const had = Object.getOwnPropertyDescriptor(globalThis, 'location');
  const u = new URL(url);
  Object.defineProperty(globalThis, 'location', { value: { pathname: u.pathname, hostname: u.hostname, search: u.search }, configurable: true });
  try {
    return await fn();
  } finally {
    if (had) Object.defineProperty(globalThis, 'location', had);
    else delete globalThis.location;
  }
}

// ---- 8.1: on a path gateway the vault warned and went on ---------------------------------------

const CID = 'bafybeigfj45xzun5mek5zvqeby6bs76ukwkslx7ifa7ipzdoylfl4pnavi';

test('8.1 no vault is created, restored from words or a backup, or unlocked on a path gateway', async () => {
  const backup = memStorage();
  await (await Vault.fromWords(backup, WORDS, 'pass')).save();
  const record = backup.getItem(STORAGE_KEY);
  await at(`https://ipfs.io/ipfs/${CID}/vault/`, async () => {
    const s = memStorage();
    await assert.rejects(Vault.create(s, 'pass'), /path gateway/);
    await assert.rejects(Vault.fromWords(s, WORDS, 'pass'), /path gateway/);
    await assert.rejects(Vault.restore(s, record, 'pass'), /path gateway/);
    assert.equal(s.getItem(STORAGE_KEY), null, 'nothing stored');
    await assert.rejects(Vault.open(backup, 'pass'), /path gateway/, 'a vault stored there earlier is not unlocked either');
  });
  await at(`https://${CID}.ipfs.dweb.link/vault/`, async () => {
    assert.ok(await Vault.open(backup, 'pass'), 'a subdomain gateway is its own origin');
  });
  await at('http://localhost:8000/vault/', async () => assert.ok(await Vault.open(backup, 'pass')));
});

test('8.1 the page says where to open the same release instead', () => {
  const o = (url) => { const u = new URL(url); return ownOrigins({ pathname: u.pathname }); };
  assert.deepEqual(o(`https://ipfs.io/ipfs/${CID}/vault/`), [`https://${CID}.ipfs.dweb.link/vault/`, `http://${CID}.ipfs.localhost:8080/vault/`]);
  assert.deepEqual(o(`https://ipfs.io/ipfs/${CID}`), [`https://${CID}.ipfs.dweb.link/`, `http://${CID}.ipfs.localhost:8080/`]);
  assert.deepEqual(o('https://gw.example/ipns/vault.sh20-test.org/vault/'), ['https://vault-sh20--test-org.ipns.dweb.link/vault/', 'http://vault-sh20--test-org.ipns.localhost:8080/vault/'], 'a DNSLink name, inlined in one label');
  const v0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';
  assert.deepEqual(o(`https://ipfs.io/ipfs/${v0}/vault/`), [`https://dweb.link/ipfs/${v0}/vault/`, `http://localhost:8080/ipfs/${v0}/vault/`], 'a CIDv0 is no DNS label: the path form that redirects');
  assert.equal(o(`https://${CID}.ipfs.dweb.link/vault/`), null);
  assert.equal(o('http://localhost:8000/vault/'), null);
});

test('8.1 on a path gateway the page stops before it reads its settings or shows a form', () => {
  const app = src('app.js');
  const stop = app.indexOf("if (gatewayKind() === 'path')");
  assert.ok(stop > 0, 'app.js checks for a path gateway');
  const block = app.slice(stop, app.indexOf('await new Promise(() => {});', stop));
  assert.match(block, /ownOrigins\(\)/, 'and names the addresses to use');
  for (const later of ['initContext()', 'loadSettings()', 'ensureIsolation()', 'renderAll()', 'Vault.open(', 'Vault.create(']) {
    const i = app.indexOf(later);
    assert.ok(i < 0 || i > stop, `${later} comes after the stop`);
  }
  const ctx = src('ui/context.js');
  assert.ok(!/path gateway/.test(ctx.slice(ctx.indexOf('function staticWarnings'))), 'no warning that lets the page go on');
});

// ---- 8.2: after a restore, an offer signed the terms the servers gave ------------------------------

async function vaultOf(m) {
  const st = memStorage();
  st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: m } }));
  return Vault.open(st);
}
const ixTx = (t, id) => ({
  txid: id,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: (i.witness ?? []).map((w) => Buffer.from(w)) })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

/** A chain with GENE, two public notes of the seller, and a LIST of 600 GENE for 5,000 sats with a real proof. */
async function listedChain() {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }) });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 })); // N = 0: the DEPLOY is only setup here
  const seller = await vaultOf(cv.wallets[0].m);
  const npks = [(await seller.opening(0)).npk, (await seller.opening(1)).npk];
  const b = c.block(...npks.map((npk) => helperTx({ env: { type: 'MINT', ticker: 'GENE', npk }, burnSats: 1000n })));
  for (const [k, e] of b.events.filter((x) => x.type === 'MINT').entries()) {
    const n = await seller.addNote({ index: k, ticker: 'GENE', v: 1000n, txid: null, status: 'in tree', pos: e.pos });
    await seller.updateNote(n.id, { spent: 'no' });
  }
  const tree = new NoteTree();
  for (const leaf of ix.tree.leaves) tree.append(leaf);
  const sync = { height: ix.height, tree, witness: (pos) => ({ siblings: tree.path(pos) }) };
  const lockIndex = await seller.reserveLock();
  const lock = await seller.lockOutput(lockIndex);
  const payScript = fromHex('0014' + '66'.repeat(20));
  const built = await planList({ vault: seller, sync, tip: c.next - 1, ticker: 'GENE', amount: 600n, price: 5000n, payScript, lockKey: lock.key });
  const envelope = await proveSpend(nodeProver(), built);
  const carrier = { payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: c.next - 1, outputs: listOutputs(lock.script) };
  const reveal = revealFor(planCarrier({ envelope, ...carrier }), 'c2'.repeat(32));
  const r = c.block(ixTx(reveal.tx, reveal.txid));
  assert.equal(r.events[0]?.type, 'LIST', JSON.stringify(r.rejected));
  const rec = { id: `list:${lockIndex}`, lockIndex, ticker: 'GENE', amount: '600', price: '5000', payScript: toHex(payScript), listTxid: reveal.txid, state: 'ACTIVE' };
  return { ix, c, seller, lock, rec, envelope, carrier, reveal };
}

/**
 * The same transaction with another LIST envelope in its witness, as a lying Esplora can serve it:
 * the txid covers no witness, so it is unchanged. The proof and the nullifiers are the real ones.
 */
function swapped({ envelope, carrier, reveal }, price, payScript) {
  const { env } = parseEnvelope(Buffer.from(envelope));
  const forged = serializeEnvelope({ ...env, price, payScript: Buffer.from(payScript) });
  assert.equal(forged.length, envelope.length);
  const other = revealFor(planCarrier({ envelope: forged, ...carrier }), 'c2'.repeat(32));
  const tx = { ...reveal.tx, vin: reveal.tx.vin.map((i, k) => (k === 0 ? { ...i, witness: other.tx.vin[0].witness } : i)) };
  return toHex(serializeTx(tx));
}

test('8.2 an offer is signed only for terms the vault vouches for: its record, or a proof over its notes', async () => {
  const L = await listedChain();
  const { ix, seller, lock, rec, reveal } = L;
  const thief = fromHex('0014' + 'ee'.repeat(20)); // as long as the real payee: the reveal keeps its size and its outputs
  const server = await listen(ix, { port: 0 });
  try {
    const sync = new Sync(memoryCache(), 'audit');
    await sync.sync(new IndexerApi(`http://127.0.0.1:${server.address().port}`));
    const ownNullifiers = new Set();
    for (const n of seller.state.notes) ownNullifiers.add(frHex(await seller.nullifier(n)));
    const p = nodeProver();
    const terms = (r, l, extra = {}) => offerTerms({ rec: r, l, lockKey: lock.key, ownNullifiers, rootAt: (a) => sync.rootAt(a), verify: p.verify, ...extra });

    // the reading of the audit, reproduced: same txid, another envelope, and listingFromChain takes it
    const forgedHex = swapped(L, 1n, thief);
    assert.equal(txidOf(parseTx(fromHex(forgedHex))), reveal.txid, 'the txid does not cover the witness');
    const lying = { ...ix.listings.get(reveal.txid), price: '1', payScript: toHex(thief), amount: '600' }; // an indexer that lies too
    const forged = listingFromChain(reveal.txid, forgedHex, lying);
    assert.equal(forged.price, 1n);
    assert.ok(offerValid(forged, signOffer(lock.secret, forged)), 'a signature of those terms would let the thief take the lock');
    const genuine = listingFromChain(reveal.txid, reveal.hex, { ...ix.listings.get(reveal.txid), amount: '600', price: '5000' });

    // a listing this vault sent: its own record decides, and any difference is refused
    const sent = { ...rec, source: 'sent' };
    assert.equal((await terms(sent, genuine)).vouched, 'record');
    await assert.rejects(terms(sent, forged), /differs from the one this vault sent \(price 1 sats, not 5000; payee 0014(ee){20}, not 0014(66){20}\)/);

    // after a restore (the record was rebuilt from the chain): the envelope must spend this vault's notes, with a proof that verifies
    const found = { ...rec, source: 'chain' };
    assert.equal(sync.rootAt(ix.height), ix.tree.root, 'the local root, block by block');
    assert.equal(sync.rootAt(ix.height - 1), ix.roots.get(ix.height - 1));
    assert.equal(sync.rootAt(ix.height + 1), undefined);
    const ok = await terms(found, genuine);
    assert.deepEqual([ok.vouched, ok.why], ['proof', null]);
    const bad = await terms(found, forged);
    assert.equal(bad.vouched, 'ask', 'the real proof does not verify for the swapped terms');
    assert.match(bad.why, /proof does not verify/);
    assert.equal((await terms(found, genuine, { ownNullifiers: new Set() })).vouched, 'ask', 'no note of this vault among its nullifiers');
    assert.match((await terms(found, genuine, { rootAt: () => undefined })).why, /does not reach block/);
    assert.equal((await terms({ ...rec }, genuine)).vouched, 'proof', 'a record from before this check is not vouched by itself');

    // the lock must be this vault's, whatever vouches for the rest
    await assert.rejects(terms(sent, { ...genuine, lockKey: new Uint8Array(32).fill(7) }), /another key than this vault's lock #0/);
  } finally {
    server.close();
  }
});

test('8.2 the page signs nothing it has not vouched for or shown: offerTerms, then a question naming price and payee', () => {
  const app = page();
  const body = app.slice(app.indexOf('async function copyOffer('), app.indexOf('async function checkOffer('));
  assert.ok(body.indexOf('offerTerms(') > 0 && body.indexOf('offerTerms(') < body.indexOf('signOffer('), 'the terms are checked before signing');
  assert.match(body, /t\.vouched === 'ask' && !confirm\(`[^`]*\$\{terms\}/, 'unvouched terms are shown and asked about');
  assert.match(body, /return;\s*\}\s*const offer = encodeOffer/, 'a no signs nothing');
  assert.match(body, /Offer signed for: /, 'the signed terms are shown with the offer');
  assert.equal((app.match(/signOffer\(/g) ?? []).length, 1, 'no other path signs an offer');
  assert.match(app, /source: 'sent' \}\)/, 'a listing sent here is recorded as such');
  assert.match(app, /source: 'chain' \}\)/, 'one found again after a restore is not');
  assert.equal(scriptToAddress(fromHex('0014751e76e8199196d454941c45d1b3a323f1433bd6')), WPKH, 'the payee is shown as an address');
});

// ---- 8.3: one indexer that knew the listing was enough, and one that did not was ignored ------------

const LISTED = { listTxid: 'ab'.repeat(32), ticker: 'GENE', amount: 600n, price: 5000n, payScript: '0014' + '66'.repeat(20), lock: `${'ab'.repeat(32)}:0`, lockKey: 'cd'.repeat(32), state: 'ACTIVE', height: 9 };
const knows = (base, l = LISTED) => ({ base, listing: async () => l });
const unknown = (base) => ({ base, listing: async () => null }); // IndexerApi.listing on a 404
const down = (base) => ({ base, listing: async () => { throw new Error('unreachable'); } });

test('8.3 an indexer that answers and does not know the listing refuses it; a TAKE needs two that agree', async () => {
  assert.equal(TAKE_QUORUM, 2);
  // the case of the reading: a lying indexer reports ACTIVE, the honest ones have never accepted the LIST
  await assert.rejects(listingCheck([knows('liar'), unknown('honest')], LISTED.listTxid), /honest does not know this listing, which liar reports/);
  await assert.rejects(listingCheck([unknown('honest'), knows('liar'), unknown('other')], LISTED.listTxid), /honest, other do not know this listing/);
  await assert.rejects(listingCheck([unknown('a'), unknown('b')], LISTED.listTxid), /no indexer knows this listing/);
  // other terms or another state: refused, naming what differs
  await assert.rejects(listingCheck([knows('a'), knows('b', { ...LISTED, price: 1n })], LISTED.listTxid), /b and a disagree on this listing: price "1" ≠ "5000"/);
  await assert.rejects(listingCheck([knows('a'), knows('b', { ...LISTED, state: 'SOLD' })], LISTED.listTxid), /state "SOLD" ≠ "ACTIVE"/);
  // one alone is not enough for a TAKE, even when the others are only unreachable
  const one = await listingCheck([knows('a'), down('b')], LISTED.listTxid);
  assert.deepEqual([one.agreed, one.enough, one.down], [1, false, ['b']]);
  assert.equal((await listingCheck([knows('a')], LISTED.listTxid)).enough, false);
  const two = await listingCheck([knows('a'), knows('b'), down('c')], LISTED.listTxid);
  assert.deepEqual([two.agreed, two.enough], [2, true]);
  assert.equal(two.listing, LISTED);
});

test('8.3 the page checks the quorum before a TAKE, and says why it cannot buy', () => {
  const app = page();
  const take = app.slice(app.indexOf('async function sendTake('), app.indexOf('async function sendCancel('));
  assert.ok(take.indexOf('if (!fresh.enough) throw') > 0 && take.indexOf('if (!fresh.enough) throw') < take.indexOf('buildTake('), 'checked again right before the TAKE is built');
  const checked = app.slice(app.indexOf('async function checkedListing('), app.indexOf('/**\n * One of the vault'));
  assert.match(checked, /listingCheck\(indexers, listTxid\)/);
  assert.match(app, /disabled: !st\.wallet \|\| c\.state !== 'ACTIVE' \|\| !c\.enough/, 'no Buy button without the quorum');
  assert.ok(!/one indexer: add others in Settings to cross-check/.test(app), 'the old message, which described another case');
});
