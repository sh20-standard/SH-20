// The findings of docs/AUDIT.md §8 (a reading of the vault's cryptography), one test or more each,
// 8.1 to 8.6: each checks a behaviour the code read for §8 did not have (8.2 reproduces the reading:
// a swapped LIST envelope under the same txid).
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
import { matchNotes } from '../src/match.js';
import { planList, listOutputs, listingFromChain, offerTerms, signOffer, offerValid } from '../src/market.js';
import { parseTx, serializeTx, txid as txidOf, scriptToAddress } from '../src/btc.js';
import { parseEnvelope, serializeEnvelope, NoteTree } from '../src/sh20.js';
import { fromHex, toHex } from '../src/bytes.js';
import { frHex } from '../src/fr.js';
import { listingCheck, TAKE_QUORUM, digestAgreement, agreementText } from '../src/consensus.js';
import { scanOutput, wallet } from '../src/notekeys.js';
import { mockVerifier } from '../../indexer/test/helpers.js';
import { seal, decodeAddress } from '../src/sh20.js';
import { REORG_MARGIN } from '../src/sync.js';

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
    // the swap: a note of this vault, the root at the anchor, and the real proof fails for the swapped body: refused
    await assert.rejects(terms(found, forged), /not signed: the LIST's proof does not verify for the terms on chain/);
    // asked only when the vault cannot check
    assert.equal((await terms(found, genuine, { ownNullifiers: new Set() })).vouched, 'ask', 'no note of this vault among its nullifiers');
    assert.match((await terms(found, genuine, { rootAt: () => undefined })).why, /does not reach block/);
    const unloaded = await terms(found, forged, { verify: async () => { throw new Error('the prover is not loaded'); } });
    assert.deepEqual([unloaded.vouched, unloaded.why], ['ask', 'the LIST\'s proof could not be checked (the prover is not loaded)']);
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
  assert.match(app + src('match.js'), /source: 'chain' \}\)/, 'one found again after a restore is not (matchListings, since §8.9)');
  assert.equal(scriptToAddress(fromHex('0014751e76e8199196d454941c45d1b3a323f1433bd6')), WPKH, 'the payee is shown as an address');
});

// ---- 8.3: one indexer that knew the listing was enough, and one that did not was ignored ------------

const LISTED = { listTxid: 'ab'.repeat(32), ticker: 'GENE', amount: 600n, price: 5000n, payScript: '0014' + '66'.repeat(20), lock: `${'ab'.repeat(32)}:0`, lockKey: 'cd'.repeat(32), state: 'ACTIVE', height: 9 };
// each at block 20, the LIST (block 9) twelve blocks deep: deep enough for a TAKE (vault-1)
const knows = (base, l = LISTED) => ({ base, listing: async () => l, status: async () => ({ height: 20 }) });
const unknown = (base) => ({ base, listing: async () => null, status: async () => ({ height: 20 }) }); // IndexerApi.listing on a 404
const down = (base) => ({ base, listing: async () => { throw new Error('unreachable'); }, status: async () => ({ height: 20 }) });

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
  assert.deepEqual([two.agreed, two.enough, two.depth, two.deep], [2, true, 12, true]);
  assert.deepEqual(two.listing, LISTED);
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

// ---- 8.4: without a passphrase, the master secret and the words were stored and backed up in clear --

test('8.4 no backup in clear; a passphrase can be added, and changed with the current one', async () => {
  const st = memStorage();
  const v = await Vault.fromWords(st, WORDS); // created without a passphrase: stored in clear, as before
  assert.ok(!v.encrypted);
  await assert.rejects(v.exportBackup(), /no backup in clear: set a passphrase first/);
  await assert.rejects(v.setPassphrase(''), /cannot be empty/);
  assert.equal(await v.checkPassphrase('anything'), false, 'nothing to check against on a clear vault');

  await v.setPassphrase('first');
  assert.ok(v.encrypted);
  const rec = st.getItem(STORAGE_KEY);
  assert.ok(!/plain|seed|abandon/.test(rec), 'the copy on this device is encrypted at once');
  // the backup is the whole vault, encrypted under the same passphrase (format 0: its notes in it, since vault-3)
  const backup = await v.exportBackup();
  assert.ok(!/plain|seed|abandon/.test(backup), 'and so is the backup');
  assert.equal(JSON.parse(backup).salt, JSON.parse(rec).salt);
  assert.equal((await Vault.open(memStorage(), 'first', backup)).address, v.address);
  assert.equal((await Vault.open(st, 'first')).address, v.address);
  await assert.rejects(Vault.open(st), /needs its passphrase/);

  await assert.rejects(v.setPassphrase('second', 'wrong'), /wrong current passphrase/);
  await assert.rejects(v.setPassphrase('second'), /wrong current passphrase/, 'changing it needs the current one');
  assert.equal(st.getItem(STORAGE_KEY), rec, 'a refused change leaves the record as it was');
  await v.setPassphrase('second', 'first');
  assert.notEqual(JSON.parse(st.getItem(STORAGE_KEY)).salt, JSON.parse(rec).salt, 'a new salt');
  await assert.rejects(Vault.open(st, 'first'), /wrong passphrase/);
  const again = await Vault.open(st, 'second');
  assert.equal(again.words, WORDS);
  assert.ok(await again.checkPassphrase('second'));
  assert.ok(!(await again.checkPassphrase('first')));
});

test('8.4 a tab that holds the vault from before a passphrase change cannot write it back', async () => {
  const st = memStorage();
  const stale = await Vault.fromWords(st, WORDS); // tab A: unlocked, in clear
  const other = await Vault.open(st); // tab B, same record
  await other.setPassphrase('set in tab B');
  const encrypted = st.getItem(STORAGE_KEY);
  await assert.rejects(stale.reserveNote(), /changed in another tab/, 'tab A would have written the record back in clear');
  assert.equal(st.getItem(STORAGE_KEY), encrypted);
  assert.throws(() => stale.address, /locked/, 'and tab A is locked');
  await assert.rejects(stale.setPassphrase('from tab A'), /locked|changed in another tab/);

  const a = await Vault.open(st, 'set in tab B');
  const b = await Vault.open(st, 'set in tab B');
  await b.setPassphrase('changed in tab B', 'set in tab B');
  const changed = st.getItem(STORAGE_KEY);
  await assert.rejects(a.reserveNote(), /changed in another tab/, 'nor under the old passphrase');
  assert.equal(st.getItem(STORAGE_KEY), changed);
  assert.ok(await Vault.open(st, 'changed in tab B'));
  await b.reserveNote(); // the tab that changed it goes on writing
  assert.match(page(), /addEventListener\('storage', \(ev\) => \{\n\s+if \(ev\.key !== STORAGE_KEY \|\| !st\.vault\) return;\n\s+st\.vault\.lock\(\);/, 'the page locks a tab when another one writes the vault');
});

test('8.4 a clear backup restored with a passphrase is encrypted with it, never kept in clear under it', async () => {
  const old = memStorage();
  await Vault.fromWords(old, WORDS);
  const clear = old.getItem(STORAGE_KEY); // what "Download backup" wrote before this fix
  assert.ok(JSON.parse(clear).plain);
  const st = memStorage();
  const r = await Vault.restore(st, clear, 'typed for the backup');
  assert.ok(r.encrypted);
  assert.ok(!/plain|abandon/.test(st.getItem(STORAGE_KEY)));
  assert.equal((await Vault.open(st, 'typed for the backup')).words, WORDS);
  const st2 = memStorage();
  assert.ok(!(await Vault.restore(st2, clear)).encrypted, 'with no passphrase typed it stays as it was, and the page says so');
});

test('8.4 the page: backup only when encrypted, a passphrase form, the words behind the passphrase', () => {
  const app = page();
  assert.match(app, /name: 'backup', disabled: !v\.encrypted/);
  assert.match(app, /v\.encrypted \? 'Change passphrase' : 'Set a passphrase'/);
  const words = app.slice(app.indexOf('function wordsForm('), app.indexOf('function passphraseForm('));
  assert.ok(words.indexOf('checkPassphrase(') > 0 && words.indexOf('checkPassphrase(') < words.indexOf('st.showWords = true'), 'the words of an encrypted vault come after its passphrase');
  const pass = app.slice(app.indexOf('function passphraseForm('), app.indexOf('function wordsBox('));
  assert.match(pass, /next\.value !== again\.value/, 'typed twice');
  assert.match(pass, /setPassphrase\(next\.value, current\?\.value/);
  assert.match(src('keys.js'), /async exportBackup\(\) \{\n\s+this\.#checkUnchanged\(\);\n\s+if \(!this\.#key\) throw/);
});

// ---- 8.6: scanOutput turned every failure into "not ours" -------------------------------------------

/** Runs `fn` while WebCrypto's deriveBits fails the way a broken platform would (not a bad key). */
async function brokenWebCrypto(fn) {
  const proto = Object.getPrototypeOf(crypto.subtle);
  const original = proto.deriveBits;
  proto.deriveBits = async () => { throw new DOMException('the platform failed', 'NotSupportedError'); };
  try {
    return await fn();
  } finally {
    proto.deriveBits = original;
  }
}

test('8.6 a scan that could not be made throws; a malformed output is still not ours', async () => {
  const w = await wallet(fromHex(cv.wallets[0].m));
  const theirs = await wallet(fromHex(cv.wallets[1].m));
  const sealed = await seal(w.address, 'GENE', 700n, crypto.getRandomValues(new Uint8Array(32)));
  const out = { leaf: sealed.leaf, pkEph: sealed.pkEph, ct: sealed.ct };
  assert.equal((await scanOutput(w, out)).v, 700n);
  assert.equal(await scanOutput(theirs, out), null, 'another wallet\'s');
  assert.equal(await scanOutput(w, { ...out, ct: out.ct.subarray(0, 27) }), null, 'a malformed ct');
  assert.equal(await scanOutput(w, { ...out, pkEph: new Uint8Array(32) }), null, 'a small-order pkEph');
  assert.equal(await scanOutput(w, { ...out, leaf: -1n }), null, 'a leaf out of the field');
  await brokenWebCrypto(() => assert.rejects(scanOutput(w, out), /the platform failed/));

  const v = await Vault.fromWords(memStorage(), WORDS);
  const mine = await seal(await decodeAddress('tsh20', v.address), 'GENE', 300n, crypto.getRandomValues(new Uint8Array(32)));
  await brokenWebCrypto(() => assert.rejects(v.receive({ pos: 4, leaf: mine.leaf, pkEph: mine.pkEph, ct: mine.ct })));
  assert.equal(v.state.notes.length, 0, 'nothing recorded');
  assert.equal((await v.receive({ pos: 4, leaf: mine.leaf, pkEph: mine.pkEph, ct: mine.ct })).v, '300', 'found once the scan can be made');
});

test('8.6 the leaves a vault has not scanned are read again, past the last blocks, until it has', async () => {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 })); // N = 0: the DEPLOY is only setup here
  const v = await vaultOf(cv.wallets[0].m);
  c.block(helperTx({ env: { type: 'MINT', ticker: 'GENE', npk: (await v.opening(0)).npk }, burnSats: 1000n }));
  const server = await listen(ix, { port: 0 });
  try {
    const api = new IndexerApi(`http://127.0.0.1:${server.address().port}`);
    const cache = memoryCache();
    const s = new Sync(cache, 'audit86');
    const first = await s.sync(api);
    assert.deepEqual(first.notes.map((n) => n.pos), [0]);
    // the scan failed (or the vault was locked): no s.scanned(). Blocks go by, more than the margin
    for (let i = 0; i < REORG_MARGIN + 4; i++) c.block();
    c.block(helperTx({ env: { type: 'MINT', ticker: 'GENE', npk: (await v.opening(1)).npk }, burnSats: 1000n }));
    const reloaded = new Sync(cache, 'audit86'); // across a reload too
    assert.ok(await reloaded.load());
    const second = await reloaded.sync(api);
    assert.deepEqual(second.notes.map((n) => n.pos), [0, 1], 'leaf 0 is read again although it is older than the last blocks');
    await reloaded.scanned();
    for (let i = 0; i < REORG_MARGIN + 4; i++) c.block();
    const third = await reloaded.sync(api);
    assert.deepEqual(third.notes.map((n) => n.pos), [1], 'once scanned, only the last blocks before the previous sync are read again');
    await reloaded.scanned();
    const fourth = await reloaded.sync(api);
    assert.deepEqual(fourth.notes.map((n) => n.pos), []);
    assert.equal(fourth.leaves, 2);
  } finally {
    server.close();
  }
  assert.ok(!/catch\s*\{\s*return null;/.test(src('notekeys.js')), 'no catch-all left in notekeys.js');
});

test('8.6 a note whose scan throws does not stop the others; the sync reads again from it, and the page says so', async () => {
  // sealed outputs: the second one's scan throws, the third is still found
  const v = await Vault.fromWords(memStorage(), WORDS);
  const to = await decodeAddress('tsh20', v.address);
  const outs = [];
  for (const [pos, value] of [[0, 100n], [1, 200n], [2, 300n]]) {
    const o = await seal(to, 'GENE', value, crypto.getRandomValues(new Uint8Array(32)));
    outs.push({ kind: 'OUT', pos, leaf: o.leaf, pkEph: o.pkEph, ct: o.ct, npk: null, ticker: null, v: null });
  }
  const receive = v.receive.bind(v);
  let broken = new Set([1]);
  v.receive = async (n) => {
    if (broken.has(n.pos)) throw new Error('the platform failed');
    return receive(n);
  };
  const m = await matchNotes(v, outs);
  assert.equal(m.found, 2);
  assert.deepEqual(m.failed.map((f) => [f.pos, f.error.message]), [[1, 'the platform failed']]);
  assert.deepEqual(v.state.notes.map((n) => [n.pos, n.v]), [[0, '100'], [2, '300']], 'the note after the failure is found');
  broken = new Set();
  assert.equal((await matchNotes(v, outs)).found, 1, 'found once the scan can be made, and the others not twice');

  // public notes through a real sync: leaf 0 throws, leaf 1 is found, and the next sync reads again from leaf 0
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 }));
  const w = await vaultOf(cv.wallets[0].m);
  c.block(helperTx({ env: { type: 'MINT', ticker: 'GENE', npk: (await w.opening(0)).npk }, burnSats: 1000n }));
  c.block(helperTx({ env: { type: 'MINT', ticker: 'GENE', npk: (await w.opening(1)).npk }, burnSats: 1000n }));
  const server = await listen(ix, { port: 0 });
  try {
    const api = new IndexerApi(`http://127.0.0.1:${server.address().port}`);
    const s = new Sync(memoryCache(), 'audit86b');
    const first = await s.sync(api);
    const addNote = w.addNote.bind(w);
    w.addNote = async (n) => {
      if (n.pos === 0) throw new Error('storage full');
      return addNote(n);
    };
    const m1 = await matchNotes(w, first.notes);
    assert.deepEqual([m1.found, m1.failed.map((f) => f.pos)], [1, [0]]);
    assert.deepEqual(w.state.notes.filter((n) => n.pos !== null).map((n) => n.pos), [1]);
    await s.scanned(m1.failed[0].pos);
    for (let i = 0; i < REORG_MARGIN + 4; i++) c.block();
    const second = await s.sync(api);
    assert.deepEqual(second.notes.map((n) => n.pos), [0, 1], 'read again from the first note that failed, past the last blocks');
    w.addNote = addNote;
    const m2 = await matchNotes(w, second.notes);
    assert.deepEqual([m2.found, m2.failed], [1, []]);
    await s.scanned(m2.failed[0]?.pos ?? null);
    assert.equal(s.unscanned, null);
  } finally {
    server.close();
  }

  // the page: every note matched before scanned, scanned at the first failure, and the failure shown
  const app = page();
  const sn = app.slice(app.indexOf('async function syncNotes('));
  assert.ok(sn.indexOf('await matchNotes(st.vault, r.notes') < sn.indexOf('await s.scanned(failed[0]?.pos ?? null);'), 'scanned only after every note was tried');
  assert.match(sn, /note\(s\) could not be scanned, from leaf \$\{failed\[0\]\.pos\} \(\$\{failed\[0\]\.error\.message\}\)/);
});

// ---- 8.5: what the vault showed as received rested on one indexer -----------------------------------

test('8.5 every sync compares the root and the digest at the synced block across the indexers, and the page shows it', async () => {
  const D = 'ab'.repeat(32);
  const R = '0c'.repeat(32);
  const at = (base, d, r = d === null ? null : R) => ({ base, digest: async (h) => { assert.equal(h, 15); return d; }, rootAt: async (h) => { assert.equal(h, 15); return r; } });
  const fails = (base) => ({ base, digest: async () => { throw new Error('unreachable'); }, rootAt: async () => { throw new Error('unreachable'); } });
  const agree = await digestAgreement([at('primary', D), at('b', D), at('c', null), fails('d')], 15, D.toUpperCase(), R);
  assert.deepEqual(agree, { height: 15, agreed: 2, total: 4, disagree: [], behind: ['c'], down: ['d'] });
  assert.equal(agreementText(agree), '2 of 4 indexers agree on the state at block 15 (1 not there yet, 1 unreachable).');
  const liar = await digestAgreement([at('primary', D), at('honest', 'cd'.repeat(32))], 15, D, R);
  assert.deepEqual(liar.disagree, ['honest']);
  assert.match(agreementText(liar), /honest disagrees with the primary indexer on the state at block 15: notes shown here may not exist on chain/);
  // a lying primary that serves its own leaves and copies the honest digest: the root gives it away
  const copied = await digestAgreement([at('liar', D), at('honest', D, 'ee'.repeat(32))], 15, D, R);
  assert.deepEqual([copied.agreed, copied.disagree], [1, ['honest']]);
  assert.match(agreementText(await digestAgreement([at('primary', D)], 15, D, R)), /One indexer only/);
  assert.equal((await digestAgreement([at('primary', D), at('b', D)], 15, null, R)).agreed, 0, 'a primary that reports no digest vouches for nothing');

  // against the real API: /digest/:height and /roots, the same values as /status at that height
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 })); // N = 0: the DEPLOY is only setup here
  c.block();
  const server = await listen(ix, { port: 0 });
  try {
    const api = new IndexerApi(`http://127.0.0.1:${server.address().port}`);
    const r = await new Sync(memoryCache(), 'audit85').sync(api);
    assert.equal(await api.digest(r.height), r.digest);
    assert.equal(await api.rootAt(r.height), r.root, 'the root the vault rebuilt from the leaves');
    assert.equal(await api.digest(r.height + 5), null, 'a block it has not reached');
    assert.equal(await api.rootAt(r.height + 5), null);
    assert.equal((await digestAgreement([api, api], r.height, r.digest, r.root)).agreed, 2);
  } finally {
    server.close();
  }
  const app = page();
  assert.match(app, /agreement: await digestAgreement\(indexers, r\.height, r\.digest, r\.root\)/, 'at every sync');
  assert.match(app, /h\('p', \{ id: 'balance' \}, h\('strong', \{\}, 'Balance: '\), bal \|\| 'nothing spendable yet', agreement/, 'next to the balance');
});
