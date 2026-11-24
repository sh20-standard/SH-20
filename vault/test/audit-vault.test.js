// The reproducers of docs/audit/2026-11-24-vault.md, one or more for each finding that code can show.
// Each test states what the vault does today, so it passes on the commit the audit read; the fix of
// a finding turns its test round (the assertion marked "today"), in the pull request that names it.
// No proof is made here: the envelopes carry the test proof of indexer/test/helpers.js, and the
// reference indexer runs with its mock verifier, which is enough for rules that involve no proof.
// vault-1 to vault-13 were written on the commit the audit read; vault-14 to vault-16 are about the
// mainnet profile and the verifier's name, read on the main this file was merged into.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Indexer } from '../../indexer/src/indexer.js';
import { chain, deployEnv, tx as helperTx, mockVerifier, testProof } from '../../indexer/test/helpers.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { NOTE_SCHEME } from '../src/notekeys.js';
import { NoteTree, serializeEnvelope, seal } from '../src/sh20.js';
import { planTransfer, planCarrier, revealFor, planPlainDeploy, deployEnvelope, pendingRecord, refusedSpend, deploySchedule, anchor } from '../src/send.js';
import { withProof, pickInputs } from '../src/spend.js';
import { planList, listOutputs, signOffer, listingFromChain, buildTake } from '../src/market.js';
import { listingCheck, profileCheck, refusalAgreed } from '../src/consensus.js';
import { IndexerApi, normListing, normToken } from '../src/api.js';
import { urlList } from '../src/ui/context.js';
import { deployMismatches } from '../src/deploy.js';
import { deployProblems } from '../src/deploy-plan.js';
import { buildMint, mintProblems, selectCoins } from '../src/mint.js';
import { matchNotes, matchListings } from '../src/match.js';
import { envelopeScript, leafHash, tweakKey } from '../src/taproot.js';
import { addressToScript, parseTx, serializeTx, txid as txidOf } from '../src/btc.js';
import { gatewayKind } from '../src/isolation.js';
import { PROFILE } from '../src/profile.js';
import { WALLETS } from '../src/wallets.js';
import { PROFILE_MODULE, fsReader, site, writeSite } from '../build.js';
import { fromHex, toHex } from '../src/bytes.js';

const cv = JSON.parse(readFileSync(new URL('../../circuit/js/vectors.json', import.meta.url), 'utf8'));
const WPKH = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const SELLER_PAY = fromHex('0014' + '66'.repeat(20));
const DEPLOYER_PAY = fromHex('0014' + '77'.repeat(20));
const OTHER_PAY = fromHex('0014' + 'ee'.repeat(20));

function memStorage() {
  const m = new Map();
  const s = { writes: 0, chars: 0, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { s.writes++; s.chars += String(v).length; m.set(k, String(v)); } };
  return s;
}
async function vaultOf(m, storage = memStorage()) {
  storage.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: m } }));
  return Vault.open(storage);
}
const ixTx = (t, id) => ({
  txid: id,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: (i.witness ?? []).map((w) => Buffer.from(w)) })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});
const fakeSigned = (t) => ({ ...t, vin: t.vin.map((i, k) => (i.witness?.length ? i : { ...i, witness: [new Uint8Array(k ? 71 : 64), new Uint8Array(33)] })) });
/** The tree as a sync rebuilds it (send.js needs height, tree, witness). */
function localSync(ix) {
  const tree = new NoteTree();
  for (const leaf of ix.tree.leaves) tree.append(leaf);
  return { height: ix.height, tree, witness: (pos, leaf) => { assert.equal(tree.leaves[pos], leaf); return { siblings: tree.path(pos) }; } };
}
/** A chain at block 2 with GENE and two public notes of 1,000 of the vault (as test/market.test.js). */
async function setup() {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 }));
  const seller = await vaultOf(cv.wallets[0].m);
  const npks = [(await seller.opening(0)).npk, (await seller.opening(1)).npk];
  const b = c.block(...npks.map((npk) => helperTx({ env: { type: 'MINT', ticker: 'GENE', npk }, burnSats: 1000n })));
  for (const [k, e] of b.events.filter((x) => x.type === 'MINT').entries()) {
    const n = await seller.addNote({ index: k, ticker: 'GENE', v: 1000n, txid: null, status: 'in tree', pos: e.pos });
    await seller.updateNote(n.id, { spent: 'no' });
  }
  return { ix, seller };
}
/** The reveal of a spend the vault planned, with the test proof in place of a real one. */
function revealOf(plan, commitTxid, outputs) {
  const envelope = withProof(plan.env, testProof());
  const cp = planCarrier({ envelope, payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: 2, outputs });
  return { cp, envelope, ...revealFor(cp, commitTxid) };
}
const apiListing = (l) => normListing({ ...l, amount: String(l.amount), price: String(l.price) });

// ---- vault-1 -------------------------------------------------------------------------------------

test('vault-1: a TAKE of a listing one block old pays the seller for nothing once a reorg puts another spend of its notes first', async () => {
  const { ix, seller } = await setup();
  const sync = localSync(ix);
  // the seller plans, on one note and one anchor, a LIST and a TRANSFER of that note to itself
  const lock = await seller.lockOutput(await seller.reserveLock());
  const listPlan = await planList({ vault: seller, sync, tip: 2, ticker: 'GENE', amount: 600n, price: 5000n, payScript: SELLER_PAY, lockKey: lock.key });
  const movePlan = await planTransfer({ vault: seller, sync, tip: 2, ticker: 'GENE', amount: 1000n, to: seller.address });
  assert.equal(listPlan.env.spend.nf[0], movePlan.env.spend.nf[0], 'both spend the same note');
  const list = revealOf(listPlan, 'c2'.repeat(32), listOutputs(lock.script));
  const move = revealOf(movePlan, 'c4'.repeat(32));

  // chain A: the LIST is mined in block 3, and every indexer reports the listing ACTIVE
  const a3 = ix.applyBlock({ height: 3, hash: 'a3', txs: [ixTx(list.tx, list.txid)] });
  assert.equal(a3.events[0].type, 'LIST');
  const listing = ix.listings.get(list.txid);
  assert.equal(listing.state, 'ACTIVE');
  assert.equal(listing.height, 3);

  // the buyer's vault, one block later: two indexers agree, the LIST is on chain, the offer is the lock key's
  const two = ['one', 'two'].map((base) => ({ base, listing: async () => apiListing(listing) }));
  const checked = await listingCheck(two, list.txid);
  assert.equal(checked.enough, true);
  const l = listingFromChain(list.txid, list.hex, { ...checked.listing, amount: String(checked.listing.amount), price: String(checked.listing.price) });
  const sig = signOffer(lock.secret, l);
  const buyer = await vaultOf(cv.wallets[2].m);
  // today: nothing between the offer and the TAKE looks at the listing's height (ui/market-panel.js sendTake)
  const take = buildTake({ l, sig, npk: (await buyer.opening(0)).npk, payer: { address: WPKH }, utxos: [{ txid: '55'.repeat(32), vout: 1, value: 50000n }], feeRate: 1, tipHeight: 3 });

  // chain B replaces block 3: the TRANSFER comes first, then the same LIST transaction, then the TAKE.
  // Each is a valid Bitcoin transaction there too: none spends an output of another but the TAKE, which
  // spends the LIST transaction's output 0, and that transaction is in both chains.
  ix.rollback(2);
  const b3 = ix.applyBlock({ height: 3, hash: 'b3', txs: [ixTx(move.tx, move.txid), ixTx(list.tx, list.txid)] });
  assert.deepEqual(b3.events.map((e) => e.type), ['TRANSFER']);
  assert.equal(b3.rejected.length, 1, 'the LIST is refused: its nullifier is spent');
  const b4 = ix.applyBlock({ height: 4, hash: 'b4', txs: [ixTx(fakeSigned(take.tx), 'd1'.repeat(32))] });
  assert.deepEqual(b4.events, []);
  assert.match(JSON.stringify(b4.rejected), /active listing lock/);
  assert.equal(ix.listings.get(list.txid), undefined, 'no listing: nothing to claim back either');
  assert.equal(ix.tree.size, 2 + 3, 'no note for the buyer: the two mints and the three outputs of the TRANSFER');

  // and the buyer's transaction paid the price to the seller all the same
  assert.equal(take.tx.vin[0].txid, list.txid);
  assert.equal(take.tx.vout[0].value, 5000n);
  assert.equal(toHex(take.tx.vout[0].script), toHex(SELLER_PAY));
});

test('vault-1: a MINT paid to the deployer of a ticker one block old pays for nothing once a reorg moves the DEPLOY', async () => {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  ix.applyBlock({ height: 1, hash: 'a1', txs: [] });
  // a DEPLOY whose mint opens in the block after its own, paid to its deployer
  const d = { ticker: 'PAID', max: 1000000n, lim: 1000n, pre: 0n, start: 3, end: 0, unlock: 3, price: 10000n, payMode: 2, payScript: DEPLOYER_PAY };
  const cp = planCarrier({ envelope: planPlainDeploy({ d, team: null }).envelope, payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: 1 });
  const deploy = revealFor(cp, 'c7'.repeat(32));
  const deployTx = ixTx(deploy.tx, deploy.txid);
  deployTx.vin[0].prevHeight = 1; // its commit is in block 1
  const a2 = ix.applyBlock({ height: 2, hash: 'a2', txs: [deployTx] });
  assert.equal(a2.events[0].type, 'DEPLOY');

  // the minter's vault: the indexer's terms are the DEPLOY's on chain, the window opens at the next block
  const token = normToken(ix.token('PAID'));
  assert.deepEqual(deployMismatches(token, deploy.hex, 2), []);
  assert.deepEqual(mintProblems(token, 3), []);
  const minter = await vaultOf(cv.wallets[1].m);
  // today: verifyDeploy asks that the DEPLOY be confirmed, not how deep (deploy.js)
  const mint = buildMint({ token, opening: await minter.opening(0), payer: { address: WPKH }, utxos: [{ txid: '66'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: 2 });

  // chain B: block 2 without the DEPLOY, which is mined in block 3 with the MINT
  ix.rollback(1);
  ix.applyBlock({ height: 2, hash: 'b2', txs: [] });
  const b3 = ix.applyBlock({ height: 3, hash: 'b3', txs: [deployTx, ixTx(fakeSigned(mint.tx), 'e1'.repeat(32))] });
  assert.deepEqual(b3.events, []);
  assert.match(JSON.stringify(b3.rejected), /start must be after the DEPLOY block/);
  assert.equal(b3.rejected.length, 2, 'the DEPLOY, then the MINT of a ticker that does not exist');
  assert.equal(ix.token('PAID'), null);
  const paid = mint.tx.vout.find((o) => toHex(o.script) === toHex(DEPLOYER_PAY));
  assert.equal(paid.value, 10000n, 'the deployer is paid');
});

// ---- vault-2 -------------------------------------------------------------------------------------

test('vault-2: a commit is funded with an unconfirmed coin, and a spend that never confirms keeps its notes for ever', async () => {
  // the smallest coin that pays is taken, confirmed or not: a coin anyone can send to the wallet's address, then replace
  const change = addressToScript(WPKH);
  const coins = [{ txid: '11'.repeat(32), vout: 0, value: 100000n, confirmed: true }, { txid: '22'.repeat(32), vout: 0, value: 3000n, confirmed: false }];
  const sel = selectCoins(coins, [{ value: 1200n, script: fromHex('5120' + '00'.repeat(32)) }], 'p2wpkh', change, 1);
  assert.deepEqual(sel.picked.map((u) => u.confirmed), [false]); // today

  const { ix, seller: v } = await setup();
  const plan = await planTransfer({ vault: v, sync: localSync(ix), tip: 2, ticker: 'GENE', amount: 1000n, to: v.address });
  const r = revealOf(plan, 'c5'.repeat(32));
  const spent = plan.inputs[0].id;
  const note = () => v.state.notes.find((n) => n.id === spent);
  const pub = v.state.notes.map((n) => ({ pos: n.pos, kind: 'MINT', ticker: n.ticker, v: BigInt(n.v), npk: BigInt('0x' + n.npk), leaf: BigInt('0x' + n.leaf), pkEph: null, ct: null, txid: null, height: 2 }));
  const listed = () => (v.state.pending ?? []).filter((p) => p.status !== 'prepared' && p.status !== 'replaced'); // ui/send-panel.js renderPending

  // 1. the wallet refuses to sign the commit: carry() has saved the record and stops (ui/spends.js)
  const pid = await v.addPending(pendingRecord('TRANSFER', r.cp, r.envelope, plan.inputs));
  assert.equal(note().status, 'spending');
  assert.equal(listed().length, 0, 'the page lists no spend to send again or to give up');
  assert.equal((await matchNotes(v, pub)).found, 0);
  assert.equal(note().status, 'spending', 'a rescan from zero leaves it reserved'); // today
  assert.equal(pickInputs(v.state.notes, 'GENE', 1001n), null, 'what the vault can spend is the other note alone');

  // 2. signed and broadcast, and the commit's coin is replaced: neither transaction is ever mined
  await v.updatePending(pid, { commitTxid: 'c5'.repeat(32), revealHex: r.hex, revealTxid: r.txid, status: 'broadcast' });
  await v.updateNote(spent, { spent: 'no', pathAt: 5000 });
  const p = v.state.pending.find((x) => x.id === pid);
  // thousands of blocks later, long after the anchor left the window: still not given back
  assert.equal(refusedSpend(p, v.state.notes, { revealHeight: null, syncHeight: 5000, nullifiersKnown: true }), false); // today
  assert.equal(note().status, 'spending');
});

// ---- vault-3 -------------------------------------------------------------------------------------

test('vault-3: a sync writes the whole state once for each note the vault holds', async () => {
  const N = 300;
  const storage = memStorage();
  const v = await vaultOf(cv.wallets[0].m, storage);
  // N sealed notes, as Vault.receive records them (any payer makes one with a TRANSFER of one unit)
  const hex = (i, c) => (i.toString(16).padStart(8, '0') + c.repeat(56));
  for (let i = 0; i < N; i++) {
    v.state.notes.push({ id: `out:${i}`, kind: 'sealed', index: null, scheme: NOTE_SCHEME, ticker: 'GENE', v: '1', npk: hex(i, 'a'), rho: hex(i, 'b'), tauA: '1'.repeat(76), tauN: '2'.repeat(76), leaf: hex(i, 'c'), txid: hex(i, 'd'), status: 'in tree', pos: i });
  }
  await v.save();
  const one = storage.chars;
  storage.writes = 0;
  storage.chars = 0;
  // what checkOwned does at every sync (ui/notes-panel.js): one updateNote, hence one save, for each note
  for (const n of [...v.state.notes]) await v.updateNote(n.id, { pathAt: 7, spent: 'no' });
  assert.equal(storage.writes, N); // today
  assert.ok(storage.chars > N * one, `${storage.chars} characters written for a state of ${one}`);
});

// ---- vault-4 -------------------------------------------------------------------------------------

test('vault-4: a DEPLOY whose mint starts within N blocks passes the screen, is revealed, and is refused', async () => {
  const N = PROFILE.deployMaturity;
  const tip = 10;
  const d = { ticker: 'SOON', max: 21000000n, lim: 1000n, pre: 0n, start: tip + 2, end: 0, unlock: tip + 2, price: 0n, payMode: 0, payScript: new Uint8Array(0) };
  assert.deepEqual(deployProblems(d, { nextHeight: tip + 1, taken: [] }), []); // today: no problem found

  // the commit in the next block, the reveal in the first block the indexers take it in
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier: mockVerifier() });
  assert.equal(ix.profile.deployMaturity, N);
  for (let h = 1; h <= tip + N; h++) ix.applyBlock({ height: h, hash: `h${h}`, txs: [] });
  const cp = planCarrier({ envelope: planPlainDeploy({ d, team: null }).envelope, payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: tip });
  const reveal = revealFor(cp, 'c8'.repeat(32));
  const t = ixTx(reveal.tx, reveal.txid);
  t.vin[0].prevHeight = tip + 1;
  // the page sends it: the schedule knows the commit's height and the proof's anchor, not the mint's start
  assert.deepEqual(deploySchedule({ anchorHeight: null }, { commitHeight: tip + 1, tip: tip + N }), { state: 'ready', blocks: 0 }); // today
  const r = ix.applyBlock({ height: tip + 1 + N, hash: 'reveal', txs: [t] });
  assert.deepEqual(r.events, []);
  assert.match(JSON.stringify(r.rejected), /start must be after the DEPLOY block/);
});

// ---- vault-5, vault-6 ----------------------------------------------------------------------------

async function deployed(d, team) {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  ix.applyBlock({ height: 1, hash: 'a1', txs: [] });
  const cp = planCarrier({ envelope: planPlainDeploy({ d, team }).envelope, payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: 1 });
  const reveal = revealFor(cp, 'c9'.repeat(32));
  const t = ixTx(reveal.tx, reveal.txid);
  t.vin[0].prevHeight = 1;
  assert.equal(ix.applyBlock({ height: 2, hash: 'a2', txs: [t] }).events[0].type, 'DEPLOY');
  return { ix, cp, reveal, token: normToken(ix.token(d.ticker)) };
}

test('vault-5: the block at which a team allocation unlocks is not compared with the DEPLOY on chain', async () => {
  const d = { ticker: 'TEAM', max: 1000000n, lim: 1000n, pre: 500000n, start: 3, end: 0, unlock: 3, price: 0n, payMode: 0, payScript: new Uint8Array(0) };
  const { reveal, token } = await deployed(d, { npk: 5n });
  assert.equal(token.unlock, 3);
  assert.deepEqual(deployMismatches(token, reveal.hex, 2), []);
  // an indexer that says the team's half of the supply is locked for decades
  assert.deepEqual(deployMismatches({ ...token, unlock: 4000000 }, reveal.hex, 2), []); // today: not noticed
  // every other term it could change is
  assert.match(deployMismatches({ ...token, pre: 0n }, reveal.hex, 2).join(), /pre/);
});

test('vault-6: a DEPLOY read from Esplora is checked by its txid, which does not cover the envelope; the output it spends does', async () => {
  const d = { ticker: 'PAID', max: 1000000n, lim: 1000n, pre: 0n, start: 3, end: 0, unlock: 3, price: 10000n, payMode: 2, payScript: DEPLOYER_PAY };
  const { cp, reveal, token } = await deployed(d, null);
  // the same transaction, with an envelope in its witness that pays another script: the same txid
  const forged = parseTx(fromHex(reveal.hex));
  forged.vin[0].witness[1] = envelopeScript(cp.c.e, serializeEnvelope(deployEnvelope({ ...d, payScript: OTHER_PAY }, null)));
  const forgedHex = toHex(serializeTx(forged));
  assert.notEqual(forgedHex, reveal.hex);
  assert.equal(txidOf(forged), reveal.txid);
  // an indexer and an Esplora that say the same thing are believed
  assert.deepEqual(deployMismatches({ ...token, payScript: toHex(OTHER_PAY) }, forgedHex, 2), []); // today
  // BIP341 binds the script to the output spent: the leaf of the witness, under its control block, gives that output's key
  const outputKey = (w) => toHex(tweakKey(w[2].subarray(1, 33), leafHash(w[1])).key);
  const committed = toHex(cp.c.scriptPubKey.subarray(2)); // the commit's output, which the commit's txid covers
  assert.equal(outputKey(parseTx(fromHex(reveal.hex)).vin[0].witness), committed);
  assert.notEqual(outputKey(forged.vin[0].witness), committed);
});

// ---- vault-7 -------------------------------------------------------------------------------------

test('vault-7: two open copies of one vault reserve the same public-note key, and the second write drops what the first recorded', async () => {
  const storage = memStorage();
  const a = await vaultOf(cv.wallets[0].m, storage);
  const b = await Vault.open(storage);
  const first = await a.reserveNote();
  await a.addPending({ kind: 'TRANSFER', secret: '01'.repeat(32), inputs: [], status: 'prepared' });
  // the page locks a tab when it hears another one write (app.js); a save already under way is not stopped
  const second = await b.reserveNote(); // today: accepted
  assert.equal(second.index, first.index);
  assert.equal(second.npk, first.npk);
  const stored = JSON.parse(storage.getItem(STORAGE_KEY)).plain;
  assert.equal(stored.pending, undefined, 'the one-time key the first copy saved is gone from the device');
});

// ---- vault-8 -------------------------------------------------------------------------------------

test('vault-8: a listing found by its lock key takes the id of the one the vault sent with that key', async () => {
  const v = await vaultOf(cv.wallets[0].m);
  const index = await v.reserveLock();
  const mine = { lockIndex: index, ticker: 'GENE', amount: '600', price: '5000', payScript: toHex(SELLER_PAY), listTxid: 'aa'.repeat(32), state: 'ACTIVE', source: 'sent' };
  await v.addListing(mine);
  // anyone can LIST tokens of their own to a lock key seen on chain, or copy a LIST from the mempool into a transaction of their own
  const other = { listTxid: 'bb'.repeat(32), lockKey: toHex((await v.lockOutput(index)).key), state: 'ACTIVE' };
  assert.equal(await matchListings(v, [other], async () => ({ ticker: 'GENE', amount: 1n, price: 1000n, payScript: SELLER_PAY })), 1);
  assert.deepEqual(v.state.listings.map((l) => l.id), ['list:0', 'list:0']); // today
  // syncListings moves each record to its listing's state by id: the second listing's state lands on the first
  await v.updateListing(v.state.listings[1].id, { state: 'SOLD' });
  assert.deepEqual(v.state.listings.map((l) => [l.listTxid.slice(0, 2), l.state]), [['aa', 'SOLD'], ['bb', 'ACTIVE']]);
});

// ---- vault-9 -------------------------------------------------------------------------------------

test('vault-9: after a reorg that swaps two of the vault\'s sealed notes, neither is taken at its new position', async () => {
  const v = await vaultOf(cv.wallets[0].m);
  const sealed = async (amount) => {
    const o = await seal(v.wallet.address, 'GENE', amount, crypto.getRandomValues(new Uint8Array(32)));
    return { leaf: o.leaf, pkEph: o.pkEph, ct: o.ct };
  };
  const [a, b] = [await sealed(5n), await sealed(7n)];
  assert.equal((await v.receive({ pos: 10, ...a })).v, '5');
  assert.equal((await v.receive({ pos: 11, ...b })).v, '7');
  // the block is replaced and its two transactions come in the other order: the sync reads both leaves again
  assert.equal(await v.receive({ pos: 10, ...b }), null); // today: a position already recorded is not opened again
  assert.equal(await v.receive({ pos: 11, ...a }), null);
  // checkOwned then drops both records, whose leaves are no longer at their positions (ui/notes-panel.js):
  // the balance loses 12 until a later sync reads these leaves again, which it does for six blocks only
  assert.deepEqual(v.state.notes.map((n) => [n.pos, n.v]), [[10, '5'], [11, '7']]);
});

// ---- vault-10, and the notes ---------------------------------------------------------------------

test('vault-10: a token an indexer lists with lim = 0 throws where every panel is drawn', () => {
  const t = normToken({ ticker: 'ZERO', max: '1000', lim: '0', pre: '0', start: 1, end: 0, unlock: 1, price: '0', payMode: 0, mints: '0' });
  assert.throws(() => mintProblems(t, 5), RangeError); // today: renderTokens calls it for every token, inside renderAll
});

test('vault-11: on the Pages site the vault does not register its service worker', () => {
  assert.equal(gatewayKind({ hostname: 'sh20-standard.github.io', pathname: '/SH-20/vault/' }), 'other'); // ensureIsolation stops there
  assert.equal(gatewayKind({ hostname: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi.ipfs.dweb.link', pathname: '/vault/' }), 'subdomain');
});

test('vault-12: without a tip from Esplora a spend is anchored on a tree of any age', () => {
  const sync = { height: 5, tree: { root: 1n } };
  assert.throws(() => anchor(sync, 500), /blocks old/);
  assert.deepEqual(anchor(sync, NaN), { anchorHeight: 5, root: 1n }); // today: Esplora.tipHeight() is Number(text)
});

test('vault-13: one indexer written twice is the two that a TAKE needs', async () => {
  const urls = urlList('https://indexer.example\nhttps://indexer.example/');
  assert.equal(urls.length, 2); // today: told apart as text
  const apis = urls.map((u) => new IndexerApi(u));
  assert.equal(apis[0].base, apis[1].base);
  const listing = apiListing({ listTxid: 'aa'.repeat(32), ticker: 'GENE', amount: 600n, price: 5000n, payScript: toHex(SELLER_PAY), lock: `${'aa'.repeat(32)}:0`, lockKey: 'bb'.repeat(32), state: 'ACTIVE', height: 3 });
  for (const a of apis) a.listing = async () => listing;
  assert.equal((await listingCheck(apis, 'aa'.repeat(32))).enough, true);
});

// ---- the mainnet profile: vault-14, vault-15, vault-16 ---------------------------------------------

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** The modules of the page `node build.js --mainnet --activation 840000` writes, built in a temporary folder. */
async function mainnetPage(use) {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-audit-mainnet-'));
  try {
    const fs = fsReader();
    // whatever height the tree's profile.js has fixed for mainnet, the build gets it from --activation
    const reader = { ...fs, read: (p) => (p === PROFILE_MODULE ? Buffer.from(fs.read(p).toString('utf8').replace(/^export const MAINNET_ACTIVATION_HEIGHT = (null|0|[1-9]\d*);$/m, 'export const MAINNET_ACTIVATION_HEIGHT = null;')) : fs.read(p)) };
    writeSite(site(reader, { mainnet: true, activation: 840000 }), dir);
    return await use((f) => import(pathToFileURL(join(dir, 'vault/src', f)).href));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('vault-14: a signet vault at the origin of a mainnet page is sent to its 12 words, where it cannot be restored', async () => {
  await mainnetPage(async (built) => {
    const { Vault: MainnetVault } = await built('keys.js');
    const origin = memStorage(); // one origin: a local copy served for signet, then for mainnet
    const signet = await Vault.fromWords(origin, WORDS, 'pass'); // the source tree's page: signet's network
    assert.equal(MainnetVault.exists(origin), true);
    await assert.rejects(MainnetVault.open(origin, 'pass'), /made on signet, and this page follows mainnet: restore it from its 12 words instead/);
    // what the message says to do is refused on that page: the other network's record is in the way, and the page removes none
    await assert.rejects(MainnetVault.fromWords(origin, WORDS, 'pass', { restored: true }), /a vault already exists on this device/); // today
    // at an origin of its own the words do restore: the keys of the signet vault, now on mainnet (sealing-4)
    const mainnet = await MainnetVault.fromWords(memStorage(), WORDS, 'pass', { restored: true });
    assert.equal((await mainnet.opening(0)).npk, (await signet.opening(0)).npk);
    assert.equal(toHex((await mainnet.lockOutput(0)).key), toHex((await signet.lockOutput(0)).key));
  });
});

test('vault-15: the smallest coin that pays is spent first, whatever it carries, and UniSat\'s list of plain coins is optional', async () => {
  // a MINT that pays its deployer 10,000 sats, from an address with a plain coin and a small one, the
  // size an inscription or runes sit on
  const d = { ticker: 'PAID', max: 1000000n, lim: 1000n, pre: 0n, start: 3, end: 0, unlock: 3, price: 10000n, payMode: 2, payScript: DEPLOYER_PAY };
  const { token } = await deployed(d, null);
  const coins = [{ txid: '11'.repeat(32), vout: 0, value: 500000n, confirmed: true }, { txid: '22'.repeat(32), vout: 0, value: 20000n, confirmed: true }];
  const mint = buildMint({ token, opening: { npk: 5n }, payer: { address: WPKH }, utxos: coins, feeRate: 2, tipHeight: 2 });
  assert.deepEqual(mint.tx.vin.map((i) => i.txid), ['22'.repeat(32)]); // today: the small coin, alone
  // its first sats go to the first output that holds any: the envelope's OP_RETURN holds none, the next is the deployer's
  assert.equal(mint.tx.vout[0].value, 0n);
  assert.deepEqual([toHex(mint.tx.vout[1].script), mint.tx.vout[1].value], [toHex(DEPLOYER_PAY), 10000n]);
  // UniSat keeps everything at one address. Without getBitcoinUtxos its adapter answers null, and the page
  // takes Esplora's list of every coin there, with no word to the user (ui/spends.js walletUtxos)
  const had = Object.hasOwn(globalThis, 'unisat');
  const saved = globalThis.unisat;
  globalThis.unisat = {};
  try {
    assert.equal(await WALLETS.find((w) => w.id === 'unisat').utxos(), null); // today
  } finally {
    if (had) globalThis.unisat = saved;
    else delete globalThis.unisat;
  }
});

test('vault-16: two indexers that the page says verify no spend are the two a TAKE needs', async () => {
  const listing = apiListing({ listTxid: 'aa'.repeat(32), ticker: 'GENE', amount: 600n, price: 5000n, payScript: toHex(SELLER_PAY), lock: `${'aa'.repeat(32)}:0`, lockKey: 'bb'.repeat(32), state: 'ACTIVE', height: 3 });
  // the vault's own profile, and the verifier that takes one fixed string as the proof of anything
  const status = { ...PROFILE, height: 5, verifier: 'test' };
  const apis = ['one', 'two'].map((base) => ({ base, status: async () => status, listing: async () => listing }));
  const check = await profileCheck(apis);
  assert.equal(check.unverified.length, 2, 'the page names both beside the balance');
  assert.deepEqual(check.problems, [], 'and requireProfile, which reads the problems alone, lets every action through'); // today
  assert.equal((await listingCheck(apis, listing.listTxid)).enough, true); // today
  // and indexers that refuse every spend agree that a spend was refused, which the indexers that verify accepted
  const refuseAll = ['one', 'two'].map((base) => ({ base, status: async () => ({ ...PROFILE, height: 50, verifier: 'reject-all' }), nullifiers: async () => [] }));
  assert.equal((await profileCheck(refuseAll)).unverified.length, 2);
  assert.deepEqual(await refusalAgreed(refuseAll, ['ab'.repeat(32)], { atLeast: 10 }), { ok: true, why: null }); // today
});
