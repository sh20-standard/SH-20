// BURN, LIST, TAKE and CLAIM, built by the vault and read by the reference indexer.
// BURN and LIST carry real proofs, checked with the pinned PLONK verifier; the offer, the TAKE, the
// cancel and the CLAIM involve no proof, so their tests run with the indexer's mock verifier.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { chain, deployEnv, tx as helperTx, mockVerifier, testProof } from '../../indexer/test/helpers.js';
import { nodeProver, WASM } from './prover-node.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { NOTE_SCHEME } from '../src/notekeys.js';
import { LocalTree } from '../src/tree.js';
import { proveSpend, planCarrier, revealFor } from '../src/send.js';
import { withProof } from '../src/spend.js';
import {
  planBurn, planList, listOutputs, signOffer, encodeOffer, decodeOffer, offerValid, listingFromChain,
  buildTake, buildCancel, buildClaim, claimMessage, LOCK_SATS,
} from '../src/market.js';
import { addressToScript, serializeTx } from '../src/btc.js';
import { fromHex, toHex } from '../src/bytes.js';
import { frHex } from '../src/fr.js';
import { noteLeaf, tickerT } from '../src/sh20.js';

const cv = JSON.parse(readFileSync(new URL('../../circuit/js/vectors.json', import.meta.url), 'utf8'));
const WPKH = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const SELLER_PAY = fromHex('0014' + '66'.repeat(20));
const GENE = tickerT('GENE');
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};
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
/** The tree as a sync rebuilds it, with the indexer's height (send.js needs height, tree, witness). */
function localSync(ix) {
  const tree = new LocalTree();
  tree.append(ix.tree.leaves);
  return { height: ix.height, tree, witness: (pos, leaf) => { assert.equal(tree.leaf(pos), leaf); return { siblings: tree.path(pos) }; } };
}
/** A chain with GENE and two public notes of 1,000 of the vault. */
async function setup(verifier) {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier });
  const c = chain(ix);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }) }));
  const seller = await vaultOf(cv.wallets[0].m);
  const npks = [(await seller.opening(0)).npk, (await seller.opening(1)).npk];
  const b = c.block(...npks.map((npk) => helperTx({ env: { type: 'MINT', ticker: 'GENE', npk }, burnSats: 1000n })));
  for (const [k, e] of b.events.filter((x) => x.type === 'MINT').entries()) {
    const n = await seller.addNote({ index: k, ticker: 'GENE', v: 1000n, txid: null, status: 'in tree', pos: e.pos });
    await seller.updateNote(n.id, { spent: 'no' });
  }
  return { ix, c, seller };
}
const fakeSigned = (t) => ({ ...t, vin: t.vin.map((i, k) => (i.witness?.length ? i : { ...i, witness: [new Uint8Array(k ? 71 : 64), new Uint8Array(33)] })) });

/** A LIST of 600 GENE for 5,000 sats, revealed and mined; `prove` makes the proof. */
async function list(ix, c, seller, prove) {
  const lockIndex = await seller.reserveLock();
  const lock = await seller.lockOutput(lockIndex);
  const built = await planList({ vault: seller, sync: localSync(ix), tip: c.next - 1, ticker: 'GENE', amount: 600n, price: 5000n, payScript: SELLER_PAY });
  const envelope = await prove(built);
  const cp = planCarrier({ envelope, payer: { address: WPKH }, utxos: [{ txid: '33'.repeat(32), vout: lockIndex, value: 100000n }], feeRate: 1, tipHeight: c.next - 1, outputs: listOutputs(lock.script) });
  const reveal = revealFor(cp, 'c2'.repeat(32));
  assert.equal(toHex(reveal.tx.vout[0].script), toHex(lock.script), 'the lock is the reveal\'s output 0');
  assert.equal(reveal.tx.vout[0].value, LOCK_SATS);
  const r = c.block(ixTx(reveal.tx, reveal.txid));
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].type, 'LIST');
  for (const n of built.inputs) await seller.updateNote(n.id, { spent: `block ${r.height}` }); // what a sync would find
  return { lock, reveal, listing: ix.listings.get(reveal.txid) };
}

test('BURN and LIST with real proofs; an offer that another vault TAKEs, paying the seller', async () => {
  const { ix, c, seller } = await setup(plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }));
  const p = nodeProver();

  // BURN 300 of a 1,000 note: the change of 700 comes back sealed
  const burn = await planBurn({ vault: seller, sync: localSync(ix), tip: c.next - 1, ticker: 'GENE', amount: 300n });
  assert.equal(burn.change, 700n);
  const envelope = await proveSpend(p, burn);
  assert.equal(envelope.length, 842);
  const cp = planCarrier({ envelope, payer: { address: WPKH }, utxos: [{ txid: '44'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: c.next - 1 });
  const rb = c.block(ixTx(revealFor(cp, 'c3'.repeat(32)).tx, 'b1'.repeat(32)));
  assert.deepEqual(rb.rejected, []);
  assert.equal(rb.events[0].type, 'BURN');
  assert.equal(ix.token('GENE').burned, 300n);
  for (const n of seller.state.notes) if (n.pos === burn.inputs[0].pos) await seller.updateNote(n.id, { spent: 'block' });

  // LIST 600 of the other note
  const { lock, reveal, listing } = await list(ix, c, seller, (b) => proveSpend(p, b));
  assert.equal(listing.state, 'ACTIVE');
  assert.equal(listing.lockKey, toHex(lock.key));

  // the offer: read back from the chain, signed by the lock key, as one line of text
  const l = listingFromChain(reveal.txid, reveal.hex, { ...listing, amount: String(listing.amount), price: String(listing.price) });
  assert.deepEqual([l.ticker, l.amount, l.price, toHex(l.payScript)], ['GENE', 600n, 5000n, toHex(SELLER_PAY)]);
  const offer = encodeOffer(reveal.txid, signOffer(lock.secret, l));
  const { listTxid, sig } = decodeOffer(offer);
  assert.equal(listTxid, reveal.txid);
  assert.ok(offerValid(l, sig));
  assert.ok(!offerValid({ ...l, price: 4999n }, sig), 'a lower price is not the offer');
  assert.ok(!offerValid({ ...l, payScript: fromHex('0014' + 'ee'.repeat(20)) }, sig), 'nor another payee');
  assert.throws(() => listingFromChain(reveal.txid, reveal.hex, { ...listing, price: '1' }), /differs from the chain: price/);

  // another vault takes it: lock at input 0, the price at output 0, its npk in the TAKE
  const buyer = await vaultOf(cv.wallets[2].m);
  const npk = (await buyer.opening(0)).npk;
  const t = buildTake({ l, sig, npk, payer: { address: WPKH }, utxos: [{ txid: '55'.repeat(32), vout: 1, value: 50000n }], feeRate: 1, tipHeight: c.next - 1 });
  assert.equal(t.tx.vin[0].txid, reveal.txid);
  assert.deepEqual(t.inputIndexes, [1], 'the wallet signs only its own inputs');
  assert.equal(t.tx.vout[0].value, 5000n);
  assert.equal(t.tx.locktime, 0);
  const rt = c.block(ixTx(fakeSigned(t.tx), 'd1'.repeat(32)));
  assert.deepEqual(rt.rejected, []);
  assert.equal(rt.events[0].outcome, 'SOLD');
  assert.equal(ix.listings.get(reveal.txid).state, 'SOLD');
  assert.equal(ix.tree.leaves[rt.events[0].pos], noteLeaf(GENE, 600n, npk, 0n), 'the buyer\'s public note');
});

const fakeProve = async (built) => withProof(built.env, testProof());

test('the seller cancels with a TAKE of its own: the tokens come back as its public note', async () => {
  const { ix, c, seller } = await setup(mockVerifier());
  const { lock, reveal, listing } = await list(ix, c, seller, fakeProve);
  const l = listingFromChain(reveal.txid, reveal.hex, { ...listing, amount: String(listing.amount), price: String(listing.price) });
  const npk = (await seller.opening(5)).npk;
  const t = buildCancel({ l, lockSecret: lock.secret, npk, payer: { address: WPKH }, utxos: [{ txid: '66'.repeat(32), vout: 0, value: 20000n }], feeRate: 1, tipHeight: c.next - 1 });
  assert.equal(t.tx.vin[0].witness.length, 1, 'the lock is signed by the vault');
  const r = c.block(ixTx(fakeSigned(t.tx), 'e1'.repeat(32)));
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].outcome, 'CANCELLED');
  assert.equal(ix.tree.leaves[r.events[0].pos], noteLeaf(GENE, 600n, npk, 0n));
  assert.ok(serializeTx(t.tx).length > 0);
});

test('a lock spent with no TAKE closes the listing; the seller CLAIMs it back with the lock key', async () => {
  const { ix, c, seller } = await setup(mockVerifier());
  const { lock, reveal } = await list(ix, c, seller, fakeProve);
  // the lock spent by a transaction that carries no envelope
  const r1 = c.block({ txid: 'f1'.repeat(32), vin: [{ txid: reveal.txid, vout: 0, witness: [Buffer.alloc(64)] }], vout: [{ value: 0n, script: Buffer.from(addressToScript(WPKH)) }] });
  assert.equal(r1.events[0].type, 'CLOSED');
  const npk = (await seller.opening(6)).npk;
  assert.equal(toHex(claimMessage(reveal.txid, npk)), Indexer.claimMessage(reveal.txid, npk).toString('hex'), 'the message the indexer checks');
  const cl = buildClaim({ listTxid: reveal.txid, lockSecret: lock.secret, npk, payer: { address: WPKH }, utxos: [{ txid: '77'.repeat(32), vout: 0, value: 20000n }], feeRate: 1, tipHeight: c.next - 1 });
  assert.equal(cl.envelope.length, 134);
  const r2 = c.block(ixTx(fakeSigned(cl.tx), 'f2'.repeat(32)));
  assert.deepEqual(r2.rejected, [], 'the indexer checks the BIP340 signature by the lock key');
  assert.equal(r2.events[0].type, 'CLAIM');
  assert.equal(ix.listings.get(reveal.txid).state, 'CLAIMED');
  assert.equal(ix.tree.leaves[r2.events[0].pos], noteLeaf(GENE, 600n, npk, 0n));
  // another key's claim is refused
  const { reveal: rv2 } = await list(ix, c, seller, fakeProve);
  c.block({ txid: 'f3'.repeat(32), vin: [{ txid: rv2.txid, vout: 0, witness: [Buffer.alloc(64)] }], vout: [] });
  const wrong = buildClaim({ listTxid: rv2.txid, lockSecret: (await seller.lockOutput(99)).secret, npk, payer: { address: WPKH }, utxos: [{ txid: '88'.repeat(32), vout: 0, value: 20000n }], feeRate: 1, tipHeight: c.next - 1 });
  assert.deepEqual(c.block(ixTx(fakeSigned(wrong.tx), 'f4'.repeat(32))).rejected.map((x) => x.reason), ['bad CLAIM signature']);
  assert.equal(frHex(npk).length, 64);
});

test('lock keys come from the master secret: the same after a restore, one per listing', async () => {
  const a = await vaultOf(cv.wallets[0].m);
  const b = await vaultOf(cv.wallets[0].m);
  assert.equal(toHex((await a.lockOutput(3)).script), toHex((await b.lockOutput(3)).script));
  assert.notEqual(toHex((await a.lockOutput(3)).key), toHex((await a.lockOutput(4)).key));
  assert.equal(await a.reserveLock(), 0);
  assert.equal(await a.reserveLock(), 1);
});

test('the turnstile: a BURN or LIST above the pool is refused before proving, as the indexer would refuse it', async () => {
  const { poolProblem } = await import('../src/market.js');
  const { normToken } = await import('../src/api.js');
  const { ix, c, seller } = await setup(mockVerifier());
  const json = (x) => JSON.parse(JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
  const token = normToken(json(ix.token('GENE')));
  assert.equal(token.pool, 2000n, 'two mints of 1,000 went in');
  assert.equal(poolProblem([token], 'GENE', 2000n, 'BURN'), null);
  assert.match(poolProblem([token], 'GENE', 2001n, 'BURN'), /holds only 2000 GENE: a BURN of 2001 would be rejected .* fees lost/);
  assert.match(poolProblem([token, { ...token, pool: 500n }], 'GENE', 600n, 'LIST'), /holds only 500/, 'the lowest of the indexers');
  assert.match(poolProblem([{ ...token, pool: null }], 'GENE', 1n, 'LIST'), /does not report the pool/);
  assert.match(poolProblem([], 'GENE', 1n, 'LIST'), /no indexer/);
  // what the indexer does with a spend above the pool: rejected before its proof is looked at
  const built = await planBurn({ vault: seller, sync: localSync(ix), tip: c.next - 1, ticker: 'GENE', amount: 1000n });
  const over = { ...built.env, vPub: 2001n };
  const r = c.block(helperTx({ env: { ...over, spend: { ...over.spend, proof: testProof() } }, carrier: 'witness' }));
  assert.deepEqual(r.rejected.map((x) => x.reason), ['more than the pool holds of this ticker']);
});
