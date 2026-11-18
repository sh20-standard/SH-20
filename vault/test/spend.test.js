// Spends with real proofs. First the vault's public inputs against plonk-scenario.json (the
// circuit's own TRANSFER and BURN: same root, nullifiers, leaves, body hash and order, or the pinned
// verifier refuses them); then a TRANSFER the vault builds, proves and reveals, which the reference
// indexer accepts with the real PLONK verifier, and whose outputs the recipient and the vault find.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { chain, deployEnv, tx as helperTx } from '../../indexer/test/helpers.js';
import { nodeProver, WASM } from './prover-node.js';
import { buildSpend, withProof, publicInputs, pickInputs, WITNESS_BYTES } from '../src/spend.js';
import { LocalTree } from '../src/tree.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { NOTE_SCHEME, wallet as walletOf } from '../src/notekeys.js';
import { commitment, commitValue, signReveal, oneTimeSecret } from '../src/taproot.js';
import { addressToScript } from '../src/btc.js';
import { fromHex } from '../src/bytes.js';
import { frHex } from '../src/fr.js';
import { parseEnvelope, noteLeaf, tickerT, decodeAddress, scan, SPEND_VK_DIGEST, PROOF_BYTES } from '../src/sh20.js';

const json = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const scenario = json('../../indexer/test/fixtures/plonk-scenario.json');
const cv = json('../../circuit/js/vectors.json');
const GENE = tickerT('GENE');

const parts = (hex) => {
  const bytes = fromHex(hex);
  return { env: parseEnvelope(Buffer.from(bytes)).env, body: bytes.subarray(0, bytes.length - PROOF_BYTES) };
};

test('the vault computes the public inputs of the circuit\'s own TRANSFER and BURN (plonk-scenario.json)', async () => {
  const p = nodeProver();
  assert.equal(p.vkDigest, SPEND_VK_DIGEST, 'the committed module and the shipped key give the pinned verifying key');
  const tree = new LocalTree();
  tree.append(scenario.mints.map((m) => noteLeaf(GENE, 1000n, BigInt(m.npk), 0n)));
  const transfer = parts(scenario.transfer);
  assert.equal(transfer.env.spend.anchorHeight, 2);
  const tp = publicInputs({ root: tree.root, ...transfer });
  assert.equal(await p.verify(tp, transfer.env.spend.proof), true);
  tree.append(transfer.env.spend.outs.map((o) => o.leaf));
  const burn = parts(scenario.burn);
  const bp = publicInputs({ root: tree.root, ...burn, vPub: burn.env.vPub, tPub: GENE });
  assert.equal(await p.verify(bp, burn.env.spend.proof), true);
  bp[7 * 32] ^= 1; // another vPub
  assert.equal(await p.verify(bp, burn.env.spend.proof), false);
});

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};
async function vaultOf(m) {
  const st = memStorage();
  st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: m } }));
  return Vault.open(st);
}
const toIndexerTx = (t, txid) => ({
  txid,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

test('a TRANSFER built and proved by the vault is accepted by the indexer with the real verifier', async () => {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier: plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }) });
  const c = chain(ix);
  // GENE (D = 0) and two public notes of the vault, 1,000 each
  const vault = await vaultOf(cv.wallets[0].m);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }) }));
  const mints = [];
  for (const i of [0, 1]) mints.push(vault.opening(i));
  const b = c.block(...mints.map((o) => helperTx({ env: { type: 'MINT', ticker: 'GENE', npk: o.npk }, burnSats: 1000n })));
  assert.equal(b.events.filter((e) => e.type === 'MINT').length, 2, JSON.stringify(b.rejected));
  const notes = [];
  for (const [k, e] of b.events.filter((x) => x.type === 'MINT').entries()) notes.push(await vault.addNote({ index: k, ticker: 'GENE', v: 1000n, txid: null, status: 'in tree', pos: e.pos }));
  for (const n of notes) await vault.updateNote(n.id, { spent: 'no' });
  const anchorHeight = c.next - 1;

  // the local tree, as a sync rebuilds it
  const tree = new LocalTree();
  tree.append(ix.tree.leaves);
  assert.equal(tree.root, ix.tree.root);

  const me = walletOf(fromHex(cv.wallets[0].m));
  const recipient = cv.wallets.find((w) => w.name === 'recipient');
  const ins = pickInputs(vault.state.notes, 'GENE', 1500n);
  assert.equal(ins.length, 2, 'two notes of 1,000 pay 1,500');
  const built = buildSpend({
    wallet: me, ticker: 'GENE', inputs: ins, paths: ins.map((n) => tree.path(n.pos)), root: tree.root, anchorHeight,
    outputs: [{ address: decodeAddress('tsh20', recipient.addressTest), v: 1500n }, { address: me.address, v: 500n }, { address: me.address, v: 0n }],
    envelope: (spend) => ({ type: 'TRANSFER', spend }),
  });
  assert.equal(built.witness.length, WITNESS_BYTES);
  const p = nodeProver();
  const t0 = performance.now();
  const proof = await p.prove(built.witness);
  console.log(`  proved in ${((performance.now() - t0) / 1000).toFixed(1)} s (one thread, Node)`);
  assert.ok(proof && proof.length === 480, 'the prover accepts the vault\'s witness');
  assert.equal(await p.verify(built.publics, proof), true);
  const envelope = withProof(built.env, proof);
  assert.equal(envelope.length, 830);

  // the witness carrier: commit output, then the reveal the indexer reads
  const secret = oneTimeSecret();
  const cm = commitment(secret, envelope);
  const back = addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
  const value = commitValue(cm, back, 1);
  const reveal = signReveal({ secret, c: cm, commitTxid: 'c0'.repeat(32), value, returnScript: back, feeRate: 1 });
  const r = c.block(toIndexerTx(reveal.tx, reveal.txid));
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].type, 'TRANSFER');
  assert.equal(ix.nullifiers.size, 2);
  // the recipient finds its 1,500; the vault its 500 of change (the 0 is an unused output)
  const outs = ix.notes.filter((n) => n.kind === 'OUT');
  const rk = walletOf(fromHex(recipient.m));
  const theirs = outs.map((o) => scan(rk.ivk, rk.address, { leaf: BigInt('0x' + o.leaf), pkEph: fromHex(o.pkEph), ct: fromHex(o.ct) })).filter(Boolean);
  assert.deepEqual(theirs.map((x) => x.v), [1500n]);
  const mine = [];
  for (const o of outs) mine.push(await vault.receive({ pos: o.pos, leaf: BigInt('0x' + o.leaf), pkEph: fromHex(o.pkEph), ct: fromHex(o.ct) }));
  assert.deepEqual(mine.filter(Boolean).map((x) => x.v), ['500']);
  // and the indexer's nullifiers are the ones the vault computes for its two notes
  for (const n of notes) assert.ok(ix.nullifiers.has(frHex(vault.nullifier(n))));
});
