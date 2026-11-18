// The reference against the vectors written by the circuit's own model (circuit/src/vectors.rs):
// every value a wallet derives for a spend must come out the same in JavaScript and in Rust.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NoteTree } from '../../../indexer/src/tree.js';
import { DOMAIN } from '../../../indexer/src/constants.js';
import { parseEnvelope } from '../../../indexer/src/codec.js';
import { BASE8, L, NONCE_TAG, bodyHash, noteKeys, noteLeaf, npkOf, nullifier, poseidon, sign, tickerT, verify } from '../index.js';

const v = JSON.parse(readFileSync(new URL('../vectors.json', import.meta.url), 'utf8'));
const n = BigInt;
const point = (p) => p.map(n);
const str = (p) => p.map(String);

test('constants', () => {
  assert.equal(L.toString(), v.constants.l);
  assert.deepEqual(str(BASE8), v.constants.base8);
  assert.equal(DOMAIN.LEAF.toString(), v.constants.tagLeaf);
  assert.equal(NONCE_TAG, v.constants.nonceTag);
});

test('Poseidon, 2 to 5 inputs', () => {
  assert.deepEqual(v.poseidon.map((x) => x.inputs.length), [2, 3, 4, 5]);
  for (const { inputs, hash } of v.poseidon) assert.equal(poseidon(inputs.map(n)).toString(), hash);
});

test('ticker ids', () => {
  for (const { ticker, t } of v.tickers) assert.equal(tickerT(ticker).toString(), t);
});

test('note keys and npk', () => {
  assert.ok(v.keys.length >= 4);
  for (const k of v.keys) {
    const got = noteKeys(n(k.sk), n(k.nk));
    assert.deepEqual(str(got.ak), k.ak, 'Ak');
    assert.deepEqual(str(got.nkPub), k.nkPub, 'NK');
    assert.equal(got.npk.toString(), k.npk, 'npk');
    assert.equal(npkOf(point(k.ak), point(k.nkPub)).toString(), k.npk);
  }
});

test('note leaves', () => {
  for (const x of v.leaves) assert.equal(noteLeaf(tickerT(x.ticker), n(x.v), n(x.npk), n(x.rho)).toString(), x.leaf);
});

test('nullifiers', () => {
  assert.ok(v.nullifiers.some((x) => x.index === '0') && v.nullifiers.some((x) => x.index === String(2 ** 32 - 1)));
  for (const x of v.nullifiers) assert.equal(nullifier(n(x.nk), n(x.leaf), n(x.index)).toString(), x.nf);
});

test('body hashes', () => {
  for (const x of v.bodies) assert.equal(bodyHash(Buffer.from(x.body, 'hex')).toString(), x.bodyHash);
});

test('EdDSA-Poseidon signatures', () => {
  assert.ok(v.signatures.length >= 4);
  for (const x of v.signatures) {
    const sig = sign(n(x.sk), n(x.message));
    assert.deepEqual(str(sig.r8), x.r8, 'R8');
    assert.equal(sig.s.toString(), x.s, 'S');
    assert.ok(verify(point(x.ak), n(x.message), { r8: point(x.r8), s: n(x.s) }));
  }
});

test('a whole transfer: tree, nullifiers, leaves, body hash, signatures, public inputs', () => {
  const s = v.spend;
  const t = tickerT(s.ticker);
  const tree = new NoteTree();
  for (const leaf of s.treeLeaves) tree.append(n(leaf));
  assert.equal(tree.root.toString(), s.root);

  const m = bodyHash(Buffer.from(s.body, 'hex'));
  assert.equal(m.toString(), s.bodyHash);

  const nf = s.inputs.map((input, i) => {
    const keys = noteKeys(n(input.sk), n(input.nk));
    const leaf = noteLeaf(t, n(input.v), keys.npk, n(input.rho));
    assert.equal(tree.leaves[Number(input.index)], leaf, 'the input note is in the tree at its position');
    const sig = sign(keys.sk, m);
    assert.deepEqual(str(sig.r8), s.signatures[i].r8);
    assert.equal(sig.s.toString(), s.signatures[i].s);
    assert.ok(verify(keys.ak, m, sig));
    return nullifier(keys.nk, leaf, n(input.index)).toString();
  });
  assert.deepEqual(nf, s.nf);

  const outLeaf = s.outputs.map((o) => noteLeaf(t, n(o.v), n(o.npk), n(o.rho)).toString());
  assert.deepEqual(outLeaf, s.outLeaf);

  // value is conserved, and the public inputs are in the verifier's order
  const sum = (xs) => xs.reduce((a, x) => a + n(x.v), 0n);
  assert.equal(sum(s.inputs), sum(s.outputs) + n(s.vPub));
  assert.deepEqual([s.root, ...nf, ...outLeaf, s.bodyHash, s.vPub, s.tPub], s.publics);

  // the body is the TRANSFER envelope the indexer parses, up to proofLen
  const envelope = Buffer.concat([Buffer.from(s.body, 'hex'), Buffer.from([1, 0]), Buffer.alloc(1)]);
  const { env, body } = parseEnvelope(envelope);
  assert.equal(env.type, 'TRANSFER');
  assert.equal(env.spend.anchorHeight, s.anchorHeight);
  assert.deepEqual(env.spend.nf.map(String), s.nf);
  assert.deepEqual(env.spend.outs.map((o) => o.leaf.toString()), s.outLeaf);
  assert.equal(Buffer.from(body).toString('hex'), s.body);
});
