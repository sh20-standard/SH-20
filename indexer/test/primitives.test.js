import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { P, poseidon, poseidon2, POSEIDON2_VECTOR_1_2 } from '../src/poseidon.js';
import { publicKey, sign, verify } from '../src/schnorr.js';
import { NoteTree, rootFromPath } from '../src/tree.js';

const H = (x) => Buffer.from(x, 'hex');

test('Poseidon matches the circomlib vector poseidon([1, 2])', () => {
  assert.equal(poseidon2(1n, 2n), POSEIDON2_VECTOR_1_2);
});

test('Poseidon with 2 to 5 inputs matches circomlibjs', () => {
  // written from circomlibjs by circuit/bench/poseidon-vectors.mjs
  const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/poseidon-circomlibjs.json', import.meta.url), 'utf8'));
  const counting = (n) => vectors.find((v) => v.inputs.join() === Array.from({ length: n }, (_, i) => i + 1).join());
  for (const n of [2, 3, 4, 5]) assert.ok(counting(n), `poseidon([1..${n}]) is among the vectors`);
  assert.equal(BigInt(counting(2).hash), POSEIDON2_VECTOR_1_2);
  for (const { inputs, hash } of vectors) {
    assert.equal(poseidon(inputs.map(BigInt)).toString(), hash, `${inputs.length} inputs`);
    if (inputs.length === 2) assert.equal(poseidon2(BigInt(inputs[0]), BigInt(inputs[1])).toString(), hash);
  }
  // inputs are taken modulo the field, as poseidon2 always did
  assert.equal(poseidon([P + 1n, 2n, -1n]), poseidon([1n, 2n, P - 1n]));
  assert.equal(poseidon2(1, 2), POSEIDON2_VECTOR_1_2);
  // only the widths circomlib is used with here
  for (const bad of [[], [1n], [1n, 2n, 3n, 4n, 5n, 6n]]) assert.throws(() => poseidon(bad), /not supported/);
  assert.throws(() => poseidon(1n, 2n), /array/);
});

test('BIP340 test vectors 0 and 1 (sign and verify)', () => {
  const vectors = [
    ['0000000000000000000000000000000000000000000000000000000000000003', 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9', '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'],
    ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', '0000000000000000000000000000000000000000000000000000000000000001', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'],
  ];
  for (const [sk, pk, aux, msg, sig] of vectors) {
    assert.equal(publicKey(H(sk)).toString('hex').toUpperCase(), pk);
    assert.equal(sign(H(sk), H(msg), H(aux)).toString('hex').toUpperCase(), sig);
    assert.ok(verify(H(pk), H(msg), H(sig)));
    const bad = H(sig);
    bad[63] ^= 1;
    assert.ok(!verify(H(pk), H(msg), bad));
    const otherMsg = H(msg);
    otherMsg[0] ^= 1;
    assert.ok(!verify(H(pk), otherMsg, H(sig)));
  }
});

test('note tree: paths recompute the root', () => {
  const t = new NoteTree();
  const leaves = [11n, 22n, 33n, 44n, 55n];
  leaves.forEach((l) => t.append(l));
  leaves.forEach((l, i) => assert.equal(rootFromPath(l, i, t.path(i)), t.root));
  const before = t.root;
  const snap = t.snapshot();
  t.append(66n);
  assert.notEqual(t.root, before);
  t.restore(snap);
  assert.equal(t.root, before);
  assert.equal(t.size, 5);
});

test('note tree: every root and path agrees with a tree recomputed from its leaves, through appends and rollbacks', async () => {
  const { poseidon2 } = await import('../src/poseidon.js');
  const DEPTH = 6; // small enough to recompute, deep enough for every shape of unfinished subtree
  const naive = (leaves) => {
    const zeros = [0n];
    for (let i = 0; i < DEPTH; i++) zeros.push(poseidon2(zeros[i], zeros[i]));
    const levels = [leaves.slice()];
    for (let i = 0; i < DEPTH; i++) {
      const lv = levels[i];
      const up = [];
      for (let k = 0; k < Math.max(1, Math.ceil(lv.length / 2)); k++) up.push(poseidon2(lv[2 * k] ?? zeros[i], lv[2 * k + 1] ?? zeros[i]));
      levels.push(up);
    }
    const node = (i, k) => levels[i][k] ?? zeros[i];
    return { root: node(DEPTH, 0), path: (p) => Array.from({ length: DEPTH }, (_, i) => node(i, Math.floor(p / 2 ** i) ^ 1)) };
  };
  const t = new NoteTree(DEPTH);
  const leaves = [];
  assert.equal(t.root, naive([]).root);
  for (let n = 1; n <= 2 ** DEPTH; n++) {
    leaves.push(BigInt(1000 + n));
    t.append(leaves.at(-1));
    const ref = naive(leaves);
    assert.equal(t.root, ref.root, `root at size ${n}`);
    for (const p of [0, n - 1, Math.floor(n / 2), Math.floor(n / 3)]) assert.deepEqual(t.path(p), ref.path(p), `path ${p} at size ${n}`);
    if (n % 7 === 0) {
      // roll back a few leaves and grow again: the tree must be the one of the shorter list
      const keep = n - 3;
      t.restore({ size: keep });
      assert.equal(t.root, naive(leaves.slice(0, keep)).root, `root after rollback to ${keep}`);
      for (let i = keep; i < n; i++) t.append(leaves[i]);
      assert.equal(t.root, ref.root);
    }
  }
  assert.throws(() => t.append(1n), /tree full/);
});

test('sibling index stays right past 2^31 (no 32-bit bitwise ops in the tree)', async () => {
  const { siblingIndex } = await import('../src/tree.js');
  assert.equal(siblingIndex(0), 1);
  assert.equal(siblingIndex(7), 6);
  assert.equal(siblingIndex(2 ** 31), 2 ** 31 + 1);
  assert.equal(siblingIndex(2 ** 32 - 1), 2 ** 32 - 2);
  assert.notEqual(2 ** 31 ^ 1, 2 ** 31 + 1);
});
