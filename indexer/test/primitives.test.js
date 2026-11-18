import { test } from 'node:test';
import assert from 'node:assert/strict';
import { poseidon2, POSEIDON2_VECTOR_1_2 } from '../src/poseidon.js';
import { publicKey, sign, verify } from '../src/schnorr.js';
import { NoteTree, rootFromPath } from '../src/tree.js';

const H = (x) => Buffer.from(x, 'hex');

test('Poseidon matches the circomlib vector poseidon([1, 2])', () => {
  assert.equal(poseidon2(1n, 2n), POSEIDON2_VECTOR_1_2);
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
  const snap = t.snapshot();
  t.append(66n);
  assert.notEqual(t.root, snap.root);
  t.restore(snap);
  assert.equal(t.root, snap.root);
  assert.equal(t.size, 5);
});

test('sibling index stays right past 2^31 (no 32-bit bitwise ops in the tree)', async () => {
  const { siblingIndex } = await import('../src/tree.js');
  assert.equal(siblingIndex(0), 1);
  assert.equal(siblingIndex(7), 6);
  assert.equal(siblingIndex(2 ** 31), 2 ** 31 + 1);
  assert.equal(siblingIndex(2 ** 32 - 1), 2 ** 32 - 2);
  assert.notEqual(2 ** 31 ^ 1, 2 ** 31 + 1);
});
