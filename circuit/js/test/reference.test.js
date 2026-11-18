// Properties of the reference that vectors alone do not pin: the group, what a signature binds, and
// the inputs it refuses.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BASE8, IDENTITY, L, P, add, mul, mulBase8, noteKeys, nullifier, onCurve, sign, verify } from '../index.js';

test('BabyJubJub: Base8 is on the curve and has order l', () => {
  assert.ok(onCurve(BASE8) && onCurve(IDENTITY));
  assert.deepEqual(mul(BASE8, L), [...IDENTITY]);
  assert.notDeepEqual(mul(BASE8, L - 1n), [...IDENTITY]);
  assert.deepEqual(add(BASE8, IDENTITY), [...BASE8]);
  const [p, q] = [mulBase8(11n), mulBase8(31n)];
  assert.deepEqual(add(p, q), mulBase8(42n));
  assert.deepEqual(add(p, q), add(q, p));
  assert.ok(!onCurve([1n, 1n]) && !onCurve([P, 1n]));
});

test('a signature binds the message, the key and both of its parts', () => {
  const keys = noteKeys(123456789n, 987654321n);
  const other = noteKeys(123456790n, 987654321n);
  const m = 0x1234n;
  const sig = sign(keys.sk, m);
  assert.ok(verify(keys.ak, m, sig));
  assert.deepEqual(sign(keys.sk, m), sig, 'the nonce is derived from the key and the message');
  assert.notDeepEqual(sign(keys.sk, m + 1n).r8, sig.r8, 'a new nonce for another message');

  assert.ok(!verify(keys.ak, m + 1n, sig), 'another message');
  assert.ok(!verify(other.ak, m, sig), 'another key');
  assert.ok(!verify(keys.ak, m, { r8: sig.r8, s: (sig.s + 1n) % L }), 'S changed');
  assert.ok(!verify(keys.ak, m, { r8: add(sig.r8, BASE8), s: sig.s }), 'R8 changed');
});

test('what the circuit refuses is refused here', () => {
  const keys = noteKeys(5n, 7n);
  const m = 99n;
  const sig = sign(keys.sk, m);
  // S + l satisfies the group equation but is not below l
  assert.ok(!verify(keys.ak, m, { r8: sig.r8, s: sig.s + L }));
  // a message that is not a field element
  assert.ok(!verify(keys.ak, P + m, sig));
  // points off the curve
  assert.ok(!verify([keys.ak[0] + 1n, keys.ak[1]], m, sig));
  assert.ok(!verify(keys.ak, m, { r8: [sig.r8[0], sig.r8[1] + 1n], s: sig.s }));
  // small-order keys: the identity and the point of order 2 pass the equation with R8 = S·B8
  for (const weak of [[0n, 1n], [0n, P - 1n]]) {
    assert.ok(onCurve(weak));
    assert.ok(!verify(weak, m, { r8: mulBase8(3n), s: 3n }));
  }
});

test('scalars and positions out of range are errors, never silently reduced', () => {
  assert.throws(() => noteKeys(0n, 1n), RangeError);
  assert.throws(() => noteKeys(1n, L), RangeError);
  assert.throws(() => noteKeys(L + 1n, 1n), RangeError);
  assert.throws(() => noteKeys(1, 1n), RangeError);
  assert.throws(() => sign(L, 1n), RangeError);
  assert.throws(() => sign(1n, P), RangeError);
  assert.throws(() => nullifier(L, 1n, 0), RangeError);
  assert.throws(() => nullifier(1n, P, 0), RangeError);
  assert.throws(() => nullifier(1n, 1n, 2 ** 32), RangeError);
  assert.throws(() => nullifier(1n, 1n, -1), RangeError);
  assert.throws(() => mulBase8(L), RangeError);
  // nk + l is the same point NK but would be another nullifier: it is not accepted as a key
  assert.throws(() => nullifier(1n + L, 1n, 0), RangeError);
  assert.equal(typeof nullifier(0n, 0n, 0), 'bigint');
});
