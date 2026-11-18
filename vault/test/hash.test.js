import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { sha256, ripemd160 } from '../src/hash.js';
import { toHex, utf8 } from '../src/bytes.js';

test('sha256 matches node:crypto on many lengths', () => {
  for (let n = 0; n < 300; n++) {
    const m = randomBytes(n);
    assert.equal(toHex(sha256(m)), createHash('sha256').update(m).digest('hex'));
  }
  assert.equal(toHex(sha256(utf8('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('ripemd160 matches the reference vectors and node:crypto', () => {
  assert.equal(toHex(ripemd160(utf8(''))), '9c1185a5c5e9fc54612808977ee8f548b2258d31');
  assert.equal(toHex(ripemd160(utf8('abc'))), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
  assert.equal(toHex(ripemd160(utf8('message digest'))), '5d0689ef49d2fae572b881b123a85ffa21595f36');
  assert.equal(toHex(ripemd160(utf8('1234567890'.repeat(8)))), '9b752e45573d4b39f4dbd3323cab82bf63326bfb');
  let node = true;
  try { createHash('ripemd160'); } catch { node = false; }
  if (node) for (let n = 0; n < 200; n++) {
    const m = randomBytes(n);
    assert.equal(toHex(ripemd160(m)), createHash('ripemd160').update(m).digest('hex'));
  }
});
