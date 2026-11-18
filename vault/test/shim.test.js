import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ShimBuffer } from '../src/shim/buffer.js';
import { deriveNpk } from '../src/npk.js';
import { frHex } from '../src/fr.js';

test('Buffer shim behaves like Node Buffer on what the codec uses', () => {
  const hex = '00ff10a5deadbeef0123456789abcdef';
  const a = Buffer.from(hex, 'hex');
  const b = ShimBuffer.from(hex, 'hex');
  assert.equal(b.toString('hex'), a.toString('hex'));
  assert.equal(b.readUInt16LE(1), a.readUInt16LE(1));
  assert.equal(b.readUInt32LE(3), a.readUInt32LE(3));
  assert.equal(b.readBigUInt64LE(5), a.readBigUInt64LE(5));
  assert.equal(ShimBuffer.from('SH20', 'ascii').toString('latin1'), 'SH20');
  assert.ok(b.subarray(2, 4) instanceof ShimBuffer);
  assert.ok(b.subarray(2, 4).equals(a.subarray(2, 4)));
  assert.equal(ShimBuffer.from(b).reverse().toString('hex'), Buffer.from(a).reverse().toString('hex'));
  assert.equal(ShimBuffer.concat([b, b]).toString('hex'), hex + hex);
  assert.equal(ShimBuffer.from('é', 'utf8').toString('hex'), Buffer.from('é', 'utf8').toString('hex'));
  const w = ShimBuffer.alloc(8);
  w.writeBigUInt64LE(0x0102030405060708n);
  assert.equal(w.toString('hex'), '0807060504030201');
  assert.throws(() => ShimBuffer.alloc(4).writeUInt32LE(2 ** 32), RangeError);
  assert.throws(() => ShimBuffer.alloc(8).writeBigUInt64LE(-1n), RangeError);
  assert.throws(() => ShimBuffer.alloc(2).writeUInt16LE(70000), RangeError);
});

test('indexer codec runs unchanged in a browser-like environment', () => {
  const run = fileURLToPath(new URL('./browser-env/run.mjs', import.meta.url));
  const out = JSON.parse(execFileSync(process.execPath, [run], { encoding: 'utf8' }));
  assert.equal(out.shim, true, 'the shim Buffer was used');
  assert.ok(Object.keys(out.envelopes).length >= 7);
  for (const [name, ok] of Object.entries(out.envelopes)) assert.equal(ok, true, name);
  assert.equal(out.noteLeaf, true);
  assert.equal(out.domainLeaf, true);
  assert.equal(out.rejectsTrailing, true);
  assert.equal(out.carrier, true, 'carrier.js finds the DEPLOY envelope');
  assert.equal(out.npk7, frHex(deriveNpk(new Uint8Array(32).fill(7), 3).npk), 'same npk in Node and browser');
});
