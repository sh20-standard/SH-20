import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as node from 'node:crypto';
import { ShimBuffer } from '../src/shim/buffer.js';
import * as shim from '../src/shim/node-crypto.js';

test('Buffer shim behaves like Node Buffer on what the codec uses', () => {
  const hex = '00ff10a5deadbeef0123456789abcdef';
  const a = Buffer.from(hex, 'hex');
  const b = ShimBuffer.from(hex, 'hex');
  assert.equal(b.toString('hex'), a.toString('hex'));
  assert.equal(b.readUInt16LE(1), a.readUInt16LE(1));
  assert.equal(b.readUInt32LE(3), a.readUInt32LE(3));
  assert.equal(b.readUInt32BE(3), a.readUInt32BE(3));
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
  // what circuit/js adds: toString with a range, write
  const p = ShimBuffer.alloc(12);
  assert.equal(p.write('GENE', 8, 'latin1'), 4);
  assert.equal(p.toString('latin1', 8, 12), 'GENE');
  assert.equal(p.toString('hex', 8, 10), Buffer.from('GE').toString('hex'));
});

test('node:crypto shim gives Node\'s bytes: SHA-256/512, HMAC, HKDF, AES-256-GCM, X25519', () => {
  for (let n = 0; n < 160; n++) {
    const m = node.randomBytes(n);
    const k = node.randomBytes(n % 140);
    for (const alg of ['sha256', 'sha512']) {
      assert.equal(shim.createHash(alg).update('tag', 'utf8').update(m).digest('hex'), node.createHash(alg).update('tag', 'utf8').update(m).digest('hex'));
      assert.equal(shim.createHmac(alg, k).update(m).digest('hex'), node.createHmac(alg, k).update(m).digest('hex'));
    }
    const info = node.randomBytes(n % 70);
    const len = 1 + (n % 90);
    assert.equal(Buffer.from(shim.hkdfSync('sha256', m, k, info, len)).toString('hex'), Buffer.from(node.hkdfSync('sha256', m, k, info, len)).toString('hex'));

    const key = node.randomBytes(32);
    const iv = node.randomBytes(12);
    const aad = node.randomBytes(n % 48);
    const enc = (lib) => {
      const c = lib.createCipheriv('aes-256-gcm', key, iv).setAAD(aad);
      return [Buffer.concat([c.update(m), c.final()]).toString('hex'), Buffer.from(c.getAuthTag()).toString('hex')];
    };
    const [ct, tag] = enc(node);
    assert.deepEqual(enc(shim), [ct, tag]);
    const dec = (t) => {
      const d = shim.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 }).setAAD(aad).setAuthTag(Buffer.from(t, 'hex'));
      return Buffer.concat([d.update(Buffer.from(ct, 'hex')), d.final()]).toString('hex');
    };
    assert.equal(dec(tag), m.toString('hex'));
    assert.throws(() => dec((tag[0] === '0' ? '1' : '0') + tag.slice(1)), /authenticate/, 'a forged tag is refused');
  }
  // X25519 in the DER forms circuit/js/address.js uses
  const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
  const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
  for (let n = 0; n < 60; n++) {
    const k = node.randomBytes(32);
    const u = node.randomBytes(32);
    const pub = (lib) => Buffer.from(lib.createPublicKey(lib.createPrivateKey({ key: Buffer.concat([PKCS8, k]), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' })).toString('hex');
    assert.equal(pub(shim), pub(node));
    const dh = (lib) => Buffer.from(lib.diffieHellman({
      privateKey: lib.createPrivateKey({ key: Buffer.concat([PKCS8, k]), format: 'der', type: 'pkcs8' }),
      publicKey: lib.createPublicKey({ key: Buffer.concat([SPKI, u]), format: 'der', type: 'spki' }),
    })).toString('hex');
    assert.equal(dh(shim), dh(node));
  }
  const low = { privateKey: shim.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, 1)]), format: 'der', type: 'pkcs8' }), publicKey: shim.createPublicKey({ key: Buffer.concat([SPKI, Buffer.alloc(32)]), format: 'der', type: 'spki' }) };
  assert.throws(() => shim.diffieHellman(low), /zero/, 'a low-order point is refused, as Node does');
});

test('indexer codec and circuit/js run unchanged in a browser-like environment, on their vectors', () => {
  const run = fileURLToPath(new URL('./browser-env/run.mjs', import.meta.url));
  const out = JSON.parse(execFileSync(process.execPath, [run], { encoding: 'utf8' }));
  assert.equal(out.shim, true, 'the shim Buffer was used');
  assert.ok(Object.keys(out.envelopes).length >= 7);
  for (const [name, ok] of Object.entries(out.envelopes)) assert.equal(ok, true, name);
  assert.equal(out.noteLeaf, true);
  assert.equal(out.domainLeaf, true);
  assert.equal(out.rejectsTrailing, true);
  assert.equal(out.carrier, true, 'carrier.js finds the envelope');
  // circuit/js/vectors.json (written by the circuit's Rust model) through the browser shim
  assert.equal(out.rfc7748, true, 'X25519 is RFC 7748');
  for (const k of ['wallets', 'invalidAddresses', 'sealed', 'publicNotes', 'spendNullifiers', 'spendOutputs']) {
    assert.ok(out[k].length > 0, k);
    out[k].forEach((ok, i) => assert.equal(ok, true, `${k}[${i}]`));
  }
  assert.equal(out.invalidAddresses.length, 13);
});
