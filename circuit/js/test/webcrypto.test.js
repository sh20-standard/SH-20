// webcrypto.js, the asynchronous reference for browsers, against index.js, the synchronous one for
// Node: the same names, the same values. notes.test.js already runs docs/SPEC-NOTES.md through both
// on the vectors of the Rust model; this file covers what is left: the primitives by themselves,
// the signature, inputs the vectors do not hold, and a platform without X25519.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, createHmac, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as node from '../index.js';
import * as web from '../webcrypto.js';
import * as subtle from '../subtle.js';
import { KAT, knownAnswers } from './subtle-kat.js';

const v = JSON.parse(readFileSync(new URL('../vectors.json', import.meta.url), 'utf8'));
const n = BigInt;
const toHex = (b) => Buffer.from(b).toString('hex');
const str = (p) => p.map(String);

// what is asynchronous in webcrypto.js; everything else must be the very function index.js exports
const ASYNC = ['decodeAddress', 'hashToScalar', 'hr', 'hs', 'masterSecret', 'noteSecrets', 'publicOpening', 'scan', 'seal', 'selfSecret', 'sign', 'walletKeys', 'x25519', 'x25519Public'];

/** Deterministic bytes for the comparisons below: SHA-256 of a label, as many blocks as needed. */
function bytes(label, length = 32) {
  const blocks = [];
  for (let i = 0; blocks.length * 32 < length; i++) blocks.push(createHash('sha256').update(`${label}/${i}`).digest());
  return Buffer.concat(blocks).subarray(0, length);
}

test('webcrypto.js exports the names of index.js, and only the listed ones differ', () => {
  assert.deepEqual(Object.keys(web).filter((k) => k !== 'available').sort(), Object.keys(node).sort());
  assert.deepEqual(Object.keys(node).filter((k) => web[k] !== node[k]).sort(), ASYNC);
});

test('the primitives give the known answers of the RFCs', async () => {
  const results = await knownAnswers(subtle);
  assert.ok(results.length >= 30);
  for (const r of results) assert.ok(r.ok, `${r.name}: got ${r.got}, want ${r.want}`);
});

test('the known answers are also what node:crypto computes', () => {
  assert.equal(createHash('sha256').update(KAT.sha256.data).digest('hex'), KAT.sha256.want);
  assert.equal(createHmac('sha512', KAT.hmacSha512.key).update(KAT.hmacSha512.data).digest('hex'), KAT.hmacSha512.want);
  for (const k of KAT.hkdf) assert.equal(toHex(hkdfSync('sha256', k.ikm, k.salt, k.info, k.length)), k.want);
  for (const k of KAT.x25519) assert.equal(toHex(node.x25519(k.k, k.u)), k.want);
  assert.equal(toHex(node.x25519Public(KAT.x25519Public.k)), KAT.x25519Public.want);
  for (const u of KAT.lowOrder) assert.ok(node.x25519(KAT.x25519[0].k, u).every((b) => b === 0));
  for (const k of KAT.aesGcm) {
    const c = createCipheriv('aes-256-gcm', k.key, k.nonce).setAAD(k.aad);
    assert.equal(toHex(Buffer.concat([c.update(k.plaintext), c.final(), c.getAuthTag()])), k.want);
  }
});

test('X25519: both back ends agree, on ordinary points and on every odd encoding', async () => {
  const k = bytes('x25519/k');
  const odd = [
    ...KAT.lowOrder,
    // the same seven with the top bit set, which RFC 7748 masks
    ...KAT.lowOrder.map((u) => Uint8Array.from(u, (b, i) => (i === 31 ? b | 0x80 : b))),
    // values at and above the field size, and all ones
    ...['efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'].map((s) => Buffer.from(s, 'hex')),
  ];
  for (const u of odd) assert.equal(toHex(await web.x25519(k, u)), toHex(node.x25519(k, u)), toHex(u));
  for (let i = 0; i < 40; i++) {
    const [a, u] = [bytes(`x25519/a/${i}`), bytes(`x25519/u/${i}`)];
    assert.equal(toHex(await web.x25519(a, u)), toHex(node.x25519(a, u)));
    assert.equal(toHex(await web.x25519Public(a)), toHex(node.x25519Public(a)));
  }
});

test('signatures: the vectors of the Rust model, and the same nonce as index.js', async () => {
  for (const x of v.signatures) {
    const sig = await web.sign(n(x.sk), n(x.message));
    assert.deepEqual(str(sig.r8), x.r8, 'R8');
    assert.equal(sig.s.toString(), x.s, 'S');
    assert.ok(web.verify(x.ak.map(n), n(x.message), sig));
    assert.deepEqual(sig, node.sign(n(x.sk), n(x.message)));
  }
  const parts = [bytes('nonce/a'), bytes('nonce/b', 7)];
  assert.equal(await web.hashToScalar(node.NONCE_TAG, ...parts), node.hashToScalar(node.NONCE_TAG, ...parts));
  await assert.rejects(() => web.sign(0n, 1n), RangeError);
  await assert.rejects(() => web.sign(node.L, 1n), RangeError);
  await assert.rejects(() => web.sign(5n, node.P), RangeError);
  await assert.rejects(() => web.sign(5, 1n), RangeError);
});

test('wallets, notes and public notes: both back ends agree on inputs the vectors do not hold', async () => {
  const tickers = ['GENE', 'AAAA', 'Z9Z9', '0000'];
  const amounts = [0n, 1n, 1000n, 2n ** 32n, 2n ** 64n - 1n];
  for (let i = 0; i < 12; i++) {
    const seed = bytes(`seed/${i}`, 64);
    const m = node.masterSecret(seed);
    assert.equal(toHex(await web.masterSecret(seed)), toHex(m));
    const [a, b] = [node.walletKeys(m), await web.walletKeys(m)];
    assert.deepEqual([b.ask, b.nsk, toHex(b.ivk), toHex(b.address.ivkPub), b.address.a, b.address.n], [a.ask, a.nsk, toHex(a.ivk), toHex(a.address.ivkPub), a.address.a, a.address.n]);

    const string = node.encodeAddress('sh20', a.address);
    assert.equal(web.encodeAddress('sh20', b.address), string);
    const decoded = await web.decodeAddress('sh20', string);
    assert.deepEqual([toHex(decoded.ivkPub), decoded.a, decoded.n], [toHex(a.address.ivkPub), a.address.a, a.address.n]);

    const x = bytes(`x/${i}`);
    assert.equal(await web.hs('sh20/v0/note/tweak-a', x), node.hs('sh20/v0/note/tweak-a', x));
    assert.equal(await web.hr('sh20/v0/note/rho', x), node.hr('sh20/v0/note/rho', x));
    assert.deepEqual(await web.noteSecrets(x), node.noteSecrets(x));

    // a note sealed by one back end is the same bytes from the other, and each opens the other's
    const [ticker, amount, e] = [tickers[i % tickers.length], amounts[i % amounts.length], bytes(`e/${i}`)];
    const [sealedNode, sealedWeb] = [node.seal(a.address, ticker, amount, e), await web.seal(b.address, ticker, amount, e)];
    assert.deepEqual([sealedWeb.leaf, toHex(sealedWeb.pkEph), toHex(sealedWeb.ct), sealedWeb.secrets, sealedWeb.npk], [sealedNode.leaf, toHex(sealedNode.pkEph), toHex(sealedNode.ct), sealedNode.secrets, sealedNode.npk]);
    const foundWeb = await web.scan(b.ivk, b.address, sealedNode);
    const foundNode = node.scan(a.ivk, a.address, sealedWeb);
    assert.deepEqual(foundWeb, foundNode);
    assert.deepEqual([foundWeb.ticker, foundWeb.v], [ticker, amount]);
    const stranger = node.walletKeys(bytes(`stranger/${i}`));
    assert.equal(await web.scan(stranger.ivk, stranger.address, sealedNode), null);

    for (const index of [0, 1, i + 2, 0xffffffff]) {
      assert.equal(toHex(await web.selfSecret(b.ivk, index)), toHex(node.selfSecret(a.ivk, index)));
      assert.deepEqual(await web.publicOpening(b.ivk, b.address, index), node.publicOpening(a.ivk, a.address, index));
    }

    const sk = node.spendKeys(a, sealedNode.secrets).sk;
    assert.deepEqual(await web.sign(sk, sealedNode.leaf), node.sign(sk, sealedNode.leaf));
  }
});

test('the asynchronous functions take plain Uint8Array and return it', async () => {
  const plain = (b) => Uint8Array.from(b);
  const isPlain = (b) => Object.getPrototypeOf(b) === Uint8Array.prototype;
  const m = await web.masterSecret(plain(bytes('plain/seed', 64)));
  const keys = await web.walletKeys(m);
  const out = await web.seal(keys.address, 'GENE', 7n, plain(bytes('plain/e')));
  const decoded = await web.decodeAddress('sh20', web.encodeAddress('sh20', keys.address));
  for (const b of [m, keys.ivk, keys.address.ivkPub, out.pkEph, out.ct, decoded.ivkPub, await web.selfSecret(keys.ivk, 0)]) assert.ok(isPlain(b));
  assert.deepEqual(decoded, keys.address);
  assert.equal((await web.scan(keys.ivk, keys.address, out)).v, 7n);
});

test('a platform without X25519 is an error, never a note that is silently not found', async () => {
  const s = globalThis.crypto.subtle;
  const original = s.importKey;
  const keys = await web.walletKeys(bytes('missing/m'));
  const out = await web.seal(keys.address, 'GENE', 1n, bytes('missing/e'));
  // what a browser does for an algorithm it does not know
  s.importKey = function (format, data, algorithm, ...rest) {
    if ((algorithm?.name ?? algorithm) === 'X25519') return Promise.reject(new DOMException('Unrecognized name.', 'NotSupportedError'));
    return original.call(this, format, data, algorithm, ...rest);
  };
  try {
    assert.equal(await web.available(), false);
    await assert.rejects(() => web.x25519(bytes('missing/k'), keys.address.ivkPub), { name: 'NotSupportedError' });
    await assert.rejects(() => web.scan(keys.ivk, keys.address, out), { name: 'NotSupportedError' });
    await assert.rejects(() => web.seal(keys.address, 'GENE', 1n, bytes('missing/e')), { name: 'NotSupportedError' });
    await assert.rejects(() => web.decodeAddress('sh20', web.encodeAddress('sh20', keys.address)), { name: 'NotSupportedError' });
  } finally {
    delete s.importKey;
  }
  assert.equal(s.importKey, original);
  assert.equal(await web.available(), true);
  assert.equal((await web.scan(keys.ivk, keys.address, out)).v, 1n);
});
