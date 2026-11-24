// webcrypto.js, the asynchronous reference for browsers, against index.js, the synchronous one for
// Node: the same names, the same values. notes.test.js already runs docs/SPEC-NOTES.md through both
// on the vectors of the Rust model; this file covers what is left: the primitives by themselves,
// the signature, inputs the vectors do not hold, and a platform without X25519.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto, { createCipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
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
  // the five that some libraries refuse: OpenSSL asked directly with the bytes as they are, then through index.js
  for (const m of KAT.maskedFirst) {
    assert.equal(toHex(rawNode(KAT.x25519Public.k, m.u)), m.want);
    assert.equal(toHex(node.x25519(KAT.x25519Public.k, m.u)), m.want);
  }
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

// ── X25519 and the points of low order ──

const topBit = (u) => Uint8Array.from(u, (b, i) => (i === 31 ? b | 0x80 : b));
/** The seven encodings of subtle-kat.js, and the same seven with bit 255 set (which RFC 7748 ignores). */
const LOW = [...KAT.lowOrder, ...KAT.lowOrder.map(topBit)];

// OpenSSL asked directly, through neither entry point
const rawNode = (k, u) =>
  diffieHellman({
    privateKey: createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), k]), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), u]), format: 'der', type: 'spki' }),
  });
async function rawWeb(k, u) {
  const s = globalThis.crypto.subtle;
  const priv = await s.importKey('pkcs8', Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), k]), { name: 'X25519' }, false, ['deriveBits']);
  const pub = await s.importKey('raw', u, { name: 'X25519' }, true, []);
  return new Uint8Array(await s.deriveBits({ name: 'X25519', public: pub }, priv, 256));
}

// The same question put to arithmetic. On y² = x³ + 486662x² + x over p = 2^255 − 19, the x of 2P is
// (x² − 1)² / 4x(x² + 486662x + 1), and (0, 0) is the point of order 2 of the curve and of its twist:
// u has an order of 2, 4 or 8 when at most two doublings lead to x = 0.
const P25519 = 2n ** 255n - 19n;
function lowOrderByArithmetic(u) {
  const inverse = (a) => {
    let [r, b] = [1n, a % P25519];
    for (let e = P25519 - 2n; e > 0n; e >>= 1n, b = (b * b) % P25519) if (e & 1n) r = (r * b) % P25519;
    return r;
  };
  let x = (BigInt(`0x${toHex(Uint8Array.from(u).reverse())}`) & ((1n << 255n) - 1n)) % P25519;
  for (let doublings = 0; doublings < 3; doublings++) {
    if (x === 0n) return true;
    x = ((x * x - 1n) ** 2n * inverse(4n * x * (x * x + 486662n * x + 1n))) % P25519;
  }
  return false;
}

test('X25519: the points of low order are the seven listed, by arithmetic and by what OpenSSL refuses', async () => {
  const k = bytes('low/k');
  for (const u of LOW) {
    assert.equal(subtle.isLowOrder(u), true, toHex(u));
    assert.equal(lowOrderByArithmetic(u), true, toHex(u));
    assert.throws(() => rawNode(k, u), toHex(u));
    await assert.rejects(() => rawWeb(k, u), { name: 'OperationError' }, toHex(u));
  }
  const fromInt = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
  const others = [
    // next to each of the seven: the same bytes with the second one raised by one
    ...KAT.lowOrder.map((u) => Uint8Array.from(u, (b, i) => (i === 1 ? (b + 1) & 0xff : b))),
    // 2 to 20, and every value from the field size to 2^255 − 1 that is not p or p + 1 (they are 2 to 18)
    ...Array.from({ length: 19 }, (_, i) => fromInt(BigInt(i + 2))),
    ...Array.from({ length: 17 }, (_, i) => fromInt(P25519 + BigInt(i + 2))),
    // just below p − 1, and the neighbours of the two points of order 8
    fromInt(P25519 - 2n),
    ...[2, 3].flatMap((i) => [-1n, 1n].map((d) => fromInt(BigInt(`0x${toHex(Uint8Array.from(KAT.lowOrder[i]).reverse())}`) + d))),
    Buffer.alloc(32, 0xff),
    ...Array.from({ length: 200 }, (_, i) => bytes(`low/u/${i}`)),
  ];
  for (const u of others) {
    assert.equal(subtle.isLowOrder(u), false, toHex(u));
    assert.equal(lowOrderByArithmetic(u), false, toHex(u));
    const z = rawNode(k, u);
    assert.ok(z.some((b) => b !== 0), toHex(u));
    assert.equal(toHex(await rawWeb(k, u)), toHex(z), toHex(u));
    assert.equal(toHex(await web.x25519(k, u)), toHex(z), toHex(u));
  }
  assert.throws(() => subtle.isLowOrder(new Uint8Array(31)), RangeError);
  assert.throws(() => subtle.isLowOrder('00'.repeat(32)), RangeError);
});

/** Runs `fn` with `crypto.subtle[name]` replaced for X25519 alone (HKDF also goes through deriveBits). */
async function withX25519(name, replacement, fn) {
  const s = globalThis.crypto.subtle;
  const original = s[name];
  let asked = 0;
  s[name] = function (...args) {
    const algorithm = name === 'importKey' ? args[2] : args[0];
    if ((algorithm?.name ?? algorithm) !== 'X25519') return original.apply(this, args);
    asked++;
    return replacement ? replacement(...args) : original.apply(this, args);
  };
  try {
    return await fn(() => asked);
  } finally {
    delete s[name];
  }
}

test('X25519: a point of low order is decided without the platform', async () => {
  const k = bytes('low/k');
  const keys = await web.walletKeys(bytes('low/m'));
  const out = await web.seal(keys.address, 'GENE', 1n, bytes('low/e'));
  for (const name of ['importKey', 'deriveBits']) {
    await withX25519(name, null, async (asked) => {
      for (const u of LOW) assert.ok((await web.x25519(k, u)).every((b) => b === 0), toHex(u));
      for (const u of LOW) assert.equal(await web.scan(keys.ivk, keys.address, { ...out, pkEph: u }), null, toHex(u));
      for (const u of LOW) await assert.rejects(() => web.decodeAddress('sh20', web.encodeAddress('sh20', { ...keys.address, ivkPub: u })), /low-order/, toHex(u));
      assert.equal(asked(), 0, `${name} was called for a point of low order`);
      // the count does see an ordinary point
      assert.equal((await web.scan(keys.ivk, keys.address, out)).v, 1n);
      assert.ok(asked() > 0);
      // seal asks the platform for pk_eph = X25519(e, 9), then refuses the address
      for (const u of LOW) await assert.rejects(() => web.seal({ ...keys.address, ivkPub: u }, 'GENE', 1n, bytes('low/e')), /low-order/, toHex(u));
    });
  }
});

test('X25519: a failure of the platform is thrown, never read as a point of low order', async () => {
  const k = bytes('failing/k');
  const keys = await web.walletKeys(bytes('failing/m'));
  const out = await web.seal(keys.address, 'GENE', 1n, bytes('failing/e'));
  const address = web.encodeAddress('sh20', keys.address);
  const reject = (name) => () => Promise.reject(new DOMException('The operation failed for an operation-specific reason', name));
  const failures = [
    // the error a platform gives for a low-order point is also the one it gives for a failure of its own
    ['deriveBits', reject('OperationError'), { name: 'OperationError' }],
    ['deriveBits', reject('DataError'), { name: 'DataError' }],
    ['importKey', (format, ...rest) => (format === 'raw' ? reject('DataError')() : globalThis.crypto.subtle.constructor.prototype.importKey.call(globalThis.crypto.subtle, format, ...rest)), { name: 'DataError' }],
    // 32 zero bytes for a point that is not of low order: no X25519 gives that
    ['deriveBits', async () => new ArrayBuffer(32), /not of low order/],
  ];
  for (const [name, replacement, error] of failures) {
    await withX25519(name, replacement, async () => {
      await assert.rejects(() => web.x25519(k, keys.address.ivkPub), error);
      await assert.rejects(() => web.scan(keys.ivk, keys.address, out), error); // was null: "not ours"
      await assert.rejects(() => web.seal(keys.address, 'GENE', 1n, bytes('failing/e')), error); // was "IVK is a low-order point"
      await assert.rejects(() => web.decodeAddress('sh20', address), error); // the same
      // what is true of the point itself still needs no platform
      assert.equal(await web.scan(keys.ivk, keys.address, { ...out, pkEph: KAT.lowOrder[2] }), null);
      await assert.rejects(() => web.decodeAddress('sh20', web.encodeAddress('sh20', { ...keys.address, ivkPub: KAT.lowOrder[3] })), /low-order/);
    });
  }
  assert.equal((await web.scan(keys.ivk, keys.address, out)).v, 1n);
});

test('X25519 on node:crypto: the same rule, a failure of OpenSSL is thrown', () => {
  const k = bytes('failing/k');
  const keys = node.walletKeys(bytes('failing/m'));
  const out = node.seal(keys.address, 'GENE', 1n, bytes('failing/e'));
  const address = node.encodeAddress('sh20', keys.address);
  const original = nodeCrypto.diffieHellman;
  let asked = 0;
  // address.js imports diffieHellman by name: the binding follows the module once it is synchronised
  const replace = (fn) => {
    nodeCrypto.diffieHellman = fn;
    syncBuiltinESMExports();
  };
  try {
    replace((...args) => (asked++, original(...args)));
    for (const u of LOW) assert.ok(node.x25519(k, u).every((b) => b === 0), toHex(u));
    for (const u of LOW) assert.equal(node.scan(keys.ivk, keys.address, { ...out, pkEph: Buffer.from(u) }), null, toHex(u));
    for (const u of LOW) assert.throws(() => node.decodeAddress('sh20', node.encodeAddress('sh20', { ...keys.address, ivkPub: Buffer.from(u) })), /low-order/, toHex(u));
    assert.equal(asked, 0, 'OpenSSL was asked about a point of low order');
    assert.equal(node.scan(keys.ivk, keys.address, out).v, 1n);
    assert.equal(asked, 1);

    replace(() => {
      throw new Error('error:1C8000A6:Provider routines::failed during derivation');
    });
    assert.throws(() => node.x25519(k, keys.address.ivkPub), /failed during derivation/);
    assert.throws(() => node.scan(keys.ivk, keys.address, out), /failed during derivation/); // was null: "not ours"
    assert.throws(() => node.seal(keys.address, 'GENE', 1n, bytes('failing/e')), /failed during derivation/); // was "IVK is a low-order point"
    assert.throws(() => node.decodeAddress('sh20', address), /failed during derivation/);
    assert.equal(node.scan(keys.ivk, keys.address, { ...out, pkEph: Buffer.from(KAT.lowOrder[2]) }), null);

    replace(() => Buffer.alloc(32));
    assert.throws(() => node.scan(keys.ivk, keys.address, out), /not of low order/);
  } finally {
    replace(original);
  }
  assert.equal(node.scan(keys.ivk, keys.address, out).v, 1n);
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
