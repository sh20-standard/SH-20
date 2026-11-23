// The BIP340 code of src/schnorr.js as it was until 2026-11-23: affine coordinates, one inversion per
// point operation, about 100 ms a verification. Kept only as the reference test/schnorr.test.js checks the
// faster code against, input for input. Not imported by anything outside the tests.

import { createHash } from 'node:crypto';

const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

const md = (a, m) => ((a % m) + m) % m;

function powMod(b, e, m) {
  let r = 1n;
  b = md(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const invP = (a) => powMod(a, p - 2n, p);

function add(P1, P2) {
  if (P1 === null) return P2;
  if (P2 === null) return P1;
  if (P1.x === P2.x && md(P1.y + P2.y, p) === 0n) return null;
  let lam;
  if (P1.x === P2.x && P1.y === P2.y) lam = md(3n * P1.x * P1.x * invP(2n * P1.y), p);
  else lam = md((P2.y - P1.y) * invP(md(P2.x - P1.x, p)), p);
  const x = md(lam * lam - P1.x - P2.x, p);
  return { x, y: md(lam * (P1.x - x) - P1.y, p) };
}

function mul(P0, k) {
  let R = null;
  let A = P0;
  while (k > 0n) {
    if (k & 1n) R = add(R, A);
    A = add(A, A);
    k >>= 1n;
  }
  return R;
}

const toInt = (buf) => BigInt('0x' + (Buffer.from(buf).toString('hex') || '0'));
const toBytes32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');

export function taggedHash(tag, ...parts) {
  const th = createHash('sha256').update(tag, 'utf8').digest();
  const h = createHash('sha256').update(th).update(th);
  for (const part of parts) h.update(part);
  return h.digest();
}

function liftX(xBuf) {
  const x = toInt(xBuf);
  if (x >= p) return null;
  const c = md(x * x * x + 7n, p);
  const y = powMod(c, (p + 1n) / 4n, p);
  if (powMod(y, 2n, p) !== c) return null;
  return { x, y: (y & 1n) === 0n ? y : p - y };
}

/** x-only public key (32 bytes) for a 32-byte secret key. */
export function publicKey(secret) {
  const d = toInt(secret);
  if (d <= 0n || d >= n) throw new Error('bad secret key');
  return toBytes32(mul(G, d).x);
}

/** BIP340 signature (64 bytes). `aux` is 32 bytes of auxiliary randomness. */
export function sign(secret, msg, aux = Buffer.alloc(32)) {
  const d0 = toInt(secret);
  if (d0 <= 0n || d0 >= n) throw new Error('bad secret key');
  const Pt = mul(G, d0);
  const d = (Pt.y & 1n) === 0n ? d0 : n - d0;
  const t = toBytes32(d ^ toInt(taggedHash('BIP0340/aux', aux)));
  const px = toBytes32(Pt.x);
  const k0 = md(toInt(taggedHash('BIP0340/nonce', t, px, msg)), n);
  if (k0 === 0n) throw new Error('bad nonce');
  const R = mul(G, k0);
  const k = (R.y & 1n) === 0n ? k0 : n - k0;
  const rx = toBytes32(R.x);
  const e = md(toInt(taggedHash('BIP0340/challenge', rx, px, msg)), n);
  return Buffer.concat([rx, toBytes32(md(k + e * d, n))]);
}

/** BIP340 verification. pubkey: 32-byte x-only key; sig: 64 bytes. */
export function verify(pubkey, msg, sig) {
  if (pubkey.length !== 32 || sig.length !== 64) return false;
  const Pt = liftX(pubkey);
  if (Pt === null) return false;
  const r = toInt(sig.subarray(0, 32));
  const s = toInt(sig.subarray(32, 64));
  if (r >= p || s >= n) return false;
  const e = md(toInt(taggedHash('BIP0340/challenge', sig.subarray(0, 32), pubkey, msg)), n);
  const R = add(mul(G, s), mul(Pt, n - e));
  if (R === null || (R.y & 1n) !== 0n || R.x !== r) return false;
  return true;
}
