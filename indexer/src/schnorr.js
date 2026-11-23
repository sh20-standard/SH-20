// BIP340 Schnorr signatures over secp256k1, using only Node's built-in crypto.
// Verification is what the indexer needs (CLAIM). Signing is here for tests
// and wallets (not in constant time: the vault signs with its own vault/src/secp256k1.js). Checked
// against the BIP340 test vectors in test/primitives.test.js.

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

// Points are kept in Jacobian coordinates [X, Y, Z] (x = X/Z², y = Y/Z³) while they are added, so that a
// scalar multiplication pays one inversion, at the end, instead of one per addition; null is the point at
// infinity. secp256k1 has no point of order 2 (y = 0), which these formulas would need to handle.
const jac = (P) => (P === null ? null : [P.x, P.y, 1n]);

function jDouble(P) {
  if (P === null) return null;
  const [X, Y, Z] = P;
  const A = (X * X) % p;
  const B = (Y * Y) % p;
  const C = (B * B) % p;
  const D = md(2n * ((X + B) * (X + B) - A - C), p);
  const E = (3n * A) % p;
  const X3 = md(E * E - 2n * D, p);
  return [X3, md(E * (D - X3) - 8n * C, p), (2n * Y * Z) % p];
}

function jAdd(P1, P2) {
  if (P1 === null) return P2;
  if (P2 === null) return P1;
  const [X1, Y1, Z1] = P1;
  const [X2, Y2, Z2] = P2;
  const Z1Z1 = (Z1 * Z1) % p;
  const Z2Z2 = (Z2 * Z2) % p;
  const U1 = (X1 * Z2Z2) % p;
  const U2 = (X2 * Z1Z1) % p;
  const S1 = (Y1 * Z2 * Z2Z2) % p;
  const S2 = (Y2 * Z1 * Z1Z1) % p;
  if (U1 === U2) return S1 === S2 ? jDouble(P1) : null;
  const H = md(U2 - U1, p);
  const I = (4n * H * H) % p;
  const J = (H * I) % p;
  const r = md(2n * (S2 - S1), p);
  const V = (U1 * I) % p;
  const X3 = md(r * r - J - 2n * V, p);
  return [X3, md(r * (V - X3) - 2n * S1 * J, p), md(((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) * H, p)];
}

function affine(P) {
  if (P === null) return null;
  const zi = invP(P[2]);
  const zi2 = (zi * zi) % p;
  return { x: (P[0] * zi2) % p, y: (P[1] * zi2 * zi) % p };
}

/** k1·P1 + k2·P2 (P2 and k2 optional), with 4-bit windows and shared doublings; 0 ≤ k < 2^256. */
function mul2(P1, k1, P2 = null, k2 = 0n) {
  const table = (P) => {
    const t = [null, jac(P)];
    for (let i = 2; i < 16; i++) t.push(jAdd(t[i - 1], t[1]));
    return t;
  };
  const t1 = table(P1);
  const t2 = P2 === null ? null : table(P2);
  let R = null;
  for (let shift = 252n; shift >= 0n; shift -= 4n) {
    R = jDouble(jDouble(jDouble(jDouble(R))));
    R = jAdd(R, t1[Number((k1 >> shift) & 15n)]);
    if (t2) R = jAdd(R, t2[Number((k2 >> shift) & 15n)]);
  }
  return affine(R);
}

const mul = (P, k) => mul2(P, k);

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
  const R = mul2(G, s, Pt, n - e);
  if (R === null || (R.y & 1n) !== 0n || R.x !== r) return false;
  return true;
}
