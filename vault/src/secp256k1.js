// secp256k1 for the secrets the vault holds (docs/AUDIT.md §8.7): the lock keys that sign offers,
// cancels and claims, the one-time keys that sign reveals, and the BIP86 / BIP341 tweak of a secret.
// No branch, no loop bound and no memory index here depends on a secret:
//
//   - field elements and scalars are 16 limbs of 16 bits in a Float64Array; every operation runs the
//     same sequence of double-precision additions, multiplications and Math.floor whatever the
//     values (sums and products stay below 2^53, so each is exact). No BigInt: its running time
//     follows the size of the numbers;
//   - points are added with the complete formulas of Renes, Costello and Batina (2016, algorithm 7,
//     a = 0): one formula for every pair of points, the point at infinity and doubling included;
//   - k·G is a fixed-window comb: 64 additions of one entry of a table of 16, read by going through
//     all 16 and keeping one with a 0/1 mask;
//   - a choice made on a secret (the key whose point has an even y) is a masked select.
//
// What JavaScript cannot promise: the engine compiles this code as it sees fit, and a garbage
// collector moves and copies memory. This is as far as the vault can go without WebAssembly. Public
// values (a tweak, a challenge's inputs, a key to check a signature against) may use BigInt
// elsewhere (taproot.js tweakKey, indexer/src/schnorr.js verify).
//
// Signatures follow BIP340 to the byte (test/secp256k1.test.js checks them against the indexer's
// reference and the BIP340 vectors), and each one is verified before it is returned, as BIP340
// advises: a fault while signing never releases a signature that could leak the key.

import './shim/buffer.js'; // indexer/src/schnorr.js verify uses Buffer
import { sha256 } from './hash.js';
import { concat, fromHex, utf8 } from './bytes.js';
import { verify } from '../../indexer/src/schnorr.js';

const RADIX = 65536;

/** 32 bytes, big-endian → 16 limbs, least significant first. */
function limbs(b) {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new Error('32 bytes expected');
  const o = new Float64Array(16);
  for (let i = 0; i < 16; i++) o[i] = b[31 - 2 * i] + 256 * b[30 - 2 * i];
  return o;
}

/** Canonical limbs → 32 bytes, big-endian. */
function bytes(a) {
  const o = new Uint8Array(32);
  for (let i = 0; i < 16; i++) {
    o[31 - 2 * i] = a[i] & 255;
    o[30 - 2 * i] = (a[i] >>> 8) & 255;
  }
  return o;
}

/** Brings every limb into [0, 2^16) from the bottom up; returns what carries out of the top. */
function carryOut(a) {
  let c = 0;
  for (let i = 0; i < a.length; i++) {
    const v = a[i] + c;
    c = Math.floor(v / RADIX);
    a[i] = v - c * RADIX;
  }
  return c;
}

/** bit ? a : b, for bit 0 or 1. */
function select(bit, a, b) {
  const o = new Float64Array(a.length);
  for (let i = 0; i < a.length; i++) o[i] = b[i] + bit * (a[i] - b[i]);
  return o;
}

/** a − m when a ≥ m, else a (canonical a and m of 16 limbs). */
function reduceOnce(a, m) {
  const d = new Float64Array(16);
  let borrow = 0;
  for (let i = 0; i < 16; i++) {
    const v = a[i] - m[i] + borrow;
    borrow = Math.floor(v / RADIX); // 0 or −1
    d[i] = v - borrow * RADIX;
  }
  return select(-borrow, a, d);
}

/** 1 when a < m, else 0 (canonical a and m). */
function below(a, m) {
  let borrow = 0;
  for (let i = 0; i < 16; i++) borrow = Math.floor((a[i] - m[i] + borrow) / RADIX);
  return -borrow;
}

/** 1 when every limb of a is 0, else 0 (canonical a). */
function zero(a) {
  let s = 0;
  for (let i = 0; i < 16; i++) s += a[i];
  return ((s | 0) - 1) >>> 31; // s < 2^21
}

const hex = (h) => limbs(fromHex(h));

// ---- the field, p = 2^256 − 2^32 − 977 ----------------------------------------------------------

const P = hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const P_MINUS_2 = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d'; // public exponent

/** Folds what is above 2^256 back (2^256 ≡ 2^32 + 977 mod p), three times: limbs end below 2^17. */
function fnorm(a) {
  for (let k = 0; k < 3; k++) {
    const c = carryOut(a);
    a[0] += 977 * c;
    a[2] += c;
  }
  return a;
}

function fadd(a, b) {
  const o = new Float64Array(16);
  for (let i = 0; i < 16; i++) o[i] = a[i] + b[i];
  return fnorm(o);
}

function fsub(a, b) {
  const o = new Float64Array(16);
  for (let i = 0; i < 16; i++) o[i] = a[i] - b[i];
  return fnorm(o);
}

function fmul(a, b) {
  const t = new Float64Array(31);
  for (let i = 0; i < 16; i++) for (let j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
  for (let i = 14; i >= 0; i--) {
    // t[16 + i]·2^(256 + 16i) ≡ t[16 + i]·(977 + 2^32)·2^(16i)
    t[i] += 977 * t[16 + i];
    t[i + 2] += t[16 + i];
  }
  return fnorm(t.slice(0, 16));
}

function fsmall(a, k) {
  const o = new Float64Array(16);
  for (let i = 0; i < 16; i++) o[i] = a[i] * k;
  return fnorm(o);
}

/** a^(p − 2) = 1/a: the exponent is public, so its bits may steer the loop. */
function finv(a) {
  let r = FE_ONE;
  for (const digit of P_MINUS_2) {
    const d = parseInt(digit, 16);
    for (let bit = 3; bit >= 0; bit--) {
      r = fmul(r, r);
      if ((d >> bit) & 1) r = fmul(r, a);
    }
  }
  return r;
}

/** The canonical representative in [0, p). */
function freeze(a) {
  const t = fnorm(fnorm(Float64Array.from(a)));
  const c = carryOut(t); // 0 or 1; when 1, what is left is below 2^34
  t[0] += 977 * c;
  t[2] += c;
  carryOut(t);
  return reduceOnce(t, P);
}

const FE_ZERO = new Float64Array(16);
const FE_ONE = Float64Array.from({ length: 16 }, (_, i) => (i === 0 ? 1 : 0));

// ---- points, projective (X : Y : Z), y² = x³ + 7 -------------------------------------------------

const B3 = 21; // 3·b
const INFINITY = { X: FE_ZERO, Y: FE_ONE, Z: FE_ZERO };
const G = {
  X: hex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Y: hex('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
  Z: FE_ONE,
};

/** P1 + P2 for any two points (Renes, Costello, Batina 2016, algorithm 7). */
function add(p1, p2) {
  const { X: X1, Y: Y1, Z: Z1 } = p1;
  const { X: X2, Y: Y2, Z: Z2 } = p2;
  let t0 = fmul(X1, X2);
  let t1 = fmul(Y1, Y2);
  let t2 = fmul(Z1, Z2);
  let t3 = fmul(fadd(X1, Y1), fadd(X2, Y2));
  let t4 = fadd(t0, t1);
  t3 = fsub(t3, t4);
  t4 = fmul(fadd(Y1, Z1), fadd(Y2, Z2));
  let X3 = fadd(t1, t2);
  t4 = fsub(t4, X3);
  X3 = fmul(fadd(X1, Z1), fadd(X2, Z2));
  let Y3 = fadd(t0, t2);
  Y3 = fsub(X3, Y3);
  X3 = fadd(t0, t0);
  t0 = fadd(X3, t0);
  t2 = fsmall(t2, B3);
  let Z3 = fadd(t1, t2);
  t1 = fsub(t1, t2);
  Y3 = fsmall(Y3, B3);
  X3 = fmul(t4, Y3);
  t2 = fmul(t3, t1);
  X3 = fsub(t2, X3);
  Y3 = fmul(Y3, t0);
  t1 = fmul(t1, Z3);
  Y3 = fadd(t1, Y3);
  t0 = fmul(t0, t3);
  Z3 = fmul(Z3, t4);
  Z3 = fadd(Z3, t0);
  return { X: X3, Y: Y3, Z: Z3 };
}

let TABLE = null; // TABLE[w][j] = j·16^w·G, built once (public: it depends on G alone)

function table() {
  if (TABLE) return TABLE;
  const rows = [];
  let base = G;
  for (let w = 0; w < 64; w++) {
    const row = [INFINITY, base];
    for (let j = 2; j < 16; j++) row.push(add(row[j - 1], base));
    rows.push(row);
    base = add(row[15], base);
  }
  return (TABLE = rows);
}

/** row[j] for a secret j, read by going through every entry. */
function lookup(row, j) {
  const X = new Float64Array(16);
  const Y = new Float64Array(16);
  const Z = new Float64Array(16);
  for (let k = 0; k < 16; k++) {
    const m = ((k ^ j) - 1) >>> 31; // 1 when k = j
    const e = row[k];
    for (let i = 0; i < 16; i++) {
      X[i] += m * e.X[i];
      Y[i] += m * e.Y[i];
      Z[i] += m * e.Z[i];
    }
  }
  return { X, Y, Z };
}

/** k·G for a canonical scalar k: x (32 bytes) and the parity of y (0 or 1). */
function mulG(k) {
  const rows = table();
  let acc = INFINITY;
  for (let w = 0; w < 64; w++) acc = add(acc, lookup(rows[w], (k[w >> 2] >>> (4 * (w & 3))) & 15));
  const zi = finv(acc.Z);
  const y = freeze(fmul(acc.Y, zi));
  return { x: bytes(freeze(fmul(acc.X, zi))), odd: y[0] & 1 };
}

// ---- scalars, n = 2^256 − C ------------------------------------------------------------------------

const N = hex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const N_MINUS_1 = hex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140');
const C = hex('000000000000000000000000000000014551231950b75fc4402da1732fc9bebf'); // 2^256 − n, below 2^129

/** t mod n, for t of 32 limbs below 2^512: four folds of 2^256 ≡ C, then one subtraction. */
function sreduce(t) {
  let r = t;
  for (let round = 0; round < 4; round++) {
    const s = new Float64Array(32);
    for (let i = 0; i < 16; i++) s[i] = r[i];
    for (let i = 0; i < 16; i++) for (let j = 0; j < 16; j++) s[i + j] += r[16 + i] * C[j];
    carryOut(s);
    r = s; // below 2^386, 2^260, 2^256 + 2^133, then 2^256
  }
  return reduceOnce(r.subarray(0, 16), N);
}

function sadd(a, b) {
  const t = new Float64Array(32);
  for (let i = 0; i < 16; i++) t[i] = a[i] + b[i];
  carryOut(t);
  return sreduce(t);
}

function smul(a, b) {
  const t = new Float64Array(32);
  for (let i = 0; i < 16; i++) for (let j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
  carryOut(t);
  return sreduce(t);
}

/** n − a, for a in [1, n). */
function sneg(a) {
  const o = new Float64Array(16);
  for (let i = 0; i < 16; i++) o[i] = N[i] - a[i];
  carryOut(o);
  return o;
}

/** The scalar of a secret key: 32 bytes in [1, n), else an error (which says only that). */
function secretScalar(secret) {
  const d = limbs(secret);
  if (!(below(d, N) & (1 - zero(d)))) throw new Error('bad secret key');
  return d;
}

const tagged = (tag, ...parts) => {
  const t = sha256(utf8(tag));
  return sha256(concat(t, t, ...parts));
};

// ---- what the vault calls -------------------------------------------------------------------------

/** True when `secret` (32 bytes) is a secret key, in [1, n). */
export function isSecretKey(secret) {
  const d = limbs(secret);
  return (below(d, N) & (1 - zero(d))) === 1;
}

/** (int(b) mod (n − 1)) + 1, a key in [1, n) from 32 bytes (the lock keys of keys.js). */
export function keyFromBytes(b) {
  const t = new Float64Array(17);
  t.set(reduceOnce(limbs(b), N_MINUS_1)); // b < 2^256 < 2(n − 1)
  t[0] += 1;
  carryOut(t); // below n: nothing carries out
  return bytes(t);
}

/** The x-only public key of `secret` and the parity of its y: { x, odd }. */
export function pointOf(secret) {
  return mulG(secretScalar(secret));
}

/** The x-only public key of `secret` (BIP340). */
export const bip340PublicKey = (secret) => pointOf(secret).x;

/**
 * The secret that signs for a taproot output key (BIP341): `secret`, negated when its point has
 * an odd y, plus `tweak` (32 bytes, public, below n), mod n.
 */
export function tweakSecret(secret, tweak) {
  const d = secretScalar(secret);
  const t = limbs(tweak);
  if (!below(t, N)) throw new Error('tweak out of range');
  const even = select(mulG(d).odd, sneg(d), d);
  const s = sadd(even, t);
  if (zero(s)) throw new Error('the tweaked key is zero'); // probability 2^-256
  return bytes(s);
}

/** A BIP340 signature (64 bytes) of `msg` by `secret`, with 32 bytes of fresh auxiliary randomness. */
export function bip340Sign(secret, msg, aux = crypto.getRandomValues(new Uint8Array(32))) {
  if (!(aux instanceof Uint8Array) || aux.length !== 32) throw new Error('aux must be 32 bytes');
  const m = Uint8Array.from(msg);
  const d0 = secretScalar(secret);
  const P = mulG(d0);
  const d = select(P.odd, sneg(d0), d0);
  const masked = tagged('BIP0340/aux', aux);
  const db = bytes(d);
  for (let i = 0; i < 32; i++) masked[i] ^= db[i];
  const k0 = reduceOnce(limbs(tagged('BIP0340/nonce', masked, P.x, m)), N);
  if (zero(k0)) throw new Error('bad nonce'); // probability 2^-256
  const R = mulG(k0);
  const k = select(R.odd, sneg(k0), k0);
  const e = reduceOnce(limbs(tagged('BIP0340/challenge', R.x, P.x, m)), N);
  const sig = concat(R.x, bytes(sadd(k, smul(e, d))));
  if (!verify(P.x, m, sig)) throw new Error('the signature did not verify: not released');
  return sig;
}

/** For test/secp256k1.test.js only: the field and scalar arithmetic, on 32-byte values. */
export const arithmetic = {
  fmul: (a, b) => bytes(freeze(fmul(limbs(a), limbs(b)))),
  fadd: (a, b) => bytes(freeze(fadd(limbs(a), limbs(b)))),
  fsub: (a, b) => bytes(freeze(fsub(limbs(a), limbs(b)))),
  finv: (a) => bytes(freeze(finv(limbs(a)))),
  freeze: (a) => bytes(freeze(limbs(a))),
  smul: (a, b) => bytes(smul(limbs(a), limbs(b))),
  sadd: (a, b) => bytes(sadd(limbs(a), limbs(b))),
};
