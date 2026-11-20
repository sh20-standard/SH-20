// The address of a wallet (docs/SPEC-NOTES.md §2):
//   bech32m(hrp, 0x00 ‖ IVK (32) ‖ pack(A) (32) ‖ pack(N) (32))
// and the checks a payer makes before sending to one. Mirrors circuit/src/notes.rs.

import { createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';
import { P } from '../../indexer/src/poseidon.js';
import { A, D, IDENTITY, L, equal, mul, onCurve } from './babyjub.js';
import { isLowOrder } from './subtle.js';

export const ADDRESS_VERSION = 0;
export const ADDRESS_BYTES = 97;
export const HRP = Object.freeze({ mainnet: 'sh20', test: 'tsh20' });

// ── X25519 (RFC 7748), from Node ──

const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const privateKey = (k) => createPrivateKey({ key: Buffer.concat([PKCS8, k]), format: 'der', type: 'pkcs8' });
const publicKey = (u) => createPublicKey({ key: Buffer.concat([SPKI, u]), format: 'der', type: 'spki' });
const key32 = (name, b) => {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new RangeError(`${name} must be 32 bytes`);
  return Buffer.from(b);
};

/** X25519(k, 9): the public key of the private key k. */
export function x25519Public(k) {
  return Buffer.from(createPublicKey(privateKey(key32('private key', k))).export({ format: 'der', type: 'spki' }).subarray(-32));
}

/**
 * X25519(k, u). All zeros when u is a point of low order, and only then: decided from u (subtle.js),
 * not from an error of OpenSSL, which refuses such a point with the error of any failed derivation.
 * Every other failure is thrown, as is an all-zero answer for any other point.
 */
export function x25519(k, u) {
  const [priv, pub] = [key32('private key', k), key32('public key', u)];
  if (isLowOrder(pub)) return Buffer.alloc(32);
  const z = diffieHellman({ privateKey: privateKey(priv), publicKey: publicKey(pub) });
  if (z.every((b) => b === 0)) throw new Error('X25519: the platform gave no secret for a point that is not of low order');
  return z;
}

// ── points ──

const mod = (x) => ((x % P) + P) % P;
function pow(base, e) {
  let r = 1n;
  let b = mod(base);
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
}

/** A square root modulo the field (Tonelli–Shanks), or null. */
function sqrt(n) {
  n = mod(n);
  if (n === 0n) return 0n;
  if (pow(n, (P - 1n) / 2n) !== 1n) return null;
  let q = P - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s++;
  }
  let z = 2n;
  while (pow(z, (P - 1n) / 2n) !== P - 1n) z++;
  let [m, c, t, r] = [s, pow(z, q), pow(n, q), pow(n, (q + 1n) / 2n)];
  while (t !== 1n) {
    let i = 0n;
    for (let u = t; u !== 1n; u = (u * u) % P) i++;
    const b = pow(c, 1n << (m - i - 1n));
    [m, c, t, r] = [i, (b * b) % P, (t * b * b) % P, (r * b) % P];
  }
  return r;
}

const le32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
const fromLe = (b) => BigInt(`0x${Buffer.from(b).reverse().toString('hex')}`);

/** circomlib's packPoint: y little-endian, the top bit set when x > (r − 1) / 2. */
export function packPoint(p) {
  const b = le32(p[1]);
  if (p[0] > (P - 1n) / 2n) b[31] |= 0x80;
  return b;
}

/** The strict inverse of packPoint, or null: y below r, x from the curve equation, one encoding of x = 0. */
export function unpackPoint(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return null;
  const b = Buffer.from(bytes);
  const sign = (b[31] & 0x80) !== 0;
  b[31] &= 0x7f;
  const y = fromLe(b);
  if (y >= P) return null;
  // a·x² + y² = 1 + d·x²·y²  ⇒  x² = (1 − y²) / (a − d·y²)
  const y2 = (y * y) % P;
  const den = mod(A - D * y2);
  if (den === 0n) return null;
  let x = sqrt((1n - y2) * pow(den, P - 2n));
  if (x === null) return null;
  if (x > (P - 1n) / 2n !== sign) x = mod(-x);
  if (x === 0n && sign) return null;
  return [x, y];
}

/** A point a wallet accepts as a key: on the curve, in the subgroup of order l, not the identity. */
export function isKeyPoint(p) {
  return onCurve(p) && !equal(p, IDENTITY) && equal(mul(p, L), IDENTITY);
}

// ── bech32m (BIP-350), without the 90-character limit ──

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M = 0x2bc830a3;
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}
const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));

export function bech32mEncode(hrp, data) {
  const fives = [];
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      fives.push((acc >>> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) fives.push((acc << (5 - bits)) & 31);
  const pm = (polymod([...hrpExpand(hrp), ...fives, 0, 0, 0, 0, 0, 0]) ^ BECH32M) >>> 0;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...fives, ...checksum].map((v) => CHARSET[v]).join('')}`;
}

/** Strict: one case throughout, a valid bech32m checksum, fewer than 5 padding bits, all zero. */
export function bech32mDecode(s) {
  if (typeof s !== 'string' || [...s].some((c) => c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126)) throw new Error('address: invalid character');
  const lower = s.toLowerCase();
  if (s !== lower && s !== s.toUpperCase()) throw new Error('address: mixed case');
  const at = lower.lastIndexOf('1');
  if (at < 1 || lower.length - at - 1 < 6) throw new Error('address: no separator or too short');
  const hrp = lower.slice(0, at);
  const fives = [...lower.slice(at + 1)].map((c) => CHARSET.indexOf(c));
  if (fives.includes(-1)) throw new Error('address: invalid character');
  if (polymod([...hrpExpand(hrp), ...fives]) !== BECH32M) throw new Error('address: wrong checksum');
  const data = [];
  let acc = 0;
  let bits = 0;
  for (const v of fives.slice(0, -6)) {
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      data.push((acc >>> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits >= 5 || acc !== 0) throw new Error('address: invalid padding');
  return { hrp, data: Buffer.from(data) };
}

// ── address ──

/** address = bech32m(hrp, 0x00 ‖ IVK ‖ pack(A) ‖ pack(N)); `address` is { ivkPub, a, n }. */
export function encodeAddress(hrp, { ivkPub, a, n }) {
  return bech32mEncode(hrp, Buffer.concat([Buffer.from([ADDRESS_VERSION]), key32('IVK', ivkPub), packPoint(a), packPoint(n)]));
}

/**
 * Decodes an address for the network `hrp` and makes every check that needs no key agreement:
 * version 0, 97 bytes, A and N key points. Not for payers: `decodeAddress` adds the check on IVK.
 * (Apart so that the WebCrypto version, webcrypto.js, runs the same code up to that check.)
 */
export function parseAddress(hrp, s) {
  const decoded = bech32mDecode(s);
  if (decoded.hrp !== hrp) throw new Error('address: for another network');
  const d = decoded.data;
  if (d.length !== ADDRESS_BYTES || d[0] !== ADDRESS_VERSION) throw new Error('address: unknown version or length');
  const ivkPub = Buffer.from(d.subarray(1, 33));
  const a = unpackPoint(d.subarray(33, 65));
  const n = unpackPoint(d.subarray(65, 97));
  if (!a || !isKeyPoint(a)) throw new Error('address: A is not a key');
  if (!n || !isKeyPoint(n)) throw new Error('address: N is not a key');
  return { ivkPub, a, n };
}

/**
 * Decodes and validates an address for the network `hrp`. Throws unless: version 0, 97 bytes, A and
 * N key points, and an IVK that is not a low-order point (for which every shared secret is zero).
 */
export function decodeAddress(hrp, s) {
  const address = parseAddress(hrp, s);
  if (x25519(Buffer.alloc(32, 0x42), address.ivkPub).every((byte) => byte === 0)) throw new Error('address: IVK is a low-order point');
  return address;
}
