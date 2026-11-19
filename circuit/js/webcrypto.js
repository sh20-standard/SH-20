// The wallet reference for a browser: the names of index.js, with everything that touches a secret
// through a hash, a key agreement or a cipher made asynchronous and run by the platform's WebCrypto
// (subtle.js): X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA512, SHA-256.
//
//   import { available, walletKeys, masterSecret, decodeAddress, seal, scan, spendKeys, sign } from 'circuit/js/webcrypto.js';
//   if (!(await available())) throw new Error('this browser has no X25519');
//   const keys = await walletKeys(await masterSecret(bip39Seed));   // { ask, nsk, ivk, address }
//   const to = await decodeAddress('sh20', string);
//   const out = await seal(to, 'GENE', 700n, e);                     // { leaf, pkEph, ct } and { secrets, npk }
//   const note = await scan(keys.ivk, keys.address, out);            // null unless it is ours
//   const { sk, nk } = spendKeys(keys, note.secrets);
//   const { r8, s } = await sign(sk, bodyHash(body));
//
// Asynchronous here, synchronous in index.js: masterSecret, walletKeys, hs, hr, noteSecrets, seal,
// scan, selfSecret, publicOpening, x25519, x25519Public, decodeAddress, hashToScalar, sign. They
// return the same values, with Uint8Array where index.js returns a Buffer; test/ runs both against
// the same vectors (vectors.json, written by the Rust model). The rest is the same code as index.js.
//
// What stays in JavaScript: BabyJubJub and Poseidon, which no browser offers. They are BigInt
// arithmetic and do not run in constant time.
//
// In a browser the modules below still import `node:crypto` by name: the indexer's constants hash
// their public tags with createHash('sha256') at load, and address.js and seal.js import the names
// their synchronous functions call. Map `node:crypto` to a stand-in that implements createHash and
// exports the other names; nothing on the paths of this file calls them.

import { FR } from '../../indexer/src/constants.js';
import { noteLeaf, tickerT } from '../../indexer/src/notes.js';
import { parseAddress } from './address.js';
import { L, mulBase8 } from './babyjub.js';
import { NONCE_TAG, signInputs, signWithNonce } from './eddsa.js';
import { TAG, TICKER, noteNpk } from './seal.js';
import { aes256GcmOpen, aes256GcmSeal, concat, hkdfSha256, hmacSha512, sha256, x25519 as dh, x25519Public as dhPublic } from './subtle.js';

export { P, poseidon } from '../../indexer/src/poseidon.js';
export { noteLeaf, tickerT } from '../../indexer/src/notes.js';
export { A, D, L, BASE8, IDENTITY, add, mul, mulBase8, onCurve } from './babyjub.js';
export { bodyHash, noteKeys, npkOf, nullifier } from './notes.js';
export { NONCE_TAG, verify } from './eddsa.js';
export { ADDRESS_BYTES, ADDRESS_VERSION, HRP, bech32mDecode, bech32mEncode, encodeAddress, isKeyPoint, packPoint, unpackPoint } from './address.js';
export { noteNpk, spendKeys } from './seal.js';
export { available } from './subtle.js';

const utf8 = (s) => new TextEncoder().encode(s);
const bytes32 = (name, b) => {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new RangeError(`${name} must be 32 bytes`);
  return b;
};
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const le32 = (x) => Uint8Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 0xffn));
const isZero = (b) => b.every((byte) => byte === 0);

/** X25519(k, u), all zeros when u is a low-order point; and X25519(k, 9). See subtle.js. */
export const x25519 = dh;
export const x25519Public = dhPublic;

/** int_be(SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01)). */
async function wide(tag, x) {
  const [lo, hi] = await Promise.all([sha256(utf8(tag), x, Uint8Array.of(0)), sha256(utf8(tag), x, Uint8Array.of(1))]);
  return BigInt(`0x${hex(lo)}${hex(hi)}`);
}
/** hs(tag, x): a BabyJubJub scalar, or null for 0 (which a wallet treats as invalid). */
export const hs = async (tag, x) => (await wide(tag, bytes32('x', x))) % L || null;
/** hr(tag, x): a field element. */
export const hr = async (tag, x) => (await wide(tag, bytes32('x', x))) % FR;

/** 512 bits of SHA-256 output over tag ‖ parts, reduced modulo l (never 0). */
export async function hashToScalar(tag, ...parts) {
  const x = (await wide(tag, concat(...parts))) % L;
  if (x === 0n) throw new Error('zero scalar');
  return x;
}

// ── keys (§1) ──

/** m = the first 32 bytes of HMAC-SHA512(key = "sh20/v0/seed", data = the 64-byte BIP39 seed). */
export async function masterSecret(bip39Seed) {
  return (await hmacSha512(utf8(TAG.seed), bip39Seed)).slice(0, 32);
}

/** { ask, nsk, ivk, address: { ivkPub, a, n } } from the master secret. */
export async function walletKeys(m) {
  bytes32('m', m);
  const [ask, nsk, ivk] = await Promise.all([hs(TAG.ask, m), hs(TAG.nsk, m), sha256(utf8(TAG.ivk), m)]);
  if (ask === null || nsk === null) throw new Error('unusable master secret');
  return { ask, nsk, ivk, address: { ivkPub: await x25519Public(ivk), a: mulBase8(ask), n: mulBase8(nsk) } };
}

// ── addresses (§2) ──

/**
 * Decodes and validates an address for the network `hrp`. Throws unless: version 0, 97 bytes, A and
 * N key points, and an IVK that is not a low-order point (for which every shared secret is zero).
 */
export async function decodeAddress(hrp, s) {
  const { ivkPub, a, n } = parseAddress(hrp, s);
  if (isZero(await x25519(new Uint8Array(32).fill(0x42), ivkPub))) throw new Error('address: IVK is a low-order point');
  return { ivkPub: Uint8Array.from(ivkPub), a, n };
}

// ── notes (§3, §4) ──

/** { tauA, tauN, rho } from a note's 32-byte secret, or null if a tweak is 0. */
export async function noteSecrets(s) {
  const [tauA, tauN, rho] = await Promise.all([hs(TAG.tweakA, s), hs(TAG.tweakN, s), hr(TAG.rho, s)]);
  return tauA === null || tauN === null ? null : { tauA, tauN, rho };
}

const sharedSecret = (z, pkEph, ivkPub) => hkdfSha256(utf8(TAG.note), z, concat(pkEph, ivkPub), 32);
async function aeadKey(s, leafBytes) {
  const okm = await hkdfSha256(utf8(TAG.aead), s, leafBytes, 44);
  return [okm.subarray(0, 32), okm.subarray(32)];
}

/**
 * Seals `v` units of `ticker` to `address` with the fresh X25519 private key `e` (§3).
 * Returns the output { leaf, pkEph, ct } and what the sender needs for its proof: { secrets, npk }.
 */
export async function seal(address, ticker, v, e) {
  if (!TICKER.test(ticker)) throw new RangeError('not a ticker');
  if (typeof v !== 'bigint' || v < 0n || v >= 1n << 64n) throw new RangeError('v must be a BigInt below 2^64');
  const ivkPub = bytes32('IVK', address.ivkPub);
  const pkEph = await x25519Public(e);
  const z = await x25519(e, ivkPub);
  if (isZero(z)) throw new Error('address: IVK is a low-order point');
  const s = await sharedSecret(z, pkEph, ivkPub);
  const secrets = await noteSecrets(s);
  if (!secrets) throw new Error('zero tweak: draw another e');
  const npk = noteNpk(address, secrets);
  const leaf = noteLeaf(tickerT(ticker), v, npk, secrets.rho);
  const leafBytes = le32(leaf);
  const [key, nonce] = await aeadKey(s, leafBytes);
  const plaintext = new Uint8Array(12);
  new DataView(plaintext.buffer).setBigUint64(0, v, true);
  plaintext.set(Uint8Array.from(ticker, (c) => c.charCodeAt(0)), 8);
  const ct = await aes256GcmSeal(key, nonce, leafBytes, plaintext);
  return { leaf, pkEph, ct, secrets, npk };
}

/**
 * Tries to open an output { leaf, pkEph, ct } with an incoming viewing key: `ivk` and the wallet's
 * own `address` (§4). Returns { ticker, v, secrets, npk }, or null unless the tag verifies, the
 * plaintext names a ticker, and the leaf is the one this wallet computes for it.
 */
export async function scan(ivk, address, { leaf, pkEph, ct }) {
  if (!(ct instanceof Uint8Array) || ct.length !== 28 || !(pkEph instanceof Uint8Array) || pkEph.length !== 32) return null;
  if (typeof leaf !== 'bigint' || leaf < 0n || leaf >= FR) return null;
  const z = await x25519(ivk, pkEph);
  if (isZero(z)) return null;
  const s = await sharedSecret(z, pkEph, bytes32('IVK', address.ivkPub));
  const leafBytes = le32(leaf);
  const [key, nonce] = await aeadKey(s, leafBytes);
  const plaintext = await aes256GcmOpen(key, nonce, leafBytes, ct);
  if (plaintext === null) return null; // not for this wallet
  const v = new DataView(plaintext.buffer, plaintext.byteOffset, 12).getBigUint64(0, true);
  const ticker = String.fromCharCode(...plaintext.subarray(8, 12));
  if (!TICKER.test(ticker)) return null;
  const secrets = await noteSecrets(s);
  if (!secrets) return null;
  const npk = noteNpk(address, secrets);
  // the plaintext alone proves nothing: the note is ours only if it hashes to the published leaf
  return noteLeaf(tickerT(ticker), v, npk, secrets.rho) === leaf ? { ticker, v, secrets, npk } : null;
}

// ── public notes (§5) ──

/** The secret of the wallet's i-th public note: HKDF(salt "sh20/v0/self", ikm = ivk, info = u32le(i)). */
export async function selfSecret(ivk, i) {
  if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) throw new RangeError('i must be a u32');
  const info = new Uint8Array(4);
  new DataView(info.buffer).setUint32(0, i, true);
  return hkdfSha256(utf8(TAG.self), bytes32('ivk', ivk), info, 32);
}

/**
 * The opening `npk` a wallet publishes for its i-th public note, with the note's secrets.
 * A public note has rho = 0 (docs/SPEC-WIRE.md §2): { npk, rho: 0n, secrets: { tauA, tauN, rho: 0n } }.
 */
export async function publicOpening(ivk, address, i) {
  const s = await selfSecret(ivk, i);
  const [tauA, tauN] = await Promise.all([hs(TAG.tweakA, s), hs(TAG.tweakN, s)]);
  if (tauA === null || tauN === null) return null;
  const secrets = { tauA, tauN, rho: 0n };
  return { npk: noteNpk(address, secrets), rho: 0n, secrets };
}

// ── the signature of a spend ──

/** Signs the field element `m` (a bodyHash) with the note's spend scalar `sk` in [1, l). */
export async function sign(sk, m) {
  return signWithNonce(sk, m, await hashToScalar(NONCE_TAG, ...signInputs(sk, m)));
}
