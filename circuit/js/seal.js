// Wallet keys, sealing an output to an address, scanning with the leaf check, and public notes
// (docs/SPEC-NOTES.md §1, §3, §4, §5). Mirrors circuit/src/notes.rs; X25519, HKDF and AES-GCM are
// Node's own, so this file and the Rust model share no cryptographic code.

import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync } from 'node:crypto';
import { FR } from '../../indexer/src/constants.js';
import { noteLeaf, tickerT } from '../../indexer/src/notes.js';
import { x25519, x25519Public } from './address.js';
import { L, add, mulBase8 } from './babyjub.js';
import { noteKeys, npkOf } from './notes.js';

/** The domain-separation tags of docs/SPEC-NOTES.md (shared with webcrypto.js). */
export const TAG = Object.freeze({
  seed: 'sh20/v0/seed',
  ask: 'sh20/v0/key/ask',
  nsk: 'sh20/v0/key/nsk',
  ivk: 'sh20/v0/key/ivk',
  note: 'sh20/v0/note',
  tweakA: 'sh20/v0/note/tweak-a',
  tweakN: 'sh20/v0/note/tweak-n',
  rho: 'sh20/v0/note/rho',
  aead: 'sh20/v0/note/aead',
  self: 'sh20/v0/self',
});
export const TICKER = /^[A-Z0-9]{4}$/;

const bytes32 = (name, b) => {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new RangeError(`${name} must be 32 bytes`);
  return Buffer.from(b);
};
const le32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
const isZero = (b) => b.every((byte) => byte === 0);

/** int_be(SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01)), x of 32 bytes. */
function wide(tag, x) {
  const half = (last) => createHash('sha256').update(tag, 'utf8').update(x).update(Buffer.from([last])).digest('hex');
  return BigInt(`0x${half(0)}${half(1)}`);
}
/** hs(tag, x): a BabyJubJub scalar, or null for 0 (which a wallet treats as invalid). */
export const hs = (tag, x) => wide(tag, bytes32('x', x)) % L || null;
/** hr(tag, x): a field element. */
export const hr = (tag, x) => wide(tag, bytes32('x', x)) % FR;
const hkdf = (salt, ikm, info, length) => Buffer.from(hkdfSync('sha256', ikm, Buffer.from(salt, 'utf8'), info, length));

// ── keys (§1) ──

/** m = the first 32 bytes of HMAC-SHA512(key = "sh20/v0/seed", data = the 64-byte BIP39 seed). */
export function masterSecret(bip39Seed) {
  return createHmac('sha512', TAG.seed).update(bip39Seed).digest().subarray(0, 32);
}

/** { ask, nsk, ivk, address: { ivkPub, a, n } } from the master secret. */
export function walletKeys(m) {
  bytes32('m', m);
  const [ask, nsk] = [hs(TAG.ask, m), hs(TAG.nsk, m)];
  if (ask === null || nsk === null) throw new Error('unusable master secret');
  const ivk = createHash('sha256').update(TAG.ivk, 'utf8').update(m).digest();
  return { ask, nsk, ivk, address: { ivkPub: x25519Public(ivk), a: mulBase8(ask), n: mulBase8(nsk) } };
}

// ── notes ──

/** { tauA, tauN, rho } from a note's 32-byte secret, or null if a tweak is 0. */
export function noteSecrets(s) {
  const [tauA, tauN] = [hs(TAG.tweakA, s), hs(TAG.tweakN, s)];
  return tauA === null || tauN === null ? null : { tauA, tauN, rho: hr(TAG.rho, s) };
}

/** npk = Poseidon(Ak, NK) with Ak = A + τa·B8 and NK = N + τn·B8. */
export function noteNpk(address, secrets) {
  return npkOf(add(address.a, mulBase8(secrets.tauA)), add(address.n, mulBase8(secrets.tauN)));
}

const sharedSecret = (z, pkEph, ivkPub) => hkdf(TAG.note, z, Buffer.concat([pkEph, ivkPub]), 32);
function aeadKey(s, leafBytes) {
  const okm = hkdf(TAG.aead, s, leafBytes, 44);
  return [okm.subarray(0, 32), okm.subarray(32)];
}

/**
 * Seals `v` units of `ticker` to `address` with the fresh X25519 private key `e` (§3).
 * Returns the output { leaf, pkEph, ct } and what the sender needs for its proof: { secrets, npk }.
 */
export function seal(address, ticker, v, e) {
  if (!TICKER.test(ticker)) throw new RangeError('not a ticker');
  if (typeof v !== 'bigint' || v < 0n || v >= 1n << 64n) throw new RangeError('v must be a BigInt below 2^64');
  const pkEph = x25519Public(e);
  const z = x25519(e, address.ivkPub);
  if (isZero(z)) throw new Error('address: IVK is a low-order point');
  const s = sharedSecret(z, pkEph, bytes32('IVK', address.ivkPub));
  const secrets = noteSecrets(s);
  if (!secrets) throw new Error('zero tweak: draw another e');
  const npk = noteNpk(address, secrets);
  const leaf = noteLeaf(tickerT(ticker), v, npk, secrets.rho);
  const leafBytes = le32(leaf);
  const [key, nonce] = aeadKey(s, leafBytes);
  const plaintext = Buffer.alloc(12);
  plaintext.writeBigUInt64LE(v, 0);
  plaintext.write(ticker, 8, 'latin1');
  const cipher = createCipheriv('aes-256-gcm', key, nonce).setAAD(leafBytes);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { leaf, pkEph, ct, secrets, npk };
}

/**
 * Tries to open an output { leaf, pkEph, ct } with an incoming viewing key: `ivk` and the wallet's
 * own `address` (§4). Returns { ticker, v, secrets, npk }, or null unless the tag verifies, the
 * plaintext names a ticker, and the leaf is the one this wallet computes for it.
 */
export function scan(ivk, address, { leaf, pkEph, ct }) {
  if (!(ct instanceof Uint8Array) || ct.length !== 28 || !(pkEph instanceof Uint8Array) || pkEph.length !== 32) return null;
  if (typeof leaf !== 'bigint' || leaf < 0n || leaf >= FR) return null;
  const z = x25519(ivk, pkEph);
  if (isZero(z)) return null;
  const s = sharedSecret(z, Buffer.from(pkEph), bytes32('IVK', address.ivkPub));
  const leafBytes = le32(leaf);
  const [key, nonce] = aeadKey(s, leafBytes);
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 }).setAAD(leafBytes).setAuthTag(Buffer.from(ct.subarray(12)));
    plaintext = Buffer.concat([decipher.update(Buffer.from(ct.subarray(0, 12))), decipher.final()]);
  } catch {
    return null; // not for this wallet
  }
  const v = plaintext.readBigUInt64LE(0);
  const ticker = plaintext.toString('latin1', 8, 12);
  if (!TICKER.test(ticker)) return null;
  const secrets = noteSecrets(s);
  if (!secrets) return null;
  const npk = noteNpk(address, secrets);
  // the plaintext alone proves nothing: the note is ours only if it hashes to the published leaf
  return noteLeaf(tickerT(ticker), v, npk, secrets.rho) === leaf ? { ticker, v, secrets, npk } : null;
}

/** The keys that spend a note: sk = ask + τa, nk = nsk + τn (mod l); see noteKeys. */
export function spendKeys({ ask, nsk }, { tauA, tauN }) {
  return noteKeys((ask + tauA) % L, (nsk + tauN) % L);
}

// ── public notes (§5) ──

/** The secret of the wallet's i-th public note: HKDF(salt "sh20/v0/self", ikm = ivk, info = u32le(i)). */
export function selfSecret(ivk, i) {
  if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) throw new RangeError('i must be a u32');
  const info = Buffer.alloc(4);
  info.writeUInt32LE(i);
  return hkdf(TAG.self, bytes32('ivk', ivk), info, 32);
}

/**
 * The opening `npk` a wallet publishes for its i-th public note, with the note's secrets.
 * A public note has rho = 0 (docs/SPEC-WIRE.md §2): { npk, rho: 0n, secrets: { tauA, tauN, rho: 0n } }.
 */
export function publicOpening(ivk, address, i) {
  const s = selfSecret(ivk, i);
  const [tauA, tauN] = [hs(TAG.tweakA, s), hs(TAG.tweakN, s)];
  if (tauA === null || tauN === null) return null;
  const secrets = { tauA, tauN, rho: 0n };
  return { npk: noteNpk(address, secrets), rho: 0n, secrets };
}
