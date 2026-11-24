// The primitives of docs/SPEC-NOTES.md on the platform's WebCrypto (`crypto.subtle`), for browsers:
// X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA512 and SHA-256.
//
// A wallet's secrets go through these: the viewing key through X25519, the shared secret through
// HKDF, the note key through AES-GCM. Written in JavaScript they run in variable time (BigInt
// arithmetic, table look-ups); here they run in the browser's own cryptographic library. Every
// function is asynchronous and takes and returns Uint8Array. Keys are imported as non-extractable.
//
// No import: this file loads wherever `crypto.subtle` exists, which in a browser means a secure
// context (https, or localhost). X25519 is the recent one (Safari 17, Firefox 130, Chrome 133 by
// their compatibility tables): `available()` says whether this platform has it, and is what a
// wallet should go by. Checked in Node 22 and Chrome 158 (test/subtle-kat.js).

const subtle = () => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto is not available here (a browser gives crypto.subtle to secure contexts only)');
  return s;
};

const bytes = (name, b, length) => {
  if (!(b instanceof Uint8Array) || (length !== undefined && b.length !== length)) {
    throw new RangeError(`${name} must be ${length === undefined ? 'a Uint8Array' : `${length} bytes`}`);
  }
  return b;
};
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** The parts, one after the other. */
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** SHA-256 of the parts, one after the other. */
export async function sha256(...parts) {
  return new Uint8Array(await subtle().digest('SHA-256', concat(...parts)));
}

/** HMAC-SHA512(key, data), 64 bytes. */
export async function hmacSha512(key, data) {
  const k = await subtle().importKey('raw', bytes('key', key), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', k, bytes('data', data)));
}

/** HKDF-SHA256 (RFC 5869): `length` bytes from the input key material, a salt and an info string. */
export async function hkdfSha256(salt, ikm, info, length) {
  const k = await subtle().importKey('raw', bytes('ikm', ikm), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: bytes('salt', salt), info: bytes('info', info) }, k, length * 8));
}

// ── X25519 (RFC 7748) ──

// the PKCS #8 wrapping of a 32-byte X25519 private key (RFC 8410)
const PKCS8 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);
const BASE_POINT = Uint8Array.of(9, ...new Uint8Array(31));

// The points of low order, as X25519 reads u (bit 255 aside, which it ignores): 0, 1, the two of
// order 8, p − 1, p and p + 1, with p = 2^255 − 19. They are every point of order 2, 4 or 8 on the
// curve or on its twist. X25519(k, u) is all zeros for them and for no other u, whatever k: a
// clamped k is a multiple of 8, and of neither of the two large prime orders.
const LOW_ORDER = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);

/**
 * True when u is a point of low order: X25519(k, u) is then all zeros for every k, and for no other
 * u. u is a public key (an address's IVK, an output's pk_eph), so this takes no care about time.
 */
export function isLowOrder(u) {
  const low = Uint8Array.from(bytes('public key', u, 32));
  low[31] &= 0x7f;
  return LOW_ORDER.has(hex(low));
}

/**
 * The one encoding of u that every library reads the same way: bit 255 cleared, and p subtracted
 * when what is left is p or more (p + n for n < 19, so n). RFC 7748 §5 has X25519 do both by
 * itself, and X25519 of this encoding is X25519 of u. Not every platform follows it on the bytes
 * it is handed: Firefox refuses five values that have bit 255 set and are ordinary points once it
 * is cleared (docs/audit/2026-11-24-sealing.md, sealing-2). u is public: no care about time.
 */
export function canonicalU(u) {
  const c = Uint8Array.from(bytes('public key', u, 32));
  c[31] &= 0x7f;
  // p = 2^255 − 19 is ed ff … ff 7f, least significant byte first
  if (c[31] === 0x7f && c[0] >= 0xed && c.subarray(1, 31).every((b) => b === 0xff)) return Uint8Array.of(c[0] - 0xed, ...new Uint8Array(31));
  return c;
}

/** True when u is written the one way an address may carry it: below p, bit 255 clear (canonicalU changes nothing). */
export function isCanonicalU(u) {
  const c = canonicalU(u);
  return c.every((b, i) => b === u[i]);
}

/**
 * X25519(k, u). All zeros when u is a point of low order, and only then. That is decided here, from
 * u, and the platform is not asked: most refuse such a point with an OperationError, which is also
 * how they report a failure of their own. Every other u goes to the platform in its canonical
 * encoding. Every failure of the platform is thrown, as is an all-zero answer for any other point:
 * a wallet that read one as a zero secret would take a note it could not try to open for somebody
 * else's.
 */
export async function x25519(k, u) {
  bytes('private key', k, 32);
  if (isLowOrder(u)) return new Uint8Array(32);
  const priv = await subtle().importKey('pkcs8', concat(PKCS8, k), { name: 'X25519' }, false, ['deriveBits']);
  const pub = await subtle().importKey('raw', canonicalU(u), { name: 'X25519' }, true, []);
  const z = new Uint8Array(await subtle().deriveBits({ name: 'X25519', public: pub }, priv, 256));
  let any = 0;
  for (const b of z) any |= b;
  if (z.length !== 32 || any === 0) throw new Error('X25519: the platform gave no secret for a point that is not of low order');
  return z;
}

/** X25519(k, 9): the public key of the private key k. */
export const x25519Public = (k) => x25519(k, BASE_POINT);

// ── AES-256-GCM, 12-byte nonce, 16-byte tag ──

const gcm = (nonce, aad) => ({ name: 'AES-GCM', iv: bytes('nonce', nonce, 12), additionalData: bytes('aad', aad), tagLength: 128 });

/** The ciphertext followed by its 16-byte tag. */
export async function aes256GcmSeal(key, nonce, aad, plaintext) {
  const k = await subtle().importKey('raw', bytes('key', key, 32), 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await subtle().encrypt(gcm(nonce, aad), k, bytes('plaintext', plaintext)));
}

/** The plaintext, or null when the tag does not verify. `sealed` is the ciphertext followed by its tag. */
export async function aes256GcmOpen(key, nonce, aad, sealed) {
  const k = await subtle().importKey('raw', bytes('key', key, 32), 'AES-GCM', false, ['decrypt']);
  try {
    return new Uint8Array(await subtle().decrypt(gcm(nonce, aad), k, bytes('sealed', sealed)));
  } catch (e) {
    if (e?.name === 'OperationError') return null;
    throw e;
  }
}

/**
 * True when this platform can run the functions above. X25519 is the one a browser may lack, so the
 * check is its known answer (RFC 7748 §6.1). A wallet calls this once and refuses to go on without
 * it, rather than falling back to arithmetic in JavaScript.
 */
export async function available() {
  try {
    const k = Uint8Array.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'.match(/../g), (h) => parseInt(h, 16));
    const want = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    return Array.from(await x25519Public(k), (b) => b.toString(16).padStart(2, '0')).join('') === want;
  } catch {
    return false;
  }
}
