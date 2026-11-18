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
// wallet should go by. Checked in Node 22 and Chrome 157 (test/subtle-kat.js).

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

/**
 * X25519(k, u). All zeros when u is a low-order point: the platform refuses that secret (an
 * OperationError, or a DataError where it refuses the point itself) and so do the callers.
 * Any other failure is thrown: a platform without X25519 must not look like a bad point.
 */
export async function x25519(k, u) {
  bytes('private key', k, 32);
  bytes('public key', u, 32);
  const priv = await subtle().importKey('pkcs8', concat(PKCS8, k), { name: 'X25519' }, false, ['deriveBits']);
  try {
    const pub = await subtle().importKey('raw', u, { name: 'X25519' }, true, []);
    return new Uint8Array(await subtle().deriveBits({ name: 'X25519', public: pub }, priv, 256));
  } catch (e) {
    if (e?.name === 'OperationError' || e?.name === 'DataError') return new Uint8Array(32);
    throw e;
  }
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
