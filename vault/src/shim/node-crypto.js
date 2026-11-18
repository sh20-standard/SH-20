// Stand-in for `node:crypto` in the browser (wired by the import map in index.html), synchronous
// like Node's. Exactly what the reused files call:
//   indexer/src/constants.js          createHash('sha256')
//   circuit/js/seal.js, eddsa.js      createHash, createHmac('sha512'), hkdfSync('sha256'),
//                                     createCipheriv / createDecipheriv('aes-256-gcm')
//   circuit/js/address.js             X25519 keys as DER (createPrivateKey, createPublicKey), diffieHellman
// test/shim.test.js compares each with Node's own; test/browser-env runs circuit/js/vectors.json through it.

import { Buffer } from './buffer.js';
import { sha256, sha512, hmac, hkdfSha256 } from '../hash.js';
import { gcmEncrypt, gcmDecrypt } from '../aesgcm.js';
import { x25519, x25519Base } from '../x25519.js';

const bytes = (data, enc) => (typeof data === 'string' ? Buffer.from(data, enc || 'utf8') : data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
const HASH = { sha256, sha512 };

function hasher(compute) {
  const parts = [];
  const h = {
    update(data, enc) {
      parts.push(bytes(data, enc));
      return h;
    },
    digest(enc) {
      const out = Buffer.from(compute(Buffer.concat(parts)));
      return enc ? out.toString(enc) : out;
    },
  };
  return h;
}

export function createHash(alg) {
  if (!HASH[alg]) throw new Error(`createHash: no ${alg}`);
  return hasher(HASH[alg]);
}

export function createHmac(alg, key) {
  if (!HASH[alg]) throw new Error(`createHmac: no ${alg}`);
  const k = bytes(key);
  return hasher((m) => hmac(alg, k, m));
}

export function hkdfSync(alg, ikm, salt, info, length) {
  if (alg !== 'sha256') throw new Error(`hkdfSync: no ${alg}`);
  return hkdfSha256(bytes(ikm), bytes(salt), bytes(info), length).buffer;
}

// AES-256-GCM, buffered: update() returns nothing and final() everything, which concatenates
// to the same bytes as Node's streaming output.
function gcm(alg, key, iv, decrypt) {
  if (alg !== 'aes-256-gcm') throw new Error(`cipher: no ${alg}`);
  const parts = [];
  let aad = new Uint8Array(0);
  let tag = null;
  const c = {
    setAAD(a) {
      aad = bytes(a);
      return c;
    },
    setAuthTag(t) {
      tag = bytes(t);
      return c;
    },
    update(data) {
      parts.push(bytes(data));
      return Buffer.alloc(0);
    },
    final() {
      const input = Buffer.concat(parts);
      if (decrypt) {
        const out = tag && gcmDecrypt(bytes(key), bytes(iv), input, aad, tag);
        if (!out) throw new Error('Unsupported state or unable to authenticate data');
        return Buffer.from(out);
      }
      const { ct, tag: t } = gcmEncrypt(bytes(key), bytes(iv), input, aad);
      tag = t;
      return Buffer.from(ct);
    },
    getAuthTag() {
      return Buffer.from(tag);
    },
  };
  return c;
}
export const createCipheriv = (alg, key, iv) => gcm(alg, key, iv, false);
export const createDecipheriv = (alg, key, iv) => gcm(alg, key, iv, true);

// X25519 keys in the two DER forms address.js builds (PKCS#8 private, SPKI public).
const PKCS8 = '302e020100300506032b656e04220420';
const SPKI = '302a300506032b656e032100';
const der = (prefix, key) => {
  const b = Buffer.from(key);
  if (b.length !== 32 + prefix.length / 2 || b.subarray(0, prefix.length / 2).toString('hex') !== prefix) throw new Error('only X25519 DER keys are supported');
  return Uint8Array.from(b.subarray(prefix.length / 2));
};
const keyObject = (type, raw) => ({
  type,
  asymmetricKeyType: 'x25519',
  raw,
  export({ format, type: t } = {}) {
    if (type !== 'public' || format !== 'der' || t !== 'spki') throw new Error('export: only public SPKI DER');
    return Buffer.concat([Buffer.from(SPKI, 'hex'), raw]);
  },
});

export function createPrivateKey({ key, format, type }) {
  if (format !== 'der' || type !== 'pkcs8') throw new Error('createPrivateKey: only PKCS#8 DER');
  return keyObject('private', der(PKCS8, key));
}

export function createPublicKey(input) {
  if (input?.type === 'private') return keyObject('public', x25519Base(input.raw));
  if (input?.format !== 'der' || input?.type !== 'spki') throw new Error('createPublicKey: only SPKI DER or a private key');
  return keyObject('public', der(SPKI, input.key));
}

/** Like Node (OpenSSL), refuses an all-zero shared secret, which only a low-order point gives. */
export function diffieHellman({ privateKey, publicKey }) {
  const z = x25519(privateKey.raw, publicKey.raw);
  if (z.every((x) => x === 0)) throw new Error('the shared secret is zero');
  return Buffer.from(z);
}

export function randomBytes(n) {
  const b = Buffer.alloc(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export default { createHash, createHmac, hkdfSync, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, randomBytes };
