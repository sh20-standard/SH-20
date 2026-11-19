// Stand-in for `node:crypto` in the browser (wired by the import map in index.html), synchronous
// like Node's, for what the reused files call when they load: indexer/src/constants.js hashes its
// public tags with createHash('sha256'). circuit/js/address.js and seal.js import the names of their
// synchronous functions too; the vault calls none of them: it uses circuit/js/webcrypto.js, whose
// X25519, HKDF, AES-GCM and HMAC run in the platform's WebCrypto. Those names throw here.

import { Buffer } from './buffer.js';
import { sha256 } from '../hash.js';

export function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`createHash: only sha256 is available, not ${alg}`);
  const parts = [];
  const h = {
    update(data, enc) {
      parts.push(typeof data === 'string' ? Buffer.from(data, enc || 'utf8') : Uint8Array.from(data));
      return h;
    },
    digest(enc) {
      const out = Buffer.from(sha256(Buffer.concat(parts)));
      return enc ? out.toString(enc) : out;
    },
  };
  return h;
}

const webcryptoOnly = (name) => () => {
  throw new Error(`node:crypto ${name} is not in the browser: the vault goes through circuit/js/webcrypto.js`);
};
export const createHmac = webcryptoOnly('createHmac');
export const hkdfSync = webcryptoOnly('hkdfSync');
export const createCipheriv = webcryptoOnly('createCipheriv');
export const createDecipheriv = webcryptoOnly('createDecipheriv');
export const createPrivateKey = webcryptoOnly('createPrivateKey');
export const createPublicKey = webcryptoOnly('createPublicKey');
export const diffieHellman = webcryptoOnly('diffieHellman');

export function randomBytes(n) {
  const b = Buffer.alloc(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export default { createHash, createHmac, hkdfSync, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, randomBytes };
