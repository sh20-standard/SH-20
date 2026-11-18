// Stand-in for `node:crypto` in the browser (wired by the import map in index.html).
// Only what indexer/src/constants.js needs: a synchronous createHash('sha256').

import { Buffer } from './buffer.js';
import { sha256 } from '../hash.js';

export function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`createHash: only sha256 is available, not ${alg}`);
  const parts = [];
  const h = {
    update(data, enc) {
      parts.push(typeof data === 'string' ? Buffer.from(data, enc || 'utf8') : data);
      return h;
    },
    digest(enc) {
      const out = Buffer.from(sha256(Buffer.concat(parts)));
      return enc ? out.toString(enc) : out;
    },
  };
  return h;
}

export function randomBytes(n) {
  const b = Buffer.alloc(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export default { createHash, randomBytes };
