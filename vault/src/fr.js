// Field-element helpers for the BN254 scalar field.

import { FR } from './sh20.js';
import { sha256 } from './hash.js';
import { concat, utf8, u32le, bytesToBig } from './bytes.js';

/**
 * Domain-separated hash to a non-zero field element: 512 bits of SHA-256
 * output reduced mod r, so the bias is negligible.
 * `index` is optional (u32).
 */
export function hashToFr(tag, seed = new Uint8Array(0), index = null) {
  const body = concat(utf8(tag), new Uint8Array([0]), seed, index === null ? new Uint8Array(0) : u32le(index));
  const wide = concat(sha256(concat(new Uint8Array([0]), body)), sha256(concat(new Uint8Array([1]), body)));
  const x = bytesToBig(wide) % FR;
  return x === 0n ? 1n : x;
}

/** Field element ↔ 64-char big-endian hex (the format of indexer/vectors). */
export const frHex = (x) => x.toString(16).padStart(64, '0');
export const frFromHex = (h) => {
  const x = BigInt('0x' + h);
  if (x >= FR) throw new Error('not a field element');
  return x;
};
