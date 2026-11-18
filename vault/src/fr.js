// Field-element helpers for the BN254 scalar field.

import { FR } from './sh20.js';

/** Field element ↔ 64-char big-endian hex (the format of indexer/vectors). */
export const frHex = (x) => x.toString(16).padStart(64, '0');
export const frFromHex = (h) => {
  const x = BigInt('0x' + h);
  if (x >= FR) throw new Error('not a field element');
  return x;
};
