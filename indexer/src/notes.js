// Note leaves. One formula for every note, whoever creates it:
//   leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))       with H = Poseidon(2)
// t = tickerT(ticker), v = amount, npk = the owner's note public key (a Poseidon hash
// of its spend and nullifier keys), rho = a fresh random field element.
//
// Public notes (MINT, TAKE, CLAIM, team unlock) publish npk only and use rho = 0; the indexer
// computes the leaf. A later spend publishes only a nullifier that depends on a
// secret key, so it cannot be linked back to the public note.

import { poseidon2 } from './poseidon.js';
import { DOMAIN } from './constants.js';

/**
 * The asset id inside notes and proofs: the ticker's 4 ASCII bytes read as a
 * big-endian u32 ("GENE" = 0x47454e45). Tickers are unique forever (the first
 * DEPLOY wins), so the id is fixed by the ticker alone; no indexer-assigned
 * number is needed. t = 0 is reserved for native BTC (not active in v0).
 */
export function tickerT(ticker) {
  const b = Buffer.from(ticker, 'latin1');
  if (b.length !== 4) throw new Error('ticker must be 4 bytes');
  return BigInt(b.readUInt32BE(0));
}

/** rho of every public note (v0.3). */
export const PUBLIC_RHO = 0n;

export function noteLeaf(t, v, npk, rho) {
  const head = poseidon2(poseidon2(DOMAIN.LEAF, BigInt(t)), BigInt(v));
  return poseidon2(head, poseidon2(npk, rho));
}

/** A field element as 64 hex digits, big-endian (how the API and the vectors print it). */
export const hexFr = (x) => x.toString(16).padStart(64, '0');

/** A field element as its 32 wire bytes, little-endian. */
export const frToBytes = (x) => Buffer.from(hexFr(x), 'hex').reverse();
