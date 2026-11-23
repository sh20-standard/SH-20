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

// H(TAG_LEAF, t) and H(H(TAG_LEAF, t), v) depend on the asset and the amount alone, and every MINT of a ticker
// shares them (its amount is lim, or k·lim): they are kept, so that a MINT's leaf costs two hashes instead of four.
// Each cache holds at most CACHE entries and starts again when full, so amounts anyone chooses (a TAKE's) cannot
// make it grow without end. A leaf is the same with the caches or without them.
const CACHE = 4096;
const tags = new Map();
const heads = new Map();
const kept = (map, key, compute) => {
  let x = map.get(key);
  if (x === undefined) {
    if (map.size >= CACHE) map.clear();
    x = compute();
    map.set(key, x);
  }
  return x;
};

export function noteLeaf(t, v, npk, rho) {
  const tag = kept(tags, t, () => poseidon2(DOMAIN.LEAF, BigInt(t)));
  const head = kept(heads, `${t}/${v}`, () => poseidon2(tag, BigInt(v)));
  return poseidon2(head, poseidon2(npk, rho));
}

/** A field element as 64 hex digits, big-endian (how the API and the vectors print it). */
export const hexFr = (x) => x.toString(16).padStart(64, '0');

/** A field element as its 32 wire bytes, little-endian. */
export const frToBytes = (x) => Buffer.from(hexFr(x), 'hex').reverse();
