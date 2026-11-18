// Note leaves. One formula for every note, whoever creates it:
//   leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))       with H = Poseidon(2)
// t = tokenNum, v = amount, npk = the owner's note public key (a Poseidon hash
// of its spend and nullifier keys), rho = a fresh random field element.
//
// Public notes (MINT, TAKE, CLAIM, team unlock) publish (npk, rho); the indexer
// computes the leaf. A later spend publishes only a nullifier that depends on a
// secret key, so it cannot be linked back to the public note.

import { poseidon2 } from './poseidon.js';
import { DOMAIN } from './constants.js';

export function noteLeaf(t, v, npk, rho) {
  const head = poseidon2(poseidon2(DOMAIN.LEAF, BigInt(t)), BigInt(v));
  return poseidon2(head, poseidon2(npk, rho));
}

export function frToBytes(x) {
  return Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
}
