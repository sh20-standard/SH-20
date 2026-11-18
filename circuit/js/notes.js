// Note keys, the note public key, the nullifier and the body hash: what the spend circuit recomputes
// from a wallet's secrets (docs/SPEC-WIRE.md §4, circuit/src/model.rs).
//
//   Ak   = sk·B8                      the key that signs spends of the note
//   NK   = nk·B8                      binds the nullifier key into the note
//   npk  = Poseidon(Ak.x, Ak.y, NK.x, NK.y)
//   leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))        (indexer/src/notes.js)
//   nf   = Poseidon(nk, leaf, index)

import { createHash } from 'node:crypto';
import { DOMAIN, FR, TREE_DEPTH } from '../../indexer/src/constants.js';
import { poseidon } from '../../indexer/src/poseidon.js';
import { L, mulBase8 } from './babyjub.js';

function scalar(name, x) {
  if (typeof x !== 'bigint' || x <= 0n || x >= L) throw new RangeError(`${name} must be a BigInt in [1, l)`);
  return x;
}
function field(name, x) {
  if (typeof x !== 'bigint' || x < 0n || x >= FR) throw new RangeError(`${name} must be a field element`);
  return x;
}

/** npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y). */
export function npkOf(ak, nkPub) {
  return poseidon([ak[0], ak[1], nkPub[0], nkPub[1]]);
}

/**
 * The keys of one note from its two secret scalars, both in [1, l): `sk` signs spends, `nk` derives
 * the nullifier. The circuit takes nk as a field element below l, so it is never reduced here.
 */
export function noteKeys(sk, nk) {
  const ak = mulBase8(scalar('sk', sk));
  const nkPub = mulBase8(scalar('nk', nk));
  return { sk, nk, ak, nkPub, npk: npkOf(ak, nkPub) };
}

/** nf = Poseidon(nk, leaf, index), for nk in [0, l) and a position below 2^32. */
export function nullifier(nk, leaf, index) {
  if (typeof nk !== 'bigint' || nk < 0n || nk >= L) throw new RangeError('nk must be a BigInt in [0, l)');
  const i = BigInt(index);
  if (i < 0n || i >= 1n << BigInt(TREE_DEPTH)) throw new RangeError('index must be a position of the tree');
  return poseidon([nk, field('leaf', leaf), i]);
}

/** bodyHash = SHA256("sh20/v0/body" ‖ body) mod r, body = every envelope byte before proofLen. */
export function bodyHash(body) {
  const h = createHash('sha256').update(DOMAIN.BODY, 'utf8').update(body).digest('hex');
  return BigInt(`0x${h}`) % FR;
}
