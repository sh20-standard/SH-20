// ============================================================================
// PROVISIONAL — the note key and nullifier derivations.
//
// This is the ONLY place where the vault turns its secret into an `npk`, and
// the only place that computes a nullifier.
// It must later match the spend circuit exactly (CLAUDE.md: `npk` from tweaked
// BabyJubJub spend and nullifier keys, as in Tacit; nullifier
// Poseidon(nk_note, leaf, leaf_index); EdDSA-Poseidon over bodyHash).
// The circuit is not written yet, so this placeholder only guarantees what a
// MINT needs today: a fresh, unlinkable field element per note, reproducible
// from the vault seed.
//
// Consequence: notes minted with scheme `provisional-0` may NOT be spendable by
// the final circuit. Signet only. When the circuit lands, replace the body of
// `deriveNpk`, bump NPK_SCHEME, and keep the old scheme readable for recovery.
// ============================================================================

import { hashToFr } from './fr.js';
import { poseidon2 } from './sh20.js';

export const NPK_SCHEME = 'provisional-0';

const TAG_NPK = hashToFr('sh20/vault/provisional-0/npk');

/**
 * @param {Uint8Array} seed  32-byte vault seed
 * @param {number} index     note index (each note gets its own key: a public
 *                           mint reveals npk, so reusing one would link mints)
 * @returns {{ npk: bigint, ask: bigint, nk: bigint, scheme: string }}
 *          `ask` (spend key) and `nk` (nullifier key) are secrets.
 */
export function deriveNpk(seed, index) {
  const ask = hashToFr('sh20/vault/provisional-0/ask', seed, index);
  const nk = hashToFr('sh20/vault/provisional-0/nk', seed, index);
  const npk = poseidon2(poseidon2(TAG_NPK, ask), nk);
  return { npk, ask, nk, scheme: NPK_SCHEME };
}

/**
 * PROVISIONAL nullifier of the note at tree position `pos`. The circuit of PR #4
 * defines nf = Poseidon(nk, leaf, index) with 3 inputs. Do not write a Poseidon
 * of our own for it: the circuit session provides a circomlib-compatible JS
 * Poseidon (2 to 5 inputs) and reference npk / nullifier / EdDSA functions with
 * test vectors. Until then this two-input stand-in takes the same inputs;
 * replace it together with deriveNpk, using those reference functions.
 */
export function deriveNullifier(nk, leaf, pos) {
  return poseidon2(poseidon2(nk, leaf), BigInt(pos));
}
