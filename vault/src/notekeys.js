// Note keys, addresses and nullifiers of docs/SPEC-NOTES.md (v0.3), computed by circuit/js, the
// wallet reference that the circuit's own model checks (circuit/js/vectors.json). The vault adds
// nothing of its own here: if it derived a key any other way, its notes would not be spendable.
//
// The vault seed is the master secret m of SPEC-NOTES §1 (32 random bytes made on this device).
//   wallet(m)            { ask, nsk, ivk, address: { ivkPub, a, n } } and its signet address (tsh20…)
//   publicNote(w, i)     the i-th public note: npk, rho = 0 (§5); what a MINT publishes
//   scanOutput(w, out)   a sealed output { leaf, pkEph, ct } opened and leaf-checked, or null (§4)
//   nullifierOf(...)     Poseidon(nsk + τn, leaf, pos), the note's spend tag (SPEC-WIRE §4)

import { HRP, L, encodeAddress, walletKeys, publicOpening, scan, nullifier } from './sh20.js';

export const NOTE_SCHEME = 'sh20-notes-v0.3';
export const NETWORK_HRP = HRP.test; // signet

export function wallet(m) {
  const keys = walletKeys(m);
  return { ...keys, addressString: encodeAddress(NETWORK_HRP, keys.address) };
}

/** The opening of public note `i`: { npk, rho: 0n, secrets: { tauA, tauN } }. Throws on a zero tweak (p < 2^-250). */
export function publicNote(w, i) {
  const o = publicOpening(w.ivk, w.address, i);
  if (!o) throw new Error(`public note ${i} has a zero tweak: skip it`);
  return o;
}

/** A sealed output, if it is this wallet's and hashes to its leaf: { ticker, v, secrets, npk }, else null. */
export function scanOutput(w, out) {
  try {
    return scan(w.ivk, w.address, out);
  } catch {
    return null; // a malformed output is not ours
  }
}

/**
 * Nullifier of the note with these tweaks at tree position `pos`: Poseidon(nk, leaf, pos) with
 * nk = nsk + τn mod l (SPEC-NOTES §4.5), the `nk` of circuit/js spendKeys. spendKeys also computes
 * the note's two public points (about 170 ms in a browser); a nullifier needs only nk.
 * test/keys.test.js checks it against spendKeys and the vectors.
 */
export function nullifierOf(w, secrets, leaf, pos) {
  return nullifier((w.nsk + secrets.tauN) % L, leaf, pos);
}
