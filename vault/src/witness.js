// What binds an envelope read from Esplora to the chain (docs/audit/2026-11-24-vault.md, vault-6). A DEPLOY, always,
// and a LIST are in the witness of input 0, which no txid covers: the same transaction with another envelope in its
// witness has the same txid. BIP341 has the link: the tapscript of the witness, hashed as a leaf and combined with the
// internal key of its control block (and its Merkle path), must give the key of the output input 0 spends, and that
// output is in the transaction the outpoint names, which its own txid covers. With that check Esplora can only
// withhold: it cannot hand over an envelope other than the one the chain committed to. The tree must be that one
// leaf (as every commit of the vault is, taproot.js commitment): with two, the same txid fits a witness that reveals
// either, and whoever made the commit could have another envelope served than the one it revealed.

import { parseTx, txid as txidOf } from './btc.js';
import { LEAF_VERSION, leafHash, tweakKey } from './taproot.js';
import { fromHex, toHex } from './bytes.js';

const ANNEX = 0x50;


/**
 * Why the tapscript that input 0 of transaction `rawHex` reveals is not the one the output it spends commits to,
 * `prevHex` being the transaction that output is in; null when it is. Either is hex as Esplora serves it.
 */
export function witnessProblem(rawHex, prevHex) {
  const tx = parseTx(fromHex(rawHex));
  const input = tx.vin[0];
  if (!input) return 'the transaction has no input';
  if (!prevHex) return 'the transaction that input 0 spends is unknown';
  const prev = parseTx(fromHex(prevHex));
  if (txidOf(prev) !== input.txid) return 'Esplora returned another transaction than the one input 0 spends';
  const out = prev.vout[input.vout];
  if (!out || out.script.length !== 34 || out.script[0] !== 0x51 || out.script[1] !== 0x20) return 'input 0 does not spend a P2TR output';
  let w = input.witness ?? [];
  if (w.length >= 2 && w.at(-1)[0] === ANNEX) w = w.slice(0, -1);
  if (w.length < 2) return 'input 0 is not spent by a script path';
  const control = w.at(-1);
  const script = w.at(-2);
  if (control.length < 33 || (control.length - 33) % 32 !== 0 || (control[0] & 0xfe) !== LEAF_VERSION) return 'input 0 has no control block of a tapscript leaf';
  if (control.length !== 33) return 'the output input 0 spends commits to more than one script: which one the chain revealed cannot be told from its txid';
  let q;
  try {
    q = tweakKey(control.subarray(1, 33), leafHash(script));
  } catch {
    return 'the control block of input 0 names no valid key';
  }
  if (toHex(q.key) !== toHex(out.script.subarray(2)) || (control[0] & 1) !== q.parity) return 'the envelope in the witness is not the script the output it spends commits to';
  return null;
}

/** `witnessProblem` for the transaction `id`, both read from `esplora`: the hex of `id`, or throws the problem. */
export async function committedHex(esplora, id) {
  const hex = await esplora.txHex(id);
  const prevId = parseTx(fromHex(hex)).vin[0]?.txid;
  const problem = witnessProblem(hex, prevId ? await esplora.txHex(prevId) : null);
  if (problem) throw new Error(`${id.slice(0, 12)}…: ${problem}`);
  return hex;
}
