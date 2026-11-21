// Development and CI only: the Bitcoin wallet of the headless runs (dev/e2e.js), in place of
// Xverse, UniSat or Leather. One taproot key (BIP86, key path) derived from a public string: it
// holds regtest coins and demo-chain coins, nothing else. It signs for real (BIP341, SIGHASH_DEFAULT),
// so Bitcoin Core accepts what it signs on regtest (dev/regtest.js).

import { keyPathOutput, sigMsg, signKeyPath } from '../src/taproot.js';
import { compactSize, parsePsbt, scriptToAddress } from '../src/btc.js';
import { sha256 } from '../src/hash.js';
import { concat, equal, fromHex, toHex, utf8 } from '../src/bytes.js';

const key = keyPathOutput(sha256(utf8('sh20 vault dev wallet: public, never for real coins')));

export const WALLET = Object.freeze({
  script: key.script,
  address: scriptToAddress(key.script),
  publicKey: '02' + toHex(key.internal), // the internal key, as a wallet reports it (even y: BIP340)
});

const kv = (k, v) => concat(compactSize(k.length), k, compactSize(v.length), v);
const map = (entries) => concat(...entries.map((e) => kv(e.key, e.value)), Uint8Array.of(0));

/** The output an input spends, from its PSBT_IN_WITNESS_UTXO. */
function witnessUtxo(entries, i) {
  const e = entries.find((x) => x.key.length === 1 && x.key[0] === 0x01);
  if (!e) throw new Error(`input ${i} has no witness UTXO`);
  const v = e.value;
  let value = 0n;
  for (let k = 7; k >= 0; k--) value = (value << 8n) | BigInt(v[k]);
  const len = v[8];
  if (len >= 0xfd) throw new Error(`input ${i}: a script this wallet does not spend`);
  return { value, script: v.subarray(9, 9 + len) };
}

/**
 * Signs inputs `indexes` of a PSBT, as a wallet does: adds PSBT_IN_TAP_KEY_SIG to each, for this
 * wallet's key only; inputs signed already (a seller's lock) are left as they are.
 */
export function signPsbt(psbtHex, indexes) {
  const { tx, global, inputs, outputs } = parsePsbt(fromHex(psbtHex));
  const prevouts = inputs.map(witnessUtxo);
  const signed = inputs.map((entries, i) => {
    if (!indexes.includes(i)) return entries;
    if (!equal(prevouts[i].script, key.script)) throw new Error(`input ${i} is not this wallet's`);
    return [...entries, { key: Uint8Array.of(0x13), value: signKeyPath(key.secret, sigMsg(tx, i, prevouts)) }];
  });
  return toHex(concat(fromHex('70736274ff'), map(global), ...signed.map(map), ...outputs.map(map)));
}

/** Signs input `index` of a whole transaction whose spent outputs are `prevouts` (for a transaction built by hand). */
export function signInput(tx, index, prevouts) {
  if (!equal(prevouts[index].script, key.script)) throw new Error(`input ${index} is not this wallet's`);
  return signKeyPath(key.secret, sigMsg(tx, index, prevouts));
}
