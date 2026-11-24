// The relayer's two secrets (docs/RELAYER.md §6):
//
//   words      twelve BIP39 words, the sh20 wallet its fees are sealed to (docs/SPEC-NOTES.md §1),
//              derived exactly as the vault derives a vault from its words: the operator restores
//              the vault from them to see and spend what the relayer earned
//   btcSecret  32 bytes, the Bitcoin key of a BIP86 key-path output that pays every commit
//
// Nothing is derived here that the vault and circuit/js do not define already.

import { mnemonicToSeed } from '../../vault/src/bip39.js';
import { masterSecret } from '../../vault/src/sh20.js';
import { NETWORK_HRP, wallet } from '../../vault/src/notekeys.js';
import { keyPathOutput } from '../../vault/src/taproot.js';
import { scriptToAddress } from '../../vault/src/btc.js';

/** { notes: the sh20 wallet (ivk, address, addressString), btc: { script, key, secret, address } }. */
export async function relayerKeys({ words, btcSecret }) {
  const m = Uint8Array.from(await masterSecret(await mnemonicToSeed(words), NETWORK_HRP)); // refuses a phrase with a typo
  const notes = await wallet(m);
  m.fill(0);
  const btc = keyPathOutput(btcSecret); // throws on a key out of [1, n)
  return { notes, btc: { ...btc, address: scriptToAddress(btc.script) } };
}
