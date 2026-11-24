// Which of the wallet's coins the vault may spend (docs/audit/2026-11-24-vault.md, vault-2 and vault-15).
//
// Confirmed ones only, by Esplora's word: an unconfirmed coin can be replaced by whoever paid it, and what the
// vault funded with it leaves every mempool (vault-2).
//
// And on mainnet, plain ones only: a coin that carries an inscription or runes is spent like any other by a
// transaction that does not know it, and its first sats go to the first output that holds any, which in a MINT
// that pays is the deployer's and in a TAKE the seller's (vault-15). Nothing on the chain says which coins carry
// one; the vault knows a coin is plain when
// - the wallet lists the coins that carry nothing (UniSat's getBitcoinUtxos), or
// - the wallet keeps its collectibles at an address of their own (Xverse's ordinals address, Leather's taproot
//   one) and the coin is above SMALL_COIN, the size inscriptions and runes sit on, at the address it pays from.
// A wallet that does neither (UniSat without that list keeps everything at one address) is refused on mainnet,
// never spent from on a guess. And the second case is a guess too: nothing on the chain says a coin carries
// nothing, and a payment address can be sent a collectible. So there the page asks, each time, naming the coins
// (unverifiedCoins), and spends nothing without a yes. On signet and the test chains a coin carries nothing of worth: the rule is the
// first one alone.

/**
 * The question the page asks before it spends `coins` that no list vouches for as plain (mainnet, a wallet that
 * lists none), or null when there is nothing to ask.
 */
export function unverifiedCoins({ listed, mainnet, wallet = 'the wallet', coins }) {
  if (!mainnet || listed !== null) return null;
  const named = coins.map((u) => `${u.txid.slice(0, 8)}…:${u.vout} (${u.value} sats)`).join(', ');
  return `${wallet} cannot list which of its coins carry an inscription or runes, and nothing on the chain shows it. The vault leaves out the coins of ${SMALL_COIN} sats or less at its payment address, where the wallet keeps none of its collectibles, and would spend: ${named}. A collectible among them would be spent as plain bitcoin. Spend them?`;
}

/** Sats: a coin this small at a payment address may carry an inscription or runes (330 to 10,000 sats). */
export const SMALL_COIN = 10000n;

const key = (u) => `${u.txid}:${u.vout}`;

/**
 * The coins to spend: `chain` (Esplora's list at the address, with `confirmed`), `listed` (the wallet's list of
 * the coins that carry nothing, or null), `apart` (the wallet keeps collectibles at another address). Throws,
 * saying why, when none is left.
 */
export function spendableCoins({ chain, listed = null, apart = false, mainnet = false, wallet = 'the wallet', address = '' }) {
  if (mainnet && listed === null && !apart) {
    throw new Error(`${wallet} keeps inscriptions and runes at the address it pays from, and cannot list which of its coins carry none: on mainnet the vault spends nothing from it, rather than spend a collectible as a plain coin. Use a wallet that keeps them at an address of their own (Xverse, Leather), or a ${wallet} that lists its plain coins`);
  }
  const confirmed = new Set(chain.filter((u) => u.confirmed === true).map(key));
  let coins = (listed ?? chain).filter((u) => confirmed.has(key(u))).map((u) => ({ ...u, confirmed: true }));
  const small = mainnet && listed === null ? coins.filter((u) => u.value <= SMALL_COIN) : [];
  if (small.length) coins = coins.filter((u) => u.value > SMALL_COIN);
  if (coins.length) return coins;
  if (small.length) throw new Error(`the only confirmed coins at ${address} are of ${SMALL_COIN} sats or less, the size an inscription or runes sit on: on mainnet the vault does not spend them. Send it a larger coin`);
  if (chain.length) throw new Error(`the coins at ${address} are not confirmed yet: the vault pays from confirmed coins only, since an unconfirmed one can be replaced by whoever sent it, and the transaction with it. Wait for a block`);
  return [];
}
