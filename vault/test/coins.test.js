// docs/audit/2026-11-24-vault.md, vault-15 (and vault-2): the coins the vault spends are confirmed, and on mainnet
// known to be plain; the largest pays first, and each one is named before the wallet is asked. The audit's own
// test is `vault-15: …` in test/audit-vault.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SMALL_COIN, spendableCoins, unverifiedCoins } from '../src/coins.js';

const coin = (value, k = 0, confirmed = true) => ({ txid: String(k).padStart(2, '0').repeat(32), vout: k, value, confirmed });
const values = (cs) => cs.map((u) => u.value);
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');

test('vault-15: off mainnet a coin is a coin, once confirmed', () => {
  const chain = [coin(546n, 1), coin(50000n, 2), coin(70000n, 3, false)];
  assert.deepEqual(values(spendableCoins({ chain })), [546n, 50000n]);
  assert.deepEqual(values(spendableCoins({ chain, listed: [chain[1], chain[2]] })), [50000n], 'a wallet\'s list, kept to the confirmed coins');
  assert.throws(() => spendableCoins({ chain: [coin(1000n, 1, false)], address: 'tb1q…' }), /the coins at tb1q… are not confirmed yet/);
  assert.deepEqual(spendableCoins({ chain: [] }), [], 'no coin at all: the page says to fund the address');
});

test('vault-15: on mainnet, the wallet\'s list of plain coins, or the coins above SMALL_COIN of a wallet that keeps collectibles apart; never a guess', () => {
  assert.equal(SMALL_COIN, 10000n);
  const chain = [coin(330n, 1), coin(10000n, 2), coin(10001n, 3), coin(900000n, 4)];
  // Xverse, Leather: collectibles at their ordinals or taproot address; the small coins of the payment address are left out
  assert.deepEqual(values(spendableCoins({ chain, apart: true, mainnet: true })), [10001n, 900000n]);
  assert.throws(() => spendableCoins({ chain: chain.slice(0, 2), apart: true, mainnet: true, address: 'bc1q…' }), /the only confirmed coins at bc1q… are of 10000 sats or less, the size an inscription or runes sit on/);
  // UniSat with its list: those coins, whatever their size
  assert.deepEqual(values(spendableCoins({ chain, listed: [chain[0], chain[3]], mainnet: true })), [330n, 900000n]);
  // UniSat without it: refused, whatever the address holds
  assert.throws(() => spendableCoins({ chain, listed: null, apart: false, mainnet: true, wallet: 'UniSat' }), /UniSat keeps inscriptions and runes at the address it pays from/);
});

test('vault-15: the page asks coins.js, tells it whether the wallet keeps collectibles apart, and names the coins before the wallet signs', () => {
  const spends = src('ui/spends.js');
  assert.match(spends, /const apart = !!w\.otherAddress && w\.otherAddress !== w\.address;/);
  assert.match(spends, /spendableCoins\(\{ chain, listed, apart, mainnet: IS_MAINNET, wallet: w\.adapter\.name, address: w\.address \}\)/);
  assert.match(spends, /The commit spends \$\{coinsText\(cp\.commit\.tx, coins\)\}\. Sign it with/);
  assert.match(src('ui/tokens-panel.js'), /id: 'mint-coins' \}, `\$\{m\.tx\.vin\.length\} from \$\{short\(w\.address\)\}: \$\{coinsText\(m\.tx, utxos\)\}`/);
  // the wallets that keep collectibles apart say so at connect: Xverse's ordinals address, Leather's taproot one
  const wallets = src('wallets.js');
  assert.match(wallets, /a\.purpose === 'ordinals' && a\.address !== pay\.address/);
  assert.match(wallets, /a\.symbol === 'BTC' && a\.type === 'p2tr'/);
});

test('vault-15: coins no list vouches for are spent on mainnet only on the user\'s word, each time, named', () => {
  const coins = [coin(900000n, 4)];
  assert.equal(unverifiedCoins({ listed: [coins[0]], mainnet: true, coins }), null, 'the wallet lists them');
  assert.equal(unverifiedCoins({ listed: null, mainnet: false, coins }), null, 'off mainnet');
  assert.match(unverifiedCoins({ listed: null, mainnet: true, wallet: 'Xverse', coins }), /^Xverse cannot list which of its coins carry an inscription or runes[\s\S]*would spend: 04040404…:4 \(900000 sats\)\. A collectible among them would be spent as plain bitcoin\. Spend them\?$/);
  const spends = src('ui/spends.js');
  assert.match(spends, /const ask = unverifiedCoins\(\{ listed, mainnet: IS_MAINNET, wallet: w\.adapter\.name, coins: utxos \}\);\s*if \(ask && !confirm\(ask\)\) throw/);
});
