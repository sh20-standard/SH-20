// Recovery words: the BIP39 wordlist, the vectors (trezor/python-mnemonic, passphrase "TREZOR"),
// what a typo gives, and a vault restored from its 12 words.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { WORDS } from '../src/bip39-english.js';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, newMnemonic } from '../src/bip39.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { masterSecret, walletKeys, encodeAddress } from '../src/sh20.js';
import { fromHex, toHex } from '../src/bytes.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/bip39.json', import.meta.url), 'utf8')).english;
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};

test('the wordlist is BIP39\'s English list', async () => {
  assert.equal(WORDS.length, 2048);
  assert.equal(createHash('sha256').update(WORDS.join('\n') + '\n').digest('hex'), '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
});

test('BIP39 vectors: entropy to words and back, and the seed', async () => {
  assert.equal(vectors.length, 24);
  for (const [entropy, phrase, seed] of vectors) {
    assert.equal(entropyToMnemonic(fromHex(entropy)), phrase);
    assert.equal(toHex(mnemonicToEntropy(phrase)), entropy);
    assert.equal(toHex(await mnemonicToSeed(phrase, 'TREZOR')), seed);
  }
});

test('a mistyped phrase is refused, never turned into other keys', async () => {
  const ok = vectors[0][1];
  assert.throws(() => mnemonicToEntropy(ok.split(' ').slice(0, 11).join(' ')), /12 words/);
  assert.throws(() => mnemonicToEntropy(ok.replace(/about$/, 'abuot')), /not in the BIP39 English list: abuot/);
  assert.throws(() => mnemonicToEntropy(ok.replace(/about$/, 'abandon')), /checksum/);
  await assert.rejects(mnemonicToSeed(ok.replace(/about$/, 'abandon')), /checksum/);
  assert.equal(toHex(mnemonicToEntropy(`  ${ok.toUpperCase().replace(/ /g, '   ')}\n`)), vectors[0][0], 'case and spaces do not matter');
  const fresh = newMnemonic();
  assert.equal(fresh.split(' ').length, 12);
  assert.doesNotThrow(() => mnemonicToEntropy(fresh));
});

test('a new vault has 12 words; the words alone restore its keys and address', async () => {
  const st = memStorage();
  const v = await Vault.create(st, 'pass');
  assert.equal(v.words.split(' ').length, 12);
  assert.ok(!st.getItem(STORAGE_KEY).includes(v.words.split(' ')[0] + ' '), 'stored encrypted');
  const again = await Vault.open(st, 'pass');
  assert.equal(again.words, v.words, 'kept in the encrypted record, to show again');
  const restored = await Vault.fromWords(memStorage(), v.words.toUpperCase());
  assert.equal(restored.address, v.address);
  assert.equal((await restored.opening(0)).npk, (await v.opening(0)).npk);
  // SPEC-NOTES §1: m = HMAC-SHA512("sh20/v0/seed", BIP39 seed ‖ "tsh20")[0..32], no BIP39 passphrase
  const m = await masterSecret(await mnemonicToSeed(v.words), 'tsh20');
  assert.equal(encodeAddress('tsh20', (await walletKeys(m)).address), v.address);
  await assert.rejects(Vault.fromWords(memStorage(), vectors[0][1].replace(/about$/, 'abandon')), /checksum/, 'a wrong checksum restores nothing');
});
