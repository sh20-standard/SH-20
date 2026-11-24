// BIP39 recovery words: 12 words (128 bits of entropy and a 4-bit checksum) that stand for the
// vault. The vault's master secret is SPEC-NOTES §1's: m = the first 32 bytes of
// HMAC-SHA512("sh20/v0/seed", BIP39 seed ‖ the network's address prefix) (circuit/js masterSecret), with the BIP39 seed
// PBKDF2-HMAC-SHA512(NFKD(words), "mnemonic" ‖ NFKD(passphrase), 2,048 rounds, 64 bytes).
// Any wallet that follows SPEC-NOTES restores the same keys, the same notes and the same address
// from the same words on the same network. Checked against the BIP39 vectors (test/bip39.test.js).

import { WORDS } from './bip39-english.js';
import { sha256 } from './hash.js';

const INDEX = new Map(WORDS.map((w, i) => [w, i]));
const COUNTS = [12, 15, 18, 21, 24];

/** Words for `entropy` (16, 20, 24, 28 or 32 bytes): entropy ‖ checksum, in 11-bit groups. */
export function entropyToMnemonic(entropy) {
  if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new RangeError('entropy is 16 to 32 bytes, in steps of 4');
  const cs = entropy.length / 4; // checksum bits
  const bits = [...entropy].map((b) => b.toString(2).padStart(8, '0')).join('') + sha256(entropy)[0].toString(2).padStart(8, '0').slice(0, cs);
  return bits.match(/.{11}/g).map((g) => WORDS[parseInt(g, 2)]).join(' ');
}

/** The entropy behind a phrase, or an Error that says what is wrong with it (count, unknown word, checksum). */
export function mnemonicToEntropy(phrase) {
  const words = normalize(phrase).split(' ').filter(Boolean);
  if (!COUNTS.includes(words.length)) throw new Error(`a recovery phrase has 12 words (or 15, 18, 21, 24), not ${words.length}`);
  const unknown = words.filter((w) => !INDEX.has(w));
  if (unknown.length) throw new Error(`not in the BIP39 English list: ${unknown.join(', ')}`);
  const bits = words.map((w) => INDEX.get(w).toString(2).padStart(11, '0')).join('');
  const cs = words.length / 3;
  const entropy = Uint8Array.from(bits.slice(0, bits.length - cs).match(/.{8}/g), (b) => parseInt(b, 2));
  if (entropyToMnemonic(entropy) !== words.join(' ')) throw new Error('the checksum of these words is wrong: a word is mistyped or out of order');
  return entropy;
}

const normalize = (s) => s.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');

/** 12 fresh words. */
export const newMnemonic = () => entropyToMnemonic(crypto.getRandomValues(new Uint8Array(16)));

/** The 64-byte BIP39 seed of a valid phrase (WebCrypto PBKDF2, 2,048 rounds of HMAC-SHA512). */
export async function mnemonicToSeed(phrase, passphrase = '') {
  mnemonicToEntropy(phrase); // refuses a phrase with a typo instead of deriving other keys from it
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(normalize(phrase)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512', salt: enc.encode(`mnemonic${passphrase.normalize('NFKD')}`), iterations: 2048 }, key, 512);
  return new Uint8Array(bits);
}
