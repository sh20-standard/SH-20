// The derivation a vault's words follow, recorded (docs/SPEC-NOTES.md §1, since #98: the network's address prefix is
// in the master secret). A vault made before keeps its m and works, and says once that its words no longer restore it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DERIVATION, STORAGE_KEY, Vault } from '../src/keys.js';
import { NOTE_SCHEME } from '../src/notekeys.js';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};
/** A record as a vault wrote it before #98: words, an m derived without the prefix, no `derivation`. */
function before98(words = WORDS) {
  const s = memStorage();
  s.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: '07'.repeat(32), ...(words ? { words } : {}) } }));
  return s;
}

test('a record without the field opens, works, and says once that its words no longer restore it', async () => {
  const storage = before98();
  const v = await Vault.open(storage);
  assert.equal(v.state.derivation, undefined);
  assert.equal(v.wordsRestoreIt, false);
  assert.match(await v.derivationNotice(), /^This vault was made before the network became part of the key derivation \(SPEC-NOTES §1\)\. It keeps its keys and works as before, but its 12 words no longer restore it: entered again, they give another, empty vault\. Keep its backup file \(Download backup\), or send its notes to a new vault made from new words\.$/);
  assert.equal(await v.derivationNotice(), null, 'once');
  const again = await Vault.open(storage);
  assert.equal(await again.derivationNotice(), null, 'and not at the next unlock');
  assert.equal((await again.reserveNote()).index, 0, 'it works as before');
  // and its words do give another vault now
  const fromWords = await Vault.fromWords(memStorage(), WORDS);
  assert.notEqual(fromWords.address, again.address);
});

test('a record with the field says nothing; nor one with no words, which only its backup ever restored', async () => {
  const v = await Vault.fromWords(memStorage(), WORDS);
  assert.equal(v.state.derivation, DERIVATION);
  assert.equal(v.wordsRestoreIt, true);
  assert.equal(await v.derivationNotice(), null);
  const noWords = await Vault.open(before98(null));
  assert.equal(noWords.wordsRestoreIt, false);
  assert.equal(await noWords.derivationNotice(), null);
});

test('a vault made or restored from words writes the field; a backup keeps what its vault had', async () => {
  const made = await Vault.create(memStorage(), 'pass');
  assert.equal(made.state.derivation, DERIVATION);
  const storage = memStorage();
  await Vault.fromWords(storage, WORDS, '', { restored: true });
  assert.equal(JSON.parse(storage.getItem(STORAGE_KEY)).plain.derivation, DERIVATION, 'stored');
  // the backup of a vault made before #98, restored: still its m, still the notice
  const old = await Vault.open(before98());
  await old.setPassphrase('pass');
  const back = await Vault.restore(memStorage(), await old.exportBackup(), 'pass');
  assert.equal(back.address, old.address);
  assert.match(await back.derivationNotice(), /its 12 words no longer restore it/);
  const backNew = await Vault.restore(memStorage(), await made.exportBackup(), 'pass');
  assert.equal(await backNew.derivationNotice(), null);
});

test('the page shows the notice after an unlock or a restore, and says where the words restore', () => {
  const panel = readFileSync(new URL('../src/ui/vault-panel.js', import.meta.url), 'utf8');
  assert.equal((panel.match(/st\.derivationNotice = await st\.vault\.derivationNotice\(\);/g) ?? []).length, 2, 'an unlock, a backup restored');
  assert.match(panel, /id: 'derivation-notice' \}, st\.derivationNotice\)/);
  assert.match(panel, /in any wallet that follows SPEC-NOTES, on \$\{NET\}: they give another wallet on mainnet than on the test networks/);
  assert.doesNotMatch(panel, /restore everything \(keys, notes, address\) in any wallet that follows SPEC-NOTES\. /);
});
