// docs/audit/2026-11-24-vault.md vault-3, docs/audit/2026-11-24-sealing.md sealing-3: one record for each note, written
// when it changes, beside a small vault record that names them in order (src/keys.js, src/notestore.js). The audits'
// own tests are `vault-3: …` (test/audit-vault.test.js) and `sealing-3: …` (test/audit-sealing.test.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { memoryNoteStore, storageNoteStore } from '../src/notestore.js';
import { NOTE_SCHEME } from '../src/notekeys.js';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const memStorage = () => {
  const m = new Map();
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};
const hex = (i, c) => i.toString(16).padStart(8, '0') + c.repeat(56);
const sealed = (i) => ({ id: `out:${i}`, kind: 'sealed', index: null, scheme: NOTE_SCHEME, ticker: 'GENE', v: String(i + 1), npk: hex(i, 'a'), rho: hex(i, 'b'), tauA: '1', tauN: '2', leaf: hex(i, 'c'), txid: null, status: 'in tree', pos: i });

test('vault-3: the vault\'s record names its notes; each note is a record, bound to its id, opened in order', async () => {
  const storage = memStorage();
  const notes = memoryNoteStore();
  const v = await Vault.fromWords(storage, WORDS, 'pass', { notes });
  v.state.notes.push(sealed(4), sealed(2), sealed(9));
  await v.save();
  const rec = JSON.parse(storage.getItem(STORAGE_KEY));
  assert.equal(rec.v, 1, 'format 1: the notes are records of their own');
  assert.equal(notes.records.size, 3);
  assert.deepEqual((await Vault.open(storage, 'pass', undefined, notes)).state.notes.map((n) => [n.id, n.v]), [['out:4', '5'], ['out:2', '3'], ['out:9', '10']]);
  // a record moved under another id does not open: the id is the associated data of its AES-GCM
  const [a, b] = [notes.records.get('out:4'), notes.records.get('out:2')];
  notes.records.set('out:4', b);
  notes.records.set('out:2', a);
  await assert.rejects(Vault.open(storage, 'pass', undefined, notes), /note out:4 does not open under this vault's key/);
  notes.records.set('out:4', a);
  notes.records.set('out:2', b);
  // a record the store lost: the others open, and the page rescans from zero (ui/vault-panel.js)
  notes.records.delete('out:2');
  const lost = await Vault.open(storage, 'pass', undefined, notes);
  assert.deepEqual([lost.missingNotes, lost.state.notes.map((n) => n.id)], [1, ['out:4', 'out:9']]);
  await assert.rejects(Vault.open(storage, 'wrong', undefined, notes), /wrong passphrase/);
});

test('vault-3: a save writes the notes that changed, and only them, in one write; a dropped note is deleted', async () => {
  const notes = memoryNoteStore();
  const v = await Vault.fromWords(memStorage(), WORDS, 'pass', { notes });
  for (let i = 0; i < 50; i++) v.state.notes.push(sealed(i));
  await v.save();
  const before = new Map(notes.records);
  let writes = notes.writes;
  await v.reserveNote(); // a counter: the vault's record, no note
  assert.equal(notes.writes, writes);
  await v.updateNote('out:7', { status: 'spending' });
  assert.equal(notes.writes, writes + 1);
  assert.deepEqual([...notes.records].filter(([id, t]) => before.get(id) !== t).map(([id]) => id), ['out:7'], 'that note alone is written again');
  writes = notes.writes;
  await v.dropNote('out:3', { save: false });
  await v.updateNote('out:8', { status: 'spending' }, { save: false });
  await v.save();
  assert.equal(notes.writes, writes + 1, 'one write for both');
  assert.ok(!notes.records.has('out:3'));
});

test('vault-3: a passphrase set or changed encrypts every note again; a vault in clear stores them in clear', async () => {
  const notes = memoryNoteStore();
  const storage = memStorage();
  const v = await Vault.fromWords(storage, WORDS, '', { notes });
  v.state.notes.push(sealed(1));
  await v.save();
  assert.match(notes.records.get('out:1'), /"plain"/);
  await v.setPassphrase('first');
  assert.doesNotMatch(notes.records.get('out:1'), /plain|GENE/);
  await v.setPassphrase('second', 'first');
  assert.equal((await Vault.open(storage, 'second', undefined, notes)).state.notes[0].id, 'out:1');
  await assert.rejects(Vault.open(storage, 'first', undefined, notes), /wrong passphrase/);
});

test('vault-3: a vault stored whole (format 0) opens, and its next save moves its notes to their records', async () => {
  const storage = memStorage();
  const notes = memoryNoteStore();
  const v = await Vault.fromWords(storage, WORDS, '', { notes });
  const seed = JSON.parse(storage.getItem(STORAGE_KEY)).plain.seed;
  // what a vault wrote before vault-3: one value, its notes in it
  storage.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [sealed(5)], seed } }));
  const old = await Vault.open(storage, '', undefined, notes);
  assert.deepEqual(old.state.notes.map((n) => n.id), ['out:5']);
  await old.save();
  assert.equal(JSON.parse(storage.getItem(STORAGE_KEY)).v, 1);
  assert.deepEqual([...notes.records.keys()], ['out:5']);
  assert.equal(v.address, old.address);
});

test('vault-3: the backup is the whole vault in one file, as before, and restores its notes on another device', async () => {
  const notes = memoryNoteStore();
  const v = await Vault.fromWords(memStorage(), WORDS, 'pass', { notes });
  v.state.notes.push(sealed(1), sealed(2));
  await v.updateNote('out:1', { pathAt: 9, spent: 'no' });
  await v.save();
  const backup = await v.exportBackup();
  assert.equal(JSON.parse(backup).v, 0, 'format 0: any version restores it');
  const there = memoryNoteStore();
  const r = await Vault.restore(memStorage(), backup, 'pass', { notes: there });
  assert.deepEqual(r.state.notes.map((n) => n.id), ['out:1', 'out:2']);
  assert.equal(r.state.notes[0].pathAt, undefined, 'a path is not backed up: the next sync computes it');
  assert.deepEqual([...there.records.keys()], ['out:1', 'out:2'], 'in records of their own once restored');
});

test('vault-3: without IndexedDB the records go to the vault\'s own storage, under keys of their own', async () => {
  const storage = memStorage();
  const v = await Vault.fromWords(storage, WORDS);
  v.state.notes.push(sealed(3));
  await v.save();
  assert.deepEqual([...storage.m.keys()].sort(), [STORAGE_KEY, `${STORAGE_KEY}.note:out:3`]);
  assert.equal((await Vault.open(storage)).state.notes[0].id, 'out:3');
  const st = storageNoteStore(storage, STORAGE_KEY);
  assert.deepEqual([...(await st.read(['out:3', 'out:4'])).keys()], ['out:3']);
});

test('vault-3: the page opens the store of the page\'s localStorage in IndexedDB, and a sync saves once, before its leaves count as scanned', () => {
  const store = readFileSync(new URL('../src/notestore.js', import.meta.url), 'utf8');
  assert.match(store, /if \(globalThis\.indexedDB && globalThis\.localStorage && storage === globalThis\.localStorage\) return idbNoteStore\(`\$\{prefix\}\.notes`\);/);
  const notes = readFileSync(new URL('../src/ui/notes-panel.js', import.meta.url), 'utf8');
  const sync = notes.slice(notes.indexOf('async function syncOnce('), notes.indexOf('\n}\n', notes.indexOf('async function syncOnce(')));
  assert.match(sync, /matchNotes\(st\.vault, r\.notes, \{ defer: true,/);
  assert.ok(sync.indexOf('await st.vault.save();') > sync.indexOf('await checkOwned(s, { rest: true });'));
  assert.ok(sync.indexOf('await st.vault.save();') < sync.indexOf('await s.scanned('), 'a note found is saved before its leaf counts as scanned');
  const owned = notes.slice(notes.indexOf('async function checkOwned('), notes.indexOf('\n}\n', notes.indexOf('async function checkOwned(')));
  assert.equal((owned.match(/\{ save: false \}/g) ?? []).length, 3, 'checkOwned writes nothing itself');
});
