// docs/audit/2026-11-24-vault.md, vault-7: a copy of the vault writes over no record but the one it last read or
// wrote, and one copy's writes go out one at a time, in order. The audit's own test is `vault-7: …`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { memoryNoteStore } from '../src/notestore.js';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};

test('vault-7: a write by another copy while this one encrypts is seen before anything is written, and this one locks', async () => {
  const storage = memStorage();
  const notes = memoryNoteStore();
  const a = await Vault.fromWords(storage, WORDS, 'pass', { notes });
  const ours = storage.getItem(STORAGE_KEY);
  // what another copy writes: its record, made aside, then put back to what both read
  const b = await Vault.open(storage, 'pass', undefined, notes);
  await b.addPending({ kind: 'TRANSFER', secret: '02'.repeat(32), inputs: [], status: 'prepared' });
  const theirs = storage.getItem(STORAGE_KEY);
  storage.setItem(STORAGE_KEY, ours);
  const pending = a.reserveNote(); // checks (nothing changed yet), then encrypts
  storage.setItem(STORAGE_KEY, theirs); // the other copy's write lands during that encryption
  await assert.rejects(pending, /changed in another tab/);
  assert.equal(a.locked, true);
  assert.equal(storage.getItem(STORAGE_KEY), theirs, 'the other copy\'s record is the one stored');
  assert.equal((await Vault.open(storage, 'pass', undefined, notes)).state.pending.length, 1);
});

test('vault-7: a copy takes what was stored when it was read, and a new or restored one nothing: a write meanwhile locks it', async () => {
  // another tab's write while this one derives its passphrase key: the copy is of what it read, not of that write
  const storage = memStorage();
  const notes = memoryNoteStore();
  await Vault.fromWords(storage, WORDS, 'pass', { notes });
  const read = storage.getItem(STORAGE_KEY);
  const other = await Vault.open(storage, 'pass', undefined, notes);
  await other.reserveNote();
  const late = await Vault.open(storage, 'pass', read, notes, read); // as open() reads it, before its awaits
  await assert.rejects(late.reserveNote(), /changed in another tab/);
  // a restore that finds nothing stored, while another tab stores a vault before its first write: that vault stays
  const empty = memStorage();
  const backup = await (await Vault.fromWords(memStorage(), WORDS, 'pass')).exportBackup();
  const restoring = Vault.restore(empty, backup, 'pass', { notes: memoryNoteStore() });
  const theirs = '{"v":1,"plain":{"seed":"00"}}';
  empty.setItem(STORAGE_KEY, theirs);
  await assert.rejects(restoring, /changed in another tab/);
  assert.equal(empty.getItem(STORAGE_KEY), theirs);
});

test('vault-7: the saves of one copy go out in the order asked, each on the one before', async () => {
  const storage = memStorage();
  const v = await Vault.fromWords(storage, WORDS, 'pass', { notes: memoryNoteStore() });
  const asked = await Promise.all([v.reserveNote(), v.reserveLock(), v.addListing({ lockIndex: 0, listTxid: 'aa'.repeat(32), state: 'ACTIVE' }), v.reserveNote()]);
  assert.deepEqual([asked[0].index, asked[3].index], [0, 1]);
  assert.equal(v.locked, false, 'its own writes are never taken for another tab\'s');
  const back = await Vault.open(storage, 'pass', undefined, memoryNoteStore());
  assert.deepEqual([back.state.next, back.state.nextLock, back.state.listings.length], [2, 1, 1]);
});

test('vault-7: a passphrase changed in another tab is seen the same way', async () => {
  const storage = memStorage();
  const notes = memoryNoteStore();
  const a = await Vault.fromWords(storage, WORDS, 'first', { notes });
  const b = await Vault.open(storage, 'first', undefined, notes);
  await b.setPassphrase('second', 'first');
  await assert.rejects(a.reserveNote(), /changed in another tab/);
  await assert.rejects(Vault.open(storage, 'first', undefined, notes), /wrong passphrase/);
});

test('vault-7: where the browser has Web Locks, the check and the write it allows are one step across tabs', () => {
  const keys = readFileSync(new URL('../src/keys.js', import.meta.url), 'utf8');
  assert.match(keys, /navigator\.locks\.request\(STORAGE_KEY, \(\) => this\.#writeNow\(opts\)\)/);
  const now = keys.slice(keys.indexOf('async #writeNow('), keys.indexOf('\n  }\n', keys.indexOf('async #writeNow(')));
  const checks = [...now.matchAll(/this\.#checkUnchanged\(\);/g)].map((m) => m.index);
  assert.equal(checks.length, 2);
  assert.ok(checks[0] > now.indexOf('await this.#record()') && checks[0] < now.indexOf('await this.#notes.write('), 'after the encryption, before the notes');
  assert.ok(checks[1] > now.indexOf('await this.#notes.write(') && checks[1] < now.indexOf('this.storage.setItem('), 'and again before the record');
});
