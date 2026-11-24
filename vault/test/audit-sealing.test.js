// Tests written by the audit of the part `sealing` (docs/audit/2026-11-24-sealing.md), for its findings that
// are in the vault: what scanning lets a sender or an indexer do to it. Each test shows a finding as the code
// stands; the ones in the wallet reference itself are in circuit/js/test/audit-sealing.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Vault } from '../src/keys.js';
import { memoryNoteStore } from '../src/notestore.js';
import { matchNotes } from '../src/match.js';
import { anchor } from '../src/send.js';
import { decodeAddress, seal } from '../src/sh20.js';

const h = (label) => Uint8Array.from(createHash('sha256').update(`audit-sealing/${label}`).digest());
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
/** A leaf as the vault's API client hands it to the scan (src/api.js normNote). */
const outNote = (o, pos, height = 1) => ({ pos, kind: 'OUT', leaf: o.leaf, pkEph: Uint8Array.from(o.pkEph), ct: Uint8Array.from(o.ct), npk: null, ticker: null, v: null, txid: null, height });

// Finding sealing-3. Every note the vault receives stays in one record, the single localStorage value
// "sh20.vault.v0", about 750 characters a note, and nothing takes a spent note out. Each sync rewrites that record
// once for every note held (checkOwned calls updateNote, which saves). Whoever knows the address sends notes of one
// unit: the sync slows with the square of their number, and near 7,000 notes the record passes what a browser lets
// an origin store. From there the vault can record neither a note it receives nor a spend that would empty it.
test('sealing-3: notes sent to the vault grow one record without end, until it cannot be saved', async () => {
  const QUOTA = 5 * 1024 * 1024; // characters an origin may keep in localStorage, in the browsers measured elsewhere
  const m = new Map();
  let saves = 0;
  const storage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => {
      saves++;
      if (k.length + String(v).length > QUOTA) throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
      m.set(k, String(v));
    },
    removeItem: (k) => m.delete(k),
  };
  // fixed (vault-3, the same finding): each note is a record of its own, in the note store, which is IndexedDB
  // beside the page's localStorage (src/notestore.js); here a store in memory stands for it
  const notes = memoryNoteStore();
  const v = await Vault.fromWords(storage, WORDS, 'a passphrase', { notes });
  const mine = await decodeAddress('tsh20', v.address);
  // notes of 1 unit, sealed to the vault's address by anyone
  for (let i = 0; i < 3; i++) assert.ok(await v.receive(outNote(await seal(mine, 'GENE', 1n, h(`dust/${i}`)), 1000 + i)));
  assert.deepEqual([...m.keys()], ['sh20.vault.v0'], 'localStorage holds the vault\'s record alone');
  assert.deepEqual([...notes.records.keys()], ['out:1000', 'out:1001', 'out:1002'], 'and each note is a record of its own');
  assert.ok(![...notes.records.values()].some((t) => /plain|"v":|GENE/.test(t)), 'encrypted, as the vault is');
  // more of the same shape, without the 0.2 s each one takes to scan
  const grow = (n) => {
    while (v.state.notes.length < n) v.state.notes.push({ ...v.state.notes[0], id: `out:${1000 + v.state.notes.length}`, pos: 1000 + v.state.notes.length, pathAt: 250000, spent: 'no' });
  };
  const size = () => m.get('sh20.vault.v0').length;
  grow(1000);
  await v.save();
  const at1000 = size();
  grow(2000);
  await v.save();
  const each = (size() - at1000) / 1000;
  assert.ok(each < 40, `${each} characters a note in the vault's record: its id`);
  const record = [...notes.records.values()].at(-1).length;
  assert.ok(record > 500 && record < 1500, `${record} characters a note, in a record of its own`);
  // a path or a spent status is not stored, and a change to one note writes that note and the record, once
  const before = saves;
  const writes = notes.writes;
  await v.updateNote(v.state.notes[0].id, { pathAt: 250001, spent: 'no' });
  assert.equal(saves - before, 0, 'what a sync computes again is not written');
  await v.updateNote(v.state.notes[0].id, { status: 'not in tree (reorg?)' });
  assert.deepEqual([saves - before, notes.writes - writes], [1, 1]);
  // past where the whole vault in one value met the quota, everything is still recorded: a payment received,
  // and the spend that would move the notes out
  grow(Math.floor(QUOTA / 750) + 1);
  await v.save();
  assert.ok(size() < QUOTA / 10, `the vault's record is ${size()} characters for ${v.state.notes.length} notes`);
  assert.ok(await v.receive(outNote(await seal(mine, 'GENE', 1000n, h('a real payment')), 999999)));
  assert.ok(await v.addPending({ kind: 'TRANSFER', envelope: '00'.repeat(830), inputs: [] }));
  // and it opens again from those records, in its order, with its path and spent status left to the next sync
  const again = await Vault.open(storage, 'a passphrase', undefined, notes);
  assert.equal(again.missingNotes, 0);
  assert.deepEqual(again.state.notes.map((n) => n.id), v.state.notes.map((n) => n.id));
  assert.equal(again.state.notes[1].pathAt, undefined);
});

// Finding sealing-8. A note is named by its position, and `receive` answers "known" for a position it has a record
// for, before it looks at the leaf. After a reorg that puts another note of the vault at that position, the new note
// is skipped; checkOwned, which runs after the scan, then drops the old record because its leaf moved. The leaf is
// read again only if it is in the last blocks of the next sync.
test('sealing-8: a note that takes the position of another note of the vault in a reorg is skipped', async () => {
  const mem = new Map();
  const v = await Vault.fromWords({ getItem: (k) => mem.get(k) ?? null, setItem: (k, x) => mem.set(k, String(x)), removeItem: (k) => mem.delete(k) }, WORDS);
  const mine = await decodeAddress('tsh20', v.address);
  const [x, y] = [await seal(mine, 'GENE', 5n, h('x')), await seal(mine, 'GENE', 7n, h('y'))];
  assert.equal((await matchNotes(v, [outNote(x, 100, 999), outNote(y, 103, 999)])).found, 2);
  // block 999 is replaced by one that holds the same two transactions in the other order
  const after = [outNote(y, 100, 999), outNote(x, 103, 999)];
  assert.equal((await matchNotes(v, after)).found, 0, 'the note at a known position is now read again: update the report');
  // what checkOwned then does (ui/notes-panel.js, after matchNotes): a sealed note whose leaf is not at its position is dropped
  const tree = new Map(after.map((n) => [n.pos, n.leaf]));
  for (const n of [...v.state.notes]) if (tree.get(n.pos) !== BigInt(`0x${n.leaf}`)) await v.dropNote(n.id);
  assert.equal(v.state.notes.length, 0, '12 GENE are in the tree for this vault, and it holds no note');
});

// Finding sealing-9. The anchor of a spend, which the spend publishes, is the height the vault's indexer gave at
// the last sync, accepted up to 90 blocks behind the chain's tip without a word. An indexer that keeps one client
// on a height of its own recognises that client's next spend on the chain.
test('sealing-9: the public anchor of a spend is the height the indexer gave, up to 90 blocks behind the tip', () => {
  const tip = 250000;
  for (const behind of [1, 37, 90]) assert.equal(anchor({ height: tip - behind, tree: { root: 1n } }, tip).anchorHeight, tip - behind);
  assert.throws(() => anchor({ height: tip - 91, tree: { root: 1n } }, tip), /blocks old/);
});
