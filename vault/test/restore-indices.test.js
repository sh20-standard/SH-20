// docs/AUDIT.md §8.9: restoring an old backup (or the words) cannot reuse an index. A restored vault
// reserves no public-note key and no lock key until a sync has checked its counters against the
// chain; it then skips past the last index used, for what another device had in flight; and the lock
// keys are looked for again while a match moves their window, as the note keys were.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Vault, RESTORE_SKIP, LOCK_SKIP, RESTORE_GAP, LOCK_GAP } from '../src/keys.js';
import { matchNotes, matchListings, noteKeysSeen } from '../src/match.js';
import { noteLeaf, tickerT, PUBLIC_RHO } from '../src/sh20.js';
import { toHex } from '../src/bytes.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');

/** The public note of index `i` of `v` as an indexer's /notes lists it, at tree position `pos`. */
async function minted(v, i, pos) {
  const { npk } = await v.opening(i);
  return { kind: 'MINT', pos, npk, ticker: 'SH20', v: 1000n, leaf: noteLeaf(tickerT('SH20'), 1000n, npk, PUBLIC_RHO), txid: String(pos).padStart(64, '0') };
}

/** A listing of lock key `i` of `v`, as /listings has it. */
async function listed(v, i) {
  return { listTxid: String(100 + i).padStart(64, 'a'), lockKey: toHex((await v.lockOutput(i)).key), state: 'ACTIVE' };
}
const terms = async () => ({ ticker: 'SH20', amount: 10n, price: 1000n, payScript: Uint8Array.of(0x51, 0x20, ...new Uint8Array(32)) });

test('8.9 a restored vault reserves no index before a sync has checked it against the chain, then skips past what it found', async () => {
  assert.ok(RESTORE_SKIP < RESTORE_GAP && LOCK_SKIP < LOCK_GAP, 'a later restore from the words still finds what comes after');
  // device A writes a backup, then mints three notes (mined) and a fourth (broadcast, not mined yet), and lists twice
  const a = await Vault.fromWords(memStorage(), WORDS, 'pass');
  const backup = a.exportBackup();
  for (let i = 0; i < 4; i++) assert.equal((await a.reserveNote()).index, i, 'a vault made here reserves at once');
  assert.equal(await a.reserveLock(), 0);
  assert.equal(await a.reserveLock(), 1);
  const notes = [await minted(a, 0, 0), await minted(a, 1, 1), await minted(a, 2, 2)];
  const listings = [await listed(a, 0), await listed(a, 1)];

  // device B restores the old backup
  const b = await Vault.restore(memStorage(), backup, 'pass');
  assert.equal(b.state.next, 0, 'the backup has the counters of its day');
  await assert.rejects(b.reserveNote(), /sync first/);
  await assert.rejects(b.reserveLock(), /sync first/);
  assert.equal((await matchNotes(b, notes)).found, 3);
  await assert.rejects(b.reserveNote(), /sync first/, 'matching notes is not enough: the page says when every leaf was read');
  await b.chainChecked('notes');
  const o = await b.reserveNote();
  assert.equal(o.index, 3 + RESTORE_SKIP, 'past the three found, and past room for the one still in flight');
  assert.notEqual(o.npk, (await a.opening(3)).npk, 'not the key of the MINT in flight');
  await assert.rejects(b.reserveLock(), /sync first/, 'the lock keys are checked on their own');
  assert.equal(await matchListings(b, listings, terms), 2);
  await b.chainChecked('locks');
  assert.equal(await b.reserveLock(), 2 + LOCK_SKIP);
  assert.equal(b.state.unchecked, undefined);

  // the words: the same, from 0
  const w = await Vault.fromWords(memStorage(), WORDS, '', { restored: true });
  await assert.rejects(w.reserveNote(), /sync first/);
  await matchNotes(w, notes);
  await w.chainChecked('notes');
  assert.equal((await w.reserveNote()).index, 3 + RESTORE_SKIP);
  // a skip does not add up: restoring the backup of a vault that skipped once skips from what it found
  const again = await Vault.restore(memStorage(), (await (async () => { await w.setPassphrase('p2'); return w.exportBackup(); })()), 'p2');
  await matchNotes(again, notes);
  await again.chainChecked('notes');
  assert.equal(again.state.next, 3 + RESTORE_SKIP + 1, 'its own reservation, and no second skip');
});

test('8.9 a note key an indexer reports moves the counter, even with an amount that does not give its leaf', async () => {
  const a = await Vault.fromWords(memStorage(), WORDS, 'pass');
  const backup = a.exportBackup();
  const lying = { ...(await minted(a, 4, 0)), v: 999n }; // the leaf is that of 1000: (ticker, v) do not match it
  const b = await Vault.restore(memStorage(), backup, 'pass');
  assert.equal((await matchNotes(b, [lying])).found, 0, 'not recorded as a note');
  assert.equal(b.state.next, 5, 'but its key counts as used');
  await b.chainChecked('notes');
  assert.equal((await b.reserveNote()).index, 5 + RESTORE_SKIP);
});

test('8.9 a note key the primary hides is counted from the other indexers\' notes', async () => {
  const a = await Vault.fromWords(memStorage(), WORDS, 'pass');
  const backup = a.exportBackup();
  const honest = [await minted(a, 0, 0), await minted(a, 40, 1)]; // within RESTORE_GAP of the one before
  // the primary labels the second MINT as a sealed output, without its npk: it matches nothing
  const primary = [honest[0], { ...honest[1], kind: 'OUT', npk: null, ticker: null, v: null, pkEph: new Uint8Array(32), ct: new Uint8Array(28) }];
  const b = await Vault.restore(memStorage(), backup, 'pass');
  assert.equal((await matchNotes(b, primary)).found, 1);
  assert.equal(b.state.next, 1, 'the primary alone keeps key 40 hidden');
  await noteKeysSeen(b, honest);
  assert.equal(b.state.next, 41, 'another indexer names it: it counts as used');
  assert.equal(b.state.notes.length, 1, 'counted, not recorded: only the primary\'s notes are matched against the tree');
  await b.chainChecked('notes');
  assert.equal((await b.reserveNote()).index, 41 + RESTORE_SKIP);
});

test('8.9 lock keys past the first window are found again, and a key found moves the counter even when its LIST cannot be read', async () => {
  const a = await Vault.fromWords(memStorage(), WORDS, 'pass');
  const backup = a.exportBackup();
  const listings = [await listed(a, 5), await listed(a, 12), await listed(a, 19)]; // each within LOCK_GAP of the one before
  const b = await Vault.restore(memStorage(), backup, 'pass');
  const unreadable = new Set([listings[2].listTxid]);
  const found = await matchListings(b, listings, async (l) => {
    if (unreadable.has(l.listTxid)) throw new Error('Esplora is down');
    return terms();
  });
  assert.equal(found, 2, 'the window moved twice');
  assert.deepEqual(b.state.listings.map((l) => l.lockIndex), [5, 12]);
  assert.equal(b.state.nextLock, 20, 'key 19 is used, even if its listing could not be read');
  await b.chainChecked('locks');
  assert.equal(await b.reserveLock(), 20 + LOCK_SKIP);
});

test('8.9 the page: a full sync until the note keys are checked, then chainChecked after every indexer\'s notes; the words restore as restored', () => {
  const notes = src('ui/notes-panel.js');
  assert.match(notes, /s\.sync\(indexer, \{ full: full \|\| !!st\.vault\?\.state\.unchecked\?\.notes \}\)/);
  // the other indexers' notes are read before the scan (sealing-1), and counted once it failed on no leaf
  assert.match(notes, /const counting = r\.from === 0 && !st\.sync\.agreement\.disagree\.length && st\.vault\.state\.unchecked\?\.notes;/);
  assert.match(notes, /const others = counting \? await Promise\.allSettled\(indexers\.slice\(1\)\.map\(\(i\) => i\.notes\(0\)\)\) : null;/);
  assert.match(notes, /if \(others && !failed\.length\) \{/);
  assert.match(notes, /indexers\.slice\(1\)\.map\(\(i\) => i\.notes\(0\)\)/, 'the notes of every other indexer');
  assert.match(notes, /if \(others\.every\(\(o\) => o\.status === 'fulfilled'\)\) await st\.vault\.chainChecked\('notes'\);/, 'and every one of them read');
  const market = src('ui/market-panel.js');
  const sl = market.slice(market.indexOf('export async function syncListings('));
  assert.ok(sl.indexOf('await matchListings(v, [...union.values()],') > 0 && sl.indexOf('await matchListings(v, [...union.values()],') < sl.indexOf("await v.chainChecked('locks');"));
  assert.ok(sl.indexOf("await v.chainChecked('locks');") < sl.indexOf('\n}\n'), 'in syncListings, after the whole list was read');
  assert.match(sl, /indexers\.slice\(1\)\.map\(\(i\) => i\.listings\(\)\)/, 'the lists of every indexer');
  assert.match(sl, /if \(others\.every\(\(r\) => r\.status === 'fulfilled'\)\) await v\.chainChecked\('locks'\);/, 'and every one of them read');
  assert.match(src('ui/vault-panel.js'), /Vault\.fromWords\(localStorage, words\.value, wpass\.value, \{ restored: true \}\)/);
  assert.match(src('sync.js'), /notes, from: keep,/);
});
