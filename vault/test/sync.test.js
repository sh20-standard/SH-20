// Private sync: local tree identical to the indexer's, paths computed on the
// device, spends found in the bulk nullifier list, cache re-reads only new
// blocks, reorgs handled, and no per-note request ever leaves the vault.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NoteTree, rootFromPath } from '../../indexer/src/tree.js';
import { LocalTree } from '../src/tree.js';
import { Sync, REORG_MARGIN } from '../src/sync.js';
import { memoryCache } from '../src/cache.js';
import { IndexerApi } from '../src/api.js';
import { frHex } from '../src/fr.js';

const leafOf = (i) => BigInt(i) * 7919n + 13n;

test('local tree matches indexer/src/tree.js: roots and paths, append and truncate', () => {
  const ref = new NoteTree();
  const mine = new LocalTree();
  assert.equal(mine.root, ref.root, 'empty roots');
  for (const batch of [1, 2, 5, 1, 9]) {
    const xs = Array.from({ length: batch }, (_, k) => leafOf(ref.size + k));
    xs.forEach((x) => ref.append(x));
    mine.append(xs);
    assert.equal(mine.root, ref.root);
  }
  for (let p = 0; p < ref.size; p++) {
    assert.deepEqual(mine.path(p), ref.path(p));
    assert.equal(rootFromPath(mine.leaf(p), p, mine.path(p)), ref.root);
  }
  mine.truncate(7);
  const ref7 = new NoteTree();
  for (let i = 0; i < 7; i++) ref7.append(leafOf(i));
  assert.equal(mine.root, ref7.root, 'truncate gives the shorter tree');
  assert.deepEqual(mine.path(6), ref7.path(6));
});

// A chain served the way the indexer API does, with a request log.
function fakeIndexer() {
  const chain = { blocks: [] }; // [{ height, leaves: [bigint], nullifiers: [hex] }]
  const requests = [];
  const state = () => {
    const ref = new NoteTree();
    const notes = [];
    const nfs = [];
    for (const b of chain.blocks) {
      for (const x of b.leaves) notes.push({ pos: ref.append(x), height: b.height, txid: 'aa'.repeat(32), leaf: frHex(x), kind: 'OUT' });
      for (const nf of b.nullifiers) nfs.push({ height: b.height, nullifier: nf });
    }
    return { ref, notes, nfs, height: chain.blocks.at(-1)?.height ?? 0 };
  };
  let withNullifiers = true;
  globalThis.fetch = async (url) => {
    const u = new URL(url);
    requests.push(u.pathname + u.search);
    const s = state();
    let body;
    if (u.pathname === '/status') body = { network: 'signet', height: s.height, root: frHex(s.ref.root), leaves: s.ref.size };
    else if (u.pathname === '/notes') {
      const from = Number(u.searchParams.get('from'));
      body = { from, total: s.notes.length, notes: s.notes.slice(from, from + 3) }; // small pages
    } else if (u.pathname === '/nullifiers' && withNullifiers) {
      const from = Number(u.searchParams.get('from'));
      body = { from, height: s.height, nullifiers: s.nfs.filter((n) => n.height >= from) };
    }
    return { ok: !!body, status: body ? 200 : 404, json: async () => body };
  };
  return {
    chain, requests,
    add(height, n, nullifiers = []) {
      const base = chain.blocks.reduce((k, b) => k + b.leaves.length, 0);
      chain.blocks.push({ height, leaves: Array.from({ length: n }, (_, k) => leafOf(base + k + height * 1000)), nullifiers });
    },
    noNullifierRoute() { withNullifiers = false; },
    ref: () => state().ref,
  };
}

test('sync rebuilds the tree, computes paths locally and never asks per-note routes', async () => {
  const ix = fakeIndexer();
  for (let h = 1; h <= 10; h++) ix.add(h, h % 3, h === 7 ? ['ab'.repeat(32)] : []);
  const api = new IndexerApi('http://ix');
  const s = new Sync(memoryCache(), 'ix');
  const r = await s.sync(api);
  assert.equal(r.height, 10);
  assert.equal(s.tree.root, ix.ref().root);
  const pos = 4;
  const w = s.witness(pos, ix.ref().leaves[pos]);
  assert.deepEqual(w.siblings, ix.ref().path(pos));
  assert.equal(s.spentAt('ab'.repeat(32)), 7);
  assert.equal(s.spentAt('cd'.repeat(32)), null);
  assert.ok(ix.requests.every((p) => /^\/(status|notes|nullifiers)\?|^\/status$/.test(p)), ix.requests.join(' '));
  assert.ok(!ix.requests.some((p) => p.startsWith('/path') || p.startsWith('/nullifier/')));
});

test('cache: a second sync re-reads only the last blocks, and survives a reload', async () => {
  const ix = fakeIndexer();
  for (let h = 1; h <= 30; h++) ix.add(h, 2);
  const cache = memoryCache();
  const api = new IndexerApi('http://ix');
  await new Sync(cache, 'ix').sync(api);
  ix.add(31, 2, ['ee'.repeat(32)]);
  ix.requests.length = 0;
  const s = new Sync(cache, 'ix');
  assert.equal(await s.load(), true);
  assert.equal(s.tree.size, 60);
  await s.sync(api);
  assert.equal(s.tree.root, ix.ref().root);
  const notesFrom = Number(new URLSearchParams(ix.requests.find((p) => p.startsWith('/notes')).split('?')[1]).get('from'));
  assert.equal(notesFrom, (30 - REORG_MARGIN) * 2, 'notes re-read from the reorg margin, not from 0');
  assert.ok(ix.requests.includes(`/nullifiers?from=${30 - REORG_MARGIN + 1}`));
  assert.equal(s.spentAt('ee'.repeat(32)), 31);
});

test('reorgs: within the margin they are absorbed, deeper ones force one full re-read', async () => {
  const ix = fakeIndexer();
  for (let h = 1; h <= 20; h++) ix.add(h, 1, h === 19 ? ['19'.repeat(32)] : []);
  const api = new IndexerApi('http://ix');
  const s = new Sync(memoryCache(), 'ix');
  await s.sync(api);
  assert.equal(s.spentAt('19'.repeat(32)), 19);
  // shallow reorg: blocks 19-20 replaced, the spend disappears
  ix.chain.blocks.splice(-2);
  ix.add(19, 3);
  ix.add(20, 1);
  await s.sync(api);
  assert.equal(s.tree.root, ix.ref().root);
  assert.equal(s.spentAt('19'.repeat(32)), null, 'a nullifier undone by the reorg is forgotten');
  // deep reorg: blocks from 5 on replaced
  ix.chain.blocks.splice(4);
  for (let h = 5; h <= 21; h++) ix.add(h, 2);
  ix.requests.length = 0;
  await s.sync(api);
  assert.equal(s.tree.root, ix.ref().root);
  assert.ok(ix.requests.includes('/notes?from=0&limit=5000'), 'full re-read after a root mismatch');
});

test('an indexer whose leaves do not match its root is refused; no /nullifiers means spends unknown', async () => {
  const ix = fakeIndexer();
  for (let h = 1; h <= 3; h++) ix.add(h, 2);
  const api = new IndexerApi('http://ix');
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const r = await real(url);
    if (!url.includes('/status')) return r;
    const body = await r.json();
    return { ok: true, status: 200, json: async () => ({ ...body, root: '11'.repeat(32) }) };
  };
  await assert.rejects(new Sync(memoryCache(), 'ix').sync(api), /do not hash to its own root/);
  globalThis.fetch = real;
  ix.noNullifierRoute();
  const s = new Sync(memoryCache(), 'ix');
  const r = await s.sync(api);
  assert.equal(r.nullifiersKnown, false);
  assert.equal(s.spentAt('ab'.repeat(32)), undefined);
  assert.ok(!ix.requests.some((p) => p.startsWith('/nullifier/')), 'no per-note fallback');
});
