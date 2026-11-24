// The vault on a static mirror (docs/API.md, "The static mirror"): every route src/api.js reads gives
// the same answer from a mirror's files as from the live indexer it was built from; each base is
// told apart by its mirror.json; every file is asked for with revalidation; and a sync reads the
// mirror as it reads an indexer, again when the mirror changes under it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { buildMirror } from '../../indexer/src/mirror.js';
import { chain, mockVerifier, spend, tx as helperTx, opening } from '../../indexer/test/helpers.js';
import { IndexerApi } from '../src/api.js';
import { Sync } from '../src/sync.js';
import { memoryCache } from '../src/cache.js';
import { staticServer } from '../dev/static.js';

const up = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${server.address().port}`)));

/** A chain with mints, a transfer (so nullifiers) and more than one page of notes; its API; a mirror of it served as files. */
async function setup() {
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(idx);
  c.block();
  for (let i = 0; i < 3; i++) c.block(helperTx({ env: { type: 'MINT', ticker: 'SH20', npk: opening().npk } }));
  c.block(helperTx({ env: { type: 'TRANSFER', spend: spend(c.next - 1) }, carrier: 'witness' }));
  c.block();
  const live = await listen(idx, { port: 0 });
  const liveBase = `http://127.0.0.1:${live.address().port}`;
  const root = mkdtempSync(join(tmpdir(), 'sh20-mirror-'));
  const out = join(root, 'api', 'js');
  await buildMirror({ api: liveBase, out, notePage: 2 }); // pages of two leaves: /notes reads several files
  const files = staticServer({ root });
  const mirrorBase = `${await up(files)}/api/js/`;
  return { idx, c, liveBase, mirrorBase, out, close: () => { live.close(); files.close(); rmSync(root, { recursive: true, force: true }); } };
}

test('every route the vault reads answers from a mirror as from its indexer', async () => {
  const s = await setup();
  try {
    const live = new IndexerApi(s.liveBase);
    const mirror = new IndexerApi(s.mirrorBase);
    assert.equal((await live.kind()).kind, 'indexer', 'a live indexer answers mirror.json 404');
    const k = await mirror.kind();
    assert.equal(k.kind, 'mirror');
    assert.equal(k.mirror.format, 'sh20-api-mirror/1');
    assert.equal(k.mirror.height, s.idx.height);
    const H = s.idx.height;
    assert.deepEqual(await mirror.status(), await live.status());
    assert.deepEqual(await mirror.tokens(), await live.tokens());
    assert.deepEqual(await mirror.token('SH20'), await live.token('SH20'));
    for (let h = 1; h <= H; h++) {
      assert.equal(await mirror.rootAt(h), await live.rootAt(h), `root at ${h}`);
      assert.equal(await mirror.digest(h), await live.digest(h), `digest at ${h}`);
    }
    assert.equal(await mirror.digest(H + 1), null, 'past the tip: 404, as live');
    assert.deepEqual(await mirror.listings(), await live.listings());
    assert.deepEqual(await mirror.listings('ACTIVE'), await live.listings('ACTIVE'));
    assert.equal(await mirror.listing('ab'.repeat(32)), null);
    for (const from of [0, 1, 3, 5, 6, 99]) assert.deepEqual(await mirror.notes(from), await live.notes(from), `notes from ${from}`);
    assert.equal((await mirror.notes(0)).length, 6, 'three mints and three outputs, over three files');
    for (const from of [0, 1, 5, H, H + 1]) assert.deepEqual(await mirror.nullifiers(from), await live.nullifiers(from), `nullifiers from ${from}`);
    assert.equal((await mirror.nullifiers(0)).length, 2);
  } finally {
    s.close();
  }
});

test('a mirror\'s files are fetched with revalidation, and the vault never asks it for a per-note route', async () => {
  const s = await setup();
  const asked = [];
  const real = globalThis.fetch;
  globalThis.fetch = (url, init) => {
    asked.push({ url: String(url), cache: init?.cache });
    return real(url, init);
  };
  try {
    const mirror = new IndexerApi(s.mirrorBase);
    const sync = new Sync(memoryCache(), s.mirrorBase);
    const r = await sync.sync(mirror);
    assert.equal(r.height, s.idx.height);
    assert.equal(r.root, s.idx.tree.root.toString(16).padStart(64, '0'), 'the tree rebuilt here from the mirror\'s notes');
    await mirror.tokens();
    await mirror.digest(r.height);
    assert.ok(asked.length > 5);
    assert.ok(asked.every((a) => a.url.startsWith(s.mirrorBase) && a.cache === 'no-cache'), JSON.stringify(asked.filter((a) => a.cache !== 'no-cache')));
    assert.ok(asked.every((a) => /\.json$/.test(new URL(a.url).pathname) && !new URL(a.url).search), 'files only: no query string');
    assert.ok(!asked.some((a) => /\/(path|nullifier)\//.test(a.url)), 'no /path/:pos, no /nullifier/:hex');
  } finally {
    globalThis.fetch = real;
    s.close();
  }
});

test('a sync whose mirror is rebuilt at another tip while it reads starts again, and ends on one tip', async () => {
  const s = await setup();
  try {
    const mirror = new IndexerApi(s.mirrorBase);
    let rebuilt = false;
    const racing = {
      status: () => mirror.status(),
      notes: async (from) => {
        const n = await mirror.notes(from);
        if (!rebuilt) {
          rebuilt = true; // a block, and the site replaced while this sync was between two files
          s.c.block(helperTx({ env: { type: 'MINT', ticker: 'SH20', npk: opening().npk } }));
          await buildMirror({ api: s.liveBase, out: s.out, notePage: 2 });
        }
        return n;
      },
      nullifiers: (from) => mirror.nullifiers(from),
    };
    const sync = new Sync(memoryCache(), s.mirrorBase);
    const r = await sync.sync(racing);
    assert.ok(rebuilt);
    assert.equal(r.height, s.idx.height, 'the new tip');
    assert.equal(r.leaves, 7);
    assert.equal(r.root, s.idx.tree.root.toString(16).padStart(64, '0'));
  } finally {
    s.close();
  }
});

test('before block A: the mirrors have no height and the digest before A, and the vault reads them as such', async () => {
  // two indexers that have counted no block (follow.js applies none below A), and a mirror of each
  const made = [];
  const root = mkdtempSync(join(tmpdir(), 'sh20-mirror-before-'));
  const files = staticServer({ root });
  try {
    for (const name of ['js', 'rs']) {
      const idx = new Indexer({ profile: { activationHeight: 60 }, verifier: mockVerifier() });
      const live = await listen(idx, { port: 0 });
      made.push(live);
      await buildMirror({ api: `http://127.0.0.1:${live.address().port}`, out: join(root, 'api', name) });
    }
    const base = await up(files);
    const [js, rs] = ['js', 'rs'].map((n) => new IndexerApi(`${base}/api/${n}/`));
    const k = await js.mirrorInfo();
    assert.equal(k.height, null);
    assert.equal(k.activationHeight, 60);
    const [a, b] = [await js.status(), await rs.status()];
    assert.equal(a.height, null);
    assert.equal(a.digest, b.digest, 'digest_{A−1}, the same for both');
    assert.deepEqual(await js.tokens(), [], 'SH20 exists from block A on');
    assert.deepEqual(await js.notes(0), []);
    assert.deepEqual(await js.nullifiers(0), []);
    assert.deepEqual(await js.listings(), []);
    assert.equal(await js.rootAt(59), null);
    assert.equal(await js.digest(59), null);
    const sync = new Sync(memoryCache(), `${base}/api/js/`);
    const r = await sync.sync(js);
    assert.deepEqual({ height: r.height, leaves: r.leaves, notes: r.notes }, { height: null, leaves: 0, notes: [] }, 'nothing to sync, and no error');
    assert.equal(sync.height, null, 'the local state is left as it was');
  } finally {
    made.forEach((s) => s.close());
    files.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('before block A, the page: the sync stops at no height, and the indexer line and the tickers name block A', () => {
  const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
  const notes = src('ui/notes-panel.js');
  assert.ok(notes.indexOf('if (r.height === null) {') < notes.indexOf('digestAgreement(indexers, r.height'), 'no agreement asked at a height of null');
  assert.match(notes, /SH-20 starts at block \$\{PROFILE\.activationHeight\.toLocaleString\('en-US'\)\}/, 'A from the vault\'s own profile, never from /status');
  const tokens = src('ui/tokens-panel.js');
  assert.match(tokens, /status\.height === null \? `Indexer before block \$\{PROFILE\.activationHeight/);
  assert.match(tokens, /No ticker yet: SH20 exists from block/);
});

test('before block A, the profile check: no genesis yet is not another profile, another genesis is', async () => {
  const { profileDiff } = await import('../src/consensus.js');
  const { PROFILE } = await import('../src/profile.js');
  const on = { network: PROFILE.network, activationHeight: PROFILE.activationHeight, deployBurn: String(PROFILE.deployBurn), deployMaturity: PROFILE.deployMaturity, anchorWindow: PROFILE.anchorWindow };
  assert.deepEqual(profileDiff({ ...on, height: null, genesis: null }), [], 'the reference indexer before A');
  assert.deepEqual(profileDiff({ ...on, height: null, genesis: 'SH20' }), [], 'indexer-rs before A, as docs/API.md says');
  assert.match(profileDiff({ ...on, height: null, genesis: 'XXXX' }).join(), /genesis XXXX/);
  assert.match(profileDiff({ ...on, height: null }).join(), /genesis not reported/, 'a /status without the field at all');
  assert.match(profileDiff({ ...on, height: PROFILE.activationHeight, genesis: null }).join(), /genesis not reported/, 'from block A on it must be there');
});

test('before block A, the sync believes "no block" only before it has seen one, and resets nothing on its word', async () => {
  const at = (height) => ({ status: async () => ({ height, digest: 'd'.repeat(64), root: '0'.repeat(64), leaves: 0, activationHeight: 1 }), notes: async () => [], nullifiers: async () => [] });
  const s = new Sync(memoryCache(), 'x');
  assert.equal((await s.sync(at(null), { full: true })).height, null, 'never synced: before A');
  s.height = 7; // as after a sync at block 7
  s.leafHeights.push(3);
  await assert.rejects(s.sync(at(null)), /says it has counted no block, after block 7/);
  await assert.rejects(s.sync(at(null), { full: true }), /after block 7/, 'Rescan from zero: refused before anything is reset');
  assert.equal(s.height, 7);
  assert.deepEqual(s.leafHeights, [3], 'the local state is as it was');
});

test('before block A, the page: the primary\'s "no block" is checked against the chain\'s tip and the other indexers', () => {
  const notes = readFileSync(new URL('../src/ui/notes-panel.js', import.meta.url), 'utf8');
  const f = notes.slice(notes.indexOf('export async function beforeAProblem('));
  assert.match(f, /esplora\.tipHeight\(\)/);
  assert.match(f, /tip >= A/);
  assert.match(f, /o\.value\.height !== null/);
  assert.match(f, /o\.value\.digest !== mine\.value\.digest/);
  assert.match(notes, /st\.sync = \{ height: null, problem: await beforeAProblem\(\) \};/);
});
