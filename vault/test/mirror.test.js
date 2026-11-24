// The vault on a static mirror (docs/API.md, "The static mirror"): every route src/api.js reads gives
// the same answer from a mirror's files as from the live indexer it was built from; each base is
// told apart by its mirror.json; every file is asked for with revalidation; and a sync reads the
// mirror as it reads an indexer, again when the mirror changes under it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
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
