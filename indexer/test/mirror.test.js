// The static mirror (docs/API.md, "The static mirror"): built from the API of an indexer on a random chain, it answers
// every route the vault and the explorer read as the live API does, through src/mirror-read.js. Small pages (notes of
// 25, blocks of 6) so that a short chain crosses pages and older blocks are read one by one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { listen } from '../src/api.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { buildMirror, waitForTip } from '../src/mirror.js';
import { createServer } from 'node:http';
import { mirrorGet, MIRROR_FORMAT, NotInMirror } from '../src/mirror-read.js';
import { chain, blockJson, PROOF } from '../bin/chain-gen.js';

const PROFILE = { activationHeight: 1, deployBurn: 1000n, anchorWindow: 12, anchorMinDepth: 1, deployMaturity: 3, network: 'regtest' };
const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) };

async function setup(blocks) {
  const ix = new Indexer({ profile: PROFILE, verifier });
  for (const b of blocks) ix.applyBlock(fromBitcoindBlock(JSON.parse(blockJson(b))));
  const server = await listen(ix, { port: 0, host: '127.0.0.1', network: 'regtest' });
  const api = `http://127.0.0.1:${server.address().port}`;
  const live = async (route) => {
    const r = await fetch(api + route);
    return { status: r.status, body: r.ok ? await r.json() : null };
  };
  return { ix, server, api, live };
}

const reader = (out) => async (name) => {
  const path = join(out, name);
  if (!existsSync(path)) throw Object.assign(new Error(`${name}: not in the mirror`), { status: 404 });
  return JSON.parse(readFileSync(path, 'utf8'));
};
const fromMirror = async (route, read) => {
  try {
    return { status: 200, body: await mirrorGet(route, read) };
  } catch (e) {
    if (e.status === 404 || e.status === 400) return { status: e.status, body: null };
    throw e;
  }
};

test('the mirror answers every route the vault and the explorer read as the indexer it was built from', async () => {
  const { ix, server, api, live } = await setup(chain('mirror', { blocks: 70, missingHeights: false }));
  try {
    const out = join(mkdtempSync(join(tmpdir(), 'sh20-mirror-')), 'api');
    const built = await buildMirror({ api, out, notePage: 25, blockPage: 6, now: () => new Date('2026-11-24T00:00:00Z') });
    const read = reader(out);
    const status = (await live('/status')).body;
    assert.equal(built.height, status.height);
    assert.equal(built.digest, status.digest);
    assert.deepEqual(await read('mirror.json'), {
      format: MIRROR_FORMAT, built: '2026-11-24T00:00:00.000Z', implementation: status.implementation, network: 'regtest',
      activationHeight: 1, height: status.height, hash: status.hash, digest: status.digest, notePage: 25, blockPage: 6,
    });
    assert.ok(status.leaves > 3 * 25, `${status.leaves} leaves: several pages of notes`);
    assert.equal(readdirSync(join(out, 'notes')).length, Math.ceil(status.leaves / 25));

    const { height: tip, leaves } = status;
    const blocks = (await live(`/blocks?limit=200`)).body;
    assert.ok(blocks.length > 6, 'more blocks with activity than one page of the mirror');
    const txids = [...new Set(blocks.flatMap((b) => [...b.events, ...b.rejected].map((e) => e.txid).filter(Boolean)))];
    const spent = (await live('/nullifiers')).body.nullifiers.map((n) => n.nullifier);
    const listings = (await live('/listings')).body;
    const tokens = (await live('/tokens')).body;
    assert.ok(txids.length && spent.length && listings.length && tokens.length > 1, 'the chain has every kind of answer');
    const routes = [
      '/status', '/tokens', '/listings', '/roots', '/nullifiers', '/notes', '/blocks',
      ...tokens.map((t) => `/token/${t.ticker}`), '/token/ZZZZ', '/token/sh20',
      ...['ACTIVE', 'SOLD', 'CANCELLED', 'CLOSED', 'CLAIMED', 'OPEN'].map((s) => `/listings?state=${s}`),
      ...listings.map((l) => `/listing/${l.listTxid}`), `/listing/${'0'.repeat(64)}`,
      ...[0, 1, 2, tip - 20, tip - 13, tip - 12, tip - 1, tip, tip + 1].map((h) => `/roots?from=${h}`), '/roots?from=x',
      ...[0, 1, 30, tip, tip + 1].map((h) => `/nullifiers?from=${h}`),
      ...spent.slice(0, 5).map((n) => `/nullifier/${n}`), `/nullifier/${'1'.repeat(64)}`, '/nullifier/xyz',
      ...[[0, 1000], [0, 25], [3, 7], [24, 2], [25, 25], [10, 60], [leaves - 2, 10], [leaves, 5], [leaves + 30, 5], [5, 0], [0, 6000]]
        .map(([f, l]) => `/notes?from=${f}&limit=${l}`), '/notes?limit=40', '/notes?from=-1',
      '/blocks?limit=200', '/blocks?limit=3', '/blocks?limit=6', '/blocks?limit=7', `/blocks?before=${tip}&limit=10`,
      '/blocks?before=40&limit=20', '/blocks?before=5&limit=20', '/blocks?before=1', '/blocks?limit=0',
      ...Array.from({ length: tip + 2 }, (_, h) => `/block/${h}`), '/block/abc',
      ...[0, 1, 35, tip, tip + 1].map((h) => `/digest/${h}`),
      ...txids.map((id) => `/tx/${id}`), `/tx/${'2'.repeat(64)}`,
    ];
    for (const route of routes) assert.deepEqual(await fromMirror(route, read), await live(route), route);
    await assert.rejects(() => mirrorGet('/path/0', read), NotInMirror);
    assert.equal(ix.height, tip);
  } finally {
    server.close();
  }
});

test('the mirror of an indexer before its first block, and one built while the indexer moves', async () => {
  const blocks = chain('mirror-moving', { blocks: 12, missingHeights: false });
  const { ix, server, api, live } = await setup([]);
  try {
    const out = join(mkdtempSync(join(tmpdir(), 'sh20-mirror-')), 'api');
    const empty = await buildMirror({ api, out });
    assert.equal(empty.height, null);
    for (const route of ['/status', '/tokens', '/notes', '/blocks', '/roots', '/roots?from=1', '/nullifiers', '/block/1']) {
      assert.deepEqual(await fromMirror(route, reader(out)), await live(route), route);
    }
    // A block arrives while the first attempt reads: the mirror is the one of the new tip, not a mix.
    let moved = 0;
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, ...rest) => {
      if (moved < 3 && String(url).includes('/nullifiers')) ix.applyBlock(fromBitcoindBlock(JSON.parse(blockJson(blocks[moved++]))));
      return realFetch(url, ...rest);
    };
    let built;
    try {
      built = await buildMirror({ api, out });
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.equal(moved, 3);
    assert.equal(built.height, 3);
    assert.deepEqual(await reader(out)('status.json'), (await live('/status')).body);
    assert.deepEqual(readdirSync(join(out, 'block')).sort(), ['1.json', '2.json', '3.json']);
    assert.equal(readdirSync(join(out, '..')).length, 1, 'no folder left from the attempts');
  } finally {
    server.close();
  }
});

test('waiting for the tip: an indexer with no block is at the tip until the chain reaches A, and behind it after', async () => {
  const serve = (body) => {
    const s = createServer((req, res) => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body(req.url))));
    return new Promise((r) => s.listen(0, '127.0.0.1', () => r(s)));
  };
  let tip = 8;
  const esplora = await serve(() => tip);
  const api = await serve(() => ({ height: null, activationHeight: 20 }));
  const url = (s) => `http://127.0.0.1:${s.address().port}`;
  try {
    assert.equal(await waitForTip({ api: url(api), esplora: url(esplora), timeoutMs: 2000, everyMs: 50 }), null);
    tip = 20; // block A is mined and the indexer has not read it
    await assert.rejects(() => waitForTip({ api: url(api), esplora: url(esplora), timeoutMs: 300, everyMs: 50 }), /did not reach the tip/);
  } finally {
    esplora.close();
    api.close();
  }
});
