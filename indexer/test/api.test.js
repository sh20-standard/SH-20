import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../src/indexer.js';
import { listen } from '../src/api.js';
import { rootFromPath } from '../src/tree.js';
import { noteLeaf, tickerT } from '../src/notes.js';
import { chain, deployEnv, mockVerifier, opening, spend, tx } from './helpers.js';

async function withApi(fn) {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier: mockVerifier() });
  const c = chain(ix);
  const o = opening();
  c.block(tx({ env: deployEnv() }));
  c.block(tx({ env: { type: 'MINT', ticker: 'GENE', ...o }, burnSats: 1000n }));
  const s = spend(2);
  c.block(tx({ env: { type: 'TRANSFER', spend: s }, carrier: 'witness' }));
  const server = await listen(ix, { port: 0 });
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = async (p) => {
    const r = await fetch(base + p);
    return { status: r.status, cors: r.headers.get('access-control-allow-origin'), body: await r.json() };
  };
  try {
    await fn({ ix, get, o, s });
  } finally {
    server.close();
  }
}

test('status, tokens and one token', () =>
  withApi(async ({ ix, get }) => {
    const st = await get('/status');
    assert.equal(st.status, 200);
    assert.equal(st.cors, '*');
    assert.equal(st.body.height, 3);
    assert.equal(st.body.leaves, 4);
    assert.equal(st.body.digest, ix.digest.toString('hex'));
    assert.equal(st.body.genesis, 'SH20');
    assert.deepEqual((await get('/tokens')).body.map((x) => x.ticker), ['SH20', 'GENE']);
    const gene = (await get('/token/GENE')).body;
    assert.equal(gene.mints, '1');
    assert.equal(gene.max, '21000000');
    assert.equal((await get('/token/NOPE')).status, 404);
  }));

test('notes give wallets what they need to scan, in tree order', () =>
  withApi(async ({ get, o, s }) => {
    const { body } = await get('/notes?from=0&limit=10');
    assert.equal(body.total, 4);
    const [m, ...outs] = body.notes;
    assert.equal(m.kind, 'MINT');
    assert.equal(m.v, '1000');
    assert.equal(BigInt('0x' + m.leaf), noteLeaf(tickerT('GENE'), 1000n, o.npk, 0n));
    assert.deepEqual(outs.map((n) => [n.kind, n.j, n.pkEph]), s.outs.map((x, j) => ['OUT', j, x.pkEph.toString('hex')]));
    assert.equal((await get('/notes?from=3')).body.notes.length, 1);
    assert.equal((await get('/notes?from=-1')).status, 400);
  }));

test('a Merkle path from the API recomputes the published root', () =>
  withApi(async ({ get }) => {
    const notes = (await get('/notes')).body.notes;
    for (const n of notes) {
      const { body } = await get(`/path/${n.pos}`);
      assert.equal(rootFromPath(BigInt('0x' + n.leaf), n.pos, body.siblings.map((x) => BigInt('0x' + x))).toString(16).padStart(64, '0'), body.root);
    }
    assert.equal((await get('/path/99')).status, 404);
  }));

test('roots, nullifiers, listings and unknown routes', () =>
  withApi(async ({ get, s }) => {
    const roots = (await get('/roots?from=1')).body;
    assert.deepEqual(roots.map((r) => r.height), [1, 2, 3]);
    const nf = s.nf[0].toString(16).padStart(64, '0');
    assert.equal((await get(`/nullifier/${nf}`)).body.spent, true);
    assert.equal((await get(`/nullifier/${'0'.repeat(63)}1`)).body.spent, false);
    assert.deepEqual((await get('/listings?state=ACTIVE')).body, []);
    assert.equal((await get('/nope')).status, 404);
  }));

test('blocks with activity, newest first, and one transaction with its notes', () =>
  withApi(async ({ ix, get, s }) => {
    const blocks = (await get('/blocks')).body;
    assert.deepEqual(blocks.map((b) => b.height), [3, 2, 1]);
    assert.equal(blocks[0].events[0].type, 'TRANSFER');
    assert.equal(blocks[0].digest, ix.digest.toString('hex'));
    assert.deepEqual((await get('/blocks?before=3&limit=1')).body.map((b) => b.height), [2]);
    assert.equal((await get('/blocks?limit=x')).status, 400);

    const txid = blocks[0].events[0].txid;
    const t = (await get(`/tx/${txid}`)).body;
    assert.equal(t.height, 3);
    assert.equal(t.event.type, 'TRANSFER');
    assert.equal(t.rejected, null);
    assert.deepEqual(t.notes.map((n) => n.kind), ['OUT', 'OUT', 'OUT']);
    assert.equal(BigInt('0x' + t.notes[0].leaf), s.outs[0].leaf);
    assert.equal((await get('/tx/' + 'ab'.repeat(32))).status, 404);
    assert.deepEqual((await get('/digest/3')).body, { height: 3, digest: ix.digest.toString('hex') });
    assert.equal((await get('/digest/2')).body.digest, blocks[1].digest);
    assert.equal((await get('/digest/99')).status, 404);
    const all = (await get('/nullifiers')).body;
    assert.deepEqual(all.nullifiers.map((x) => x.nullifier).sort(), [...ix.nullifiers].sort());
    assert.ok(all.nullifiers.every((x) => x.height === 3));
    assert.equal((await get('/nullifiers?from=4')).body.nullifiers.length, 0);
  }));
