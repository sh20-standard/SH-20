import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { Indexer } from '../src/indexer.js';
import { Follower, EsploraSource, BitcoindSource } from '../src/follower.js';
import { deployEnv, mockVerifier, opening, spend, tx } from './helpers.js';

const h = (s) => createHash('sha256').update(s).digest('hex');
const mint = () => tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() }, burnSats: 1000n });

/** Builds linked blocks; `parent` is the hash the first block points to. */
function blocks(txLists, { start = 1, salt = 'a', parent = 'genesis' } = {}) {
  let prev = parent;
  return txLists.map((txs, i) => {
    const height = start + i;
    const b = { height, hash: h(`${salt}/${height}`), prev, txs };
    prev = b.hash;
    return b;
  });
}

class MemorySource {
  constructor(list) {
    this.set(list);
  }
  set(list) {
    this.byHeight = new Map(list.map((b) => [b.height, b]));
    this.byHash = new Map(list.map((b) => [b.hash, b]));
  }
  async tipHeight() {
    return Math.max(...this.byHeight.keys());
  }
  async blockHash(height) {
    return this.byHeight.get(height).hash;
  }
  async block(hash) {
    return this.byHash.get(hash);
  }
}

const make = () => new Indexer({ profile: { activationHeight: 1 }, verifier: mockVerifier() });
const replay = (list) => {
  const ix = make();
  for (const b of list) ix.applyBlock(b);
  return ix.digest.toString('hex');
};

function scenario() {
  const a = blocks([[tx({ env: deployEnv() })], [mint(), mint()], [mint()], [mint()], [tx({ env: { type: 'TRANSFER', spend: spend(3) }, carrier: 'witness' })]]);
  const fork = blocks([[mint()], [], [mint(), mint()]], { start: 4, salt: 'b', parent: a[2].hash });
  return { a, b: [...a.slice(0, 3), ...fork] };
}

test('follows to the tip and matches a direct replay', async () => {
  const { a } = scenario();
  const ix = make();
  const f = new Follower({ indexer: ix, source: new MemorySource(a), startHeight: 1 });
  assert.equal(await f.step(), 5);
  assert.equal(ix.digest.toString('hex'), replay(a));
  assert.equal(await f.step(), 0);
});

test('a reorg rolls back to the common block and replays the new branch', async () => {
  const { a, b } = scenario();
  const ix = make();
  const src = new MemorySource(a);
  const seen = [];
  const f = new Follower({ indexer: ix, source: src, startHeight: 1, log: (r) => r.reorg && seen.push(r) });
  await f.step();
  src.set(b);
  await f.step();
  assert.deepEqual(seen, [{ reorg: true, from: 5, to: 3 }]);
  assert.equal(ix.height, 6);
  assert.equal(ix.digest.toString('hex'), replay(b));
  assert.equal(ix.notes.length, ix.tree.size);
});

test('a reorg deeper than the kept history is refused, not silently wrong', async () => {
  const { a, b } = scenario();
  const ix = make();
  const src = new MemorySource(a);
  const f = new Follower({ indexer: ix, source: src, startHeight: 1, keepDepth: 1 });
  await f.step();
  src.set(b);
  await assert.rejects(() => f.step(), /deeper than the kept undo history/);
});

test('confirmations hold back the newest blocks', async () => {
  const { a } = scenario();
  const ix = make();
  const f = new Follower({ indexer: ix, source: new MemorySource(a), startHeight: 1, confirmations: 2 });
  await f.step();
  assert.equal(ix.height, 3);
});

function serve(handler) {
  const server = createServer(handler);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

test('EsploraSource reads pages of transactions and gives the same digest', async () => {
  const list = blocks([[tx({ env: deployEnv() })], Array.from({ length: 30 }, mint)]);
  const mem = new MemorySource(list);
  const esplora = (t) => ({
    txid: t.txid,
    vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => w.toString('hex')), is_coinbase: false })),
    vout: t.vout.map((o) => ({ scriptpubkey: o.script.toString('hex'), value: Number(o.value) })),
  });
  const server = await serve(async (req, res) => {
    const p = req.url;
    let m;
    const reply = (body, type = 'application/json') => {
      res.writeHead(200, { 'content-type': type });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (p === '/api/blocks/tip/height') return reply(String(await mem.tipHeight()), 'text/plain');
    if ((m = p.match(/^\/api\/block-height\/(\d+)$/))) return reply(await mem.blockHash(Number(m[1])), 'text/plain');
    if ((m = p.match(/^\/api\/block\/([0-9a-f]+)$/))) {
      const b = await mem.block(m[1]);
      return reply({ id: b.hash, height: b.height, previousblockhash: b.prev, tx_count: b.txs.length });
    }
    if ((m = p.match(/^\/api\/block\/([0-9a-f]+)\/txs\/(\d+)$/))) {
      const b = await mem.block(m[1]);
      return reply(b.txs.slice(Number(m[2]), Number(m[2]) + 25).map(esplora));
    }
    res.writeHead(404);
    res.end();
  });
  try {
    const ix = make();
    const url = `http://127.0.0.1:${server.address().port}/api/`;
    await new Follower({ indexer: ix, source: new EsploraSource(url), startHeight: 1 }).step();
    assert.equal(ix.token('GENE').mints, 30n);
    assert.equal(ix.digest.toString('hex'), replay(list));
  } finally {
    server.close();
  }
});

test('BitcoindSource speaks JSON-RPC with basic auth and gives the same digest', async () => {
  const list = blocks([[tx({ env: deployEnv() })], [mint(), mint()]]);
  const mem = new MemorySource(list);
  const auths = new Set();
  const server = await serve((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', async () => {
      auths.add(req.headers.authorization);
      const { id, method, params } = JSON.parse(raw);
      let result;
      if (method === 'getblockcount') result = await mem.tipHeight();
      if (method === 'getblockhash') result = await mem.blockHash(params[0]);
      if (method === 'getblock') {
        const b = await mem.block(params[0]);
        result = {
          height: b.height, hash: b.hash, previousblockhash: b.prev,
          tx: b.txs.map((t) => ({
            txid: t.txid,
            vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, txinwitness: i.witness.map((w) => w.toString('hex')) })),
            vout: t.vout.map((o) => ({ value: Number(o.value) / 1e8, scriptPubKey: { hex: o.script.toString('hex') } })),
          })),
        };
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id, result, error: null }));
    });
  });
  try {
    const ix = make();
    const src = new BitcoindSource(`http://127.0.0.1:${server.address().port}/`, { user: 'u', pass: 'p' });
    await new Follower({ indexer: ix, source: src, startHeight: 1 }).step();
    assert.deepEqual([...auths], ['Basic ' + Buffer.from('u:p').toString('base64')]);
    assert.equal(ix.digest.toString('hex'), replay(list));
  } finally {
    server.close();
  }
});
