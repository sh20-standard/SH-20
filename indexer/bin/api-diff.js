#!/usr/bin/env node
// The two indexers' APIs side by side: a random chain served as an Esplora API, followed by the reference
// (bin/follow.js) and by indexer-rs (`follow`), then every route of docs/API.md asked of both and the answers compared.
//
//   node bin/api-diff.js --rs <path to sh20-indexer-rs> [--seed <text>] [--blocks <n>] [--show <n>] [--reorg <depth>,<grow>]
//
// Prints, route by route, the JSON paths where the two answers differ (at most --show of them per route, default 8),
// and exits 1 if any route differs. Fields that are the implementation's own (`implementation`) are not compared.
// With --reorg, the API then serves a fork: its last <depth> blocks replaced by <depth> + <grow> others (grow 0: a fork of
// the same height). Both indexers must follow it, and agree again, with each other and with a fresh reference that only
// ever saw the fork.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { chain, blockJson } from './chain-gen.js';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : dflt;
};
const RS = arg('--rs');
if (!RS) {
  console.error('usage: node bin/api-diff.js --rs <path to sh20-indexer-rs> [--seed <text>] [--blocks <n>] [--show <n>]');
  process.exit(2);
}
const SEED = arg('--seed', 'api');
const BLOCKS = Number(arg('--blocks', 40));
const SHOW = Number(arg('--show', 8));
const [REORG_DEPTH, REORG_GROW] = (arg('--reorg', '') || '0,0').split(',').map(Number);
const here = dirname(fileURLToPath(import.meta.url));
const PROFILE = ['--activation', '1', '--deploy-burn', '1000', '--window', '12', '--min-depth', '1', '--maturity', '3', '--verifier', 'test', '--network', 'regtest'];

// The chain, as an Esplora API would serve it; `blocks` is what it serves now (the fork, after a reorg).
let blocks = chain(SEED, { blocks: BLOCKS, missingHeights: false }).map((b) => JSON.parse(blockJson(b)));
const toSats = (btc) => Math.round(Number(btc) * 1e8);
const byHash = new Map();
const spentHeight = new Map(); // the output a DEPLOY spends → the height that confirmed it
const serve = (list) => {
  blocks = list;
  for (const b of list) {
    byHash.set(b.hash, b);
    for (const t of b.tx) if (t.vin[0]?.prevout?.height !== undefined) spentHeight.set(t.vin[0].txid, t.vin[0].prevout.height);
  }
};
serve(blocks);
const esploraTx = (t) => ({
  txid: t.txid,
  vin: t.vin.map((i) => (i.coinbase ? { is_coinbase: true, witness: i.txinwitness ?? [] } : { txid: i.txid, vout: i.vout, is_coinbase: false, witness: i.txinwitness ?? [] })),
  vout: t.vout.map((o) => ({ scriptpubkey: o.scriptPubKey.hex, value: toSats(o.value) })),
});
const esplora = createServer((req, res) => {
  const send = (code, body, text = false) => {
    res.writeHead(code, { 'content-type': text ? 'text/plain' : 'application/json' });
    res.end(text ? String(body) : JSON.stringify(body));
  };
  const u = req.url;
  let m;
  if (u === '/blocks/tip/height') return send(200, blocks.at(-1).height, true);
  if (u === '/blocks/tip/hash') return send(200, blocks.at(-1).hash, true);
  if ((m = u.match(/^\/block-height\/(\d+)$/))) {
    const b = blocks.find((x) => x.height === Number(m[1]));
    return b ? send(200, b.hash, true) : send(404, 'Block not found', true);
  }
  if ((m = u.match(/^\/block\/([0-9a-f]{64})$/))) {
    const b = byHash.get(m[1]);
    if (!b) return send(404, 'Block not found', true);
    const prev = blocks.find((x) => x.height === b.height - 1) ?? [...byHash.values()].find((x) => x.height === b.height - 1);
    return send(200, { id: b.hash, height: b.height, tx_count: b.tx.length, previousblockhash: prev ? prev.hash : '00'.repeat(32) });
  }
  if ((m = u.match(/^\/block\/([0-9a-f]{64})\/txs(?:\/(\d+))?$/))) {
    const b = byHash.get(m[1]);
    if (!b) return send(404, 'Block not found', true);
    const start = Number(m[2] ?? 0);
    return send(200, b.tx.slice(start, start + 25).map(esploraTx));
  }
  if ((m = u.match(/^\/block\/([0-9a-f]{64})\/txids$/))) return byHash.has(m[1]) ? send(200, byHash.get(m[1]).tx.map((t) => t.txid)) : send(404, 'Block not found', true);
  if ((m = u.match(/^\/tx\/([0-9a-f]{64})\/status$/))) {
    const h = spentHeight.get(m[1]);
    return h === undefined ? send(404, 'Transaction not found', true) : send(200, { confirmed: true, block_height: h, block_hash: blocks.find((x) => x.height === h)?.hash });
  }
  unknown.add(u.replace(/[0-9a-f]{64}/g, ':hash').replace(/\d+$/, ':n'));
  send(404, 'not served here', true);
});
const unknown = new Set();
await new Promise((r) => esplora.listen(0, '127.0.0.1', r));
const ESPLORA = `http://127.0.0.1:${esplora.address().port}`;

const portOf = async () => {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
};
const [P1, P2] = [await portOf(), await portOf()];
const ref = spawn(process.execPath, [join(here, 'follow.js'), '--esplora', ESPLORA, ...PROFILE, '--port', String(P1), '--interval', '1'], { stdio: ['ignore', 'ignore', 'pipe'] });
const rs = spawn(RS, ['follow', '--esplora', ESPLORA, ...PROFILE, '--listen', `127.0.0.1:${P2}`], { stdio: ['ignore', 'ignore', 'pipe'] });
let errs = '';
ref.stderr.on('data', (d) => (errs += `[reference] ${d}`));
rs.stderr.on('data', (d) => (errs += `[indexer-rs] ${d}`));
const stopAll = () => {
  ref.kill();
  rs.kill();
  esplora.close();
};

const get = async (port, path) => {
  try {
    const r = await fetch(`http://127.0.0.1:${port}${path}`);
    const text = await r.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: r.status, body };
  } catch (e) {
    return { status: 'down', body: e.message };
  }
};

// Both at the tip the API serves (its height and its hash), or give up after a minute.
async function bothAtTip(label) {
  const tip = blocks.at(-1);
  const t0 = Date.now();
  for (;;) {
    const [a, b] = [await get(P1, '/status'), await get(P2, '/status')];
    const at = (x) => x.body?.height === tip.height && x.body?.hash === tip.hash;
    if (at(a) && at(b)) return true;
    if (Date.now() - t0 > 60000) {
      console.log(`${label}: not both at block ${tip.height} (${tip.hash.slice(0, 12)}…) after a minute: reference ${JSON.stringify([a.body?.height, a.body?.hash?.slice(0, 12)])}, indexer-rs ${JSON.stringify([b.body?.height, b.body?.hash?.slice(0, 12)])}`);
      console.log(errs.split('\n').slice(-12).join('\n'));
      if (unknown.size) console.log('Esplora routes asked and not served here:', [...unknown].join(' '));
      return false;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
}

// What to ask: every route, with the tokens, positions, listings, heights and transactions the chain has.
async function compareAll(groups) {
const tip = blocks.at(-1).height;
const status = (await get(P1, '/status')).body;
const tokens = (await get(P1, '/tokens')).body;
const listings = (await get(P1, '/listings')).body;
const txids = [...new Set(blocks.flatMap((b) => b.tx.map((t) => t.txid)))];
const routes = [
  '/status', '/tokens', ...tokens.map((t) => `/token/${t.ticker}`), '/token/ZZZZ',
  '/notes', '/notes?from=0&limit=5000', `/notes?from=${Math.max(0, status.leaves - 3)}`, '/notes?limit=x',
  '/path/0', `/path/${Math.max(0, status.leaves - 1)}`, `/path/${status.leaves}`,
  '/roots', '/roots?from=0', '/nullifiers', '/nullifiers?from=10',
  '/listings', '/listings?state=ACTIVE', '/listings?state=SOLD', '/listings?state=CLOSED', '/listings?state=CLAIMED', '/listings?state=NOPE',
  ...listings.map((l) => `/listing/${l.txid ?? l.listTxid}`), `/listing/${'00'.repeat(32)}`,
  ...blocks.map((b) => `/digest/${b.height}`), '/digest/0', `/digest/${tip + 1}`,
  '/blocks', '/blocks?limit=200', `/blocks?before=${Math.floor(tip / 2)}&limit=5`,
  ...blocks.map((b) => `/block/${b.height}`), '/block/0',
  ...txids.map((t) => `/tx/${t}`), '/tx/xyz', '/nope',
];

// Deep comparison: the JSON paths where the answers differ.
const diffs = (a, b, path = '', out = []) => {
  if (out.length > 200) return out;
  if (typeof a !== typeof b || Array.isArray(a) !== Array.isArray(b) || (a === null) !== (b === null)) {
    out.push(`${path || '.'}: reference ${short(a)}, indexer-rs ${short(b)}`);
  } else if (Array.isArray(a)) {
    if (a.length !== b.length) out.push(`${path}: ${a.length} items in the reference, ${b.length} in indexer-rs`);
    // items with a type (events) are named by it, so that one difference shows once per kind of event
    for (let i = 0; i < Math.min(a.length, b.length); i++) diffs(a[i], b[i], `${path}[${a[i]?.type ?? i}]`, out);
  } else if (a && typeof a === 'object') {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (k === 'implementation') continue;
      // free text: what an error or a refusal says is for people, only its presence is compared
      if ((k === 'error' || k === 'reason' || (k === 'rejected' && typeof a[k] === 'string')) && k in a && k in b && typeof a[k] === typeof b[k]) continue;
      if (!(k in a)) out.push(`${path}.${k}: only in indexer-rs (${short(b[k])})`);
      else if (!(k in b)) out.push(`${path}.${k}: only in the reference (${short(a[k])})`);
      else diffs(a[k], b[k], `${path}.${k}`, out);
    }
  } else if (a !== b) out.push(`${path || '.'}: reference ${short(a)}, indexer-rs ${short(b)}`);
  return out;
};
const short = (v) => {
  const s = JSON.stringify(v);
  return s === undefined ? 'undefined' : s.length > 70 ? s.slice(0, 67) + '…' : s;
};

// Group the routes by their shape (/tx/:txid…) so that one difference repeated over 300 transactions shows once.
for (const r of routes) {
  const [a, b] = [await get(P1, r), await get(P2, r)];
  const d = a.status !== b.status ? [`HTTP ${a.status} in the reference, ${b.status} in indexer-rs`] : diffs(a.body, b.body);
  const shape = r.replace(/[0-9a-f]{64}/g, ':txid').replace(/\/(token)\/[A-Z0-9]{4}/, '/$1/:ticker').replace(/\/(\d+)(?=$|\?)/, '/:n').replace(/=\d+/g, '=n');
  const g = groups.get(shape) ?? { asked: 0, differ: 0, lines: new Map() };
  g.asked++;
  if (d.length) {
    g.differ++;
    for (const line of d) {
      const key = line.replace(/\[\d+\]/g, '[]').replace(/: (reference|only in).*$/, '');
      if (!g.lines.has(key)) g.lines.set(key, line);
    }
  }
  groups.set(shape, g);
}
}

const groups = new Map();
let ok = await bothAtTip('the chain');
if (ok) await compareAll(groups);
if (ok && REORG_DEPTH > 0) {
  // The fork: the last REORG_DEPTH blocks give way to REORG_DEPTH + REORG_GROW others, made from another seed.
  const keep = blocks.length - REORG_DEPTH;
  const other = chain(`${SEED}/fork`, { blocks: BLOCKS + REORG_GROW, missingHeights: false }).map((b) => JSON.parse(blockJson(b)));
  serve([...blocks.slice(0, keep), ...other.slice(keep)]);
  ok = await bothAtTip(`the fork (${REORG_DEPTH} blocks replaced by ${REORG_DEPTH + REORG_GROW})`);
  if (ok) {
    const after = new Map();
    await compareAll(after);
    for (const [k, v] of after) groups.set(`after the reorg: ${k}`, v);
    // A reference that only ever saw the fork must end where both followers did.
    const { Indexer } = await import('../src/indexer.js');
    const { fromBitcoindBlock } = await import('../src/adapters/bitcoind.js');
    const { PROOF } = await import('./chain-gen.js');
    const fresh = new Indexer({ profile: { activationHeight: 1, deployBurn: 1000n, anchorWindow: 12, anchorMinDepth: 1, deployMaturity: 3 }, verifier: { name: 'test', verifySpend: (x) => Buffer.from(x.proof).equals(PROOF) } });
    for (const b of blocks) fresh.applyBlock(fromBitcoindBlock(b));
    const d = (await get(P1, '/status')).body.digest;
    if (fresh.digest.toString('hex') !== d) groups.set('after the reorg: a fresh reference', { asked: 1, differ: 1, lines: new Map([['x', `the followers end at ${d}, a reference that saw only the fork at ${fresh.digest.toString('hex')}`]]) });
  }
}
if (!ok) {
  stopAll();
  process.exit(1);
}
stopAll();

let differ = 0;
for (const [shape, g] of groups) {
  if (!g.differ) continue;
  differ++;
  console.log(`\n${shape}  (${g.differ} of ${g.asked} answers differ)`);
  for (const line of [...g.lines.values()].slice(0, SHOW)) console.log('  ' + line);
  if (g.lines.size > SHOW) console.log(`  … ${g.lines.size - SHOW} more`);
}
const asked = [...groups.values()].reduce((n, g) => n + g.asked, 0);
console.log(`\n${asked} requests in ${groups.size} shapes over a chain of ${blocks.length} blocks${REORG_DEPTH ? `, then a reorg of ${REORG_DEPTH} blocks into ${REORG_DEPTH + REORG_GROW}` : ''} (seed "${SEED}"): ${differ} shape(s) differ`);
if (unknown.size) console.log('Esplora routes asked and not served here:', [...unknown].join(' '));
process.exit(differ ? 1 : 0);
