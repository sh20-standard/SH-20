// Development only. Serves the repository root (open http://localhost:8000/vault/)
// and the indexer API on :8020 over the reference indexer fed with a small demo
// chain. When indexer/src/api.js exists (indexer-api branch) its real handler is
// used; otherwise a stand-in answers the four routes the vault reads, in the
// same shape (docs/API.md).
//
// It also mocks an Esplora server under :8020/esplora: one UTXO for any address,
// and POST /tx mines the transaction in the next block of the demo chain, so the
// whole mint flow can run without a real wallet or signet coins (see e2e.js).
//
//   node vault/dev/serve.js [--port 8000] [--api-port 8020]

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Indexer } from '../../indexer/src/indexer.js';
import { deployEnv, tx, opening } from '../../indexer/test/helpers.js';
import { extractEnvelope } from '../../indexer/src/carrier.js';
import { parseEnvelope } from '../../indexer/src/codec.js';
import { parseTx, txid as txidOf } from '../src/btc.js';
import { fromHex } from '../src/bytes.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const arg = (k, d) => (process.argv.includes(k) ? process.argv[process.argv.indexOf(k) + 1] : d);
const STATIC_PORT = Number(arg('--port', 8000));
const API_PORT = Number(arg('--api-port', 8020));
const real = await import('../../indexer/src/api.js').catch(() => null);

// Demo chain: genesis GENE (burn 1000 sats per mint), mint open from block 2, two mints.
const idx = new Indexer({ profile: { activationHeight: 1 } });
const notes = [];
// Public notes as the indexer API would list them: the event plus the opening read from the envelope.
const apply = (height, txs) => {
  const r = idx.applyBlock({ height, hash: `h${height}`, txs });
  for (const e of r.events) {
    if (e.type !== 'MINT') continue;
    const { env } = parseEnvelope(extractEnvelope(txs.find((t) => t.txid === e.txid)).bytes);
    notes.push({ ...e, height, npk: env.npk, rho: env.rho });
  }
  return r;
};
apply(1, [tx({ env: deployEnv({ ticker: 'GENE', start: 2, unlock: 2, price: 1000n, payMode: 1 }) })]);
const mintTx = () => tx({ env: { type: 'MINT', tokenNum: 1, ...opening() }, burnSats: 1000n });
apply(2, [mintTx(), mintTx()]);

const realApi = real ? real.apiHandler(idx, { network: 'signet' }) : null;
const json = (v) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 1);
const hex = (x) => x.toString(16).padStart(64, '0');

async function esplora(req, url, res) {
  const path = url.pathname.slice('/esplora'.length);
  const text = (code, v) => res.writeHead(code, { 'content-type': 'text/plain' }).end(String(v));
  if (path === '/blocks/tip/height') return text(200, idx.height);
  if (path === '/fee-estimates') return text(200, JSON.stringify({ 2: 1.5 }));
  if (/^\/address\/[^/]+\/utxo$/.test(path)) {
    return text(200, JSON.stringify([{ txid: '11'.repeat(32), vout: 0, value: 100000, status: { confirmed: true } }]));
  }
  if (path === '/tx' && req.method === 'POST') {
    let body = '';
    for await (const c of req) body += c;
    const t = parseTx(fromHex(body.trim()));
    const id = txidOf(t);
    const itx = {
      txid: id,
      vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
      vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
    };
    const r = apply(idx.height + 1, [itx]);
    console.log(`mined ${id} at ${r.height}: events ${json(r.events)} rejected ${json(r.rejected)}`);
    return text(200, id);
  }
  return text(404, 'not found');
}

createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('content-type', 'application/json');
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/esplora/')) {
    return esplora(req, url, res).catch((e) => res.writeHead(400, { 'content-type': 'text/plain' }).end(String(e.message)));
  }
  if (real) return realApi(req, res);
  const send = (code, v) => res.writeHead(code).end(json(v));
  if (url.pathname === '/status') {
    return send(200, { network: 'signet', height: idx.height, root: hex(idx.tree.root), digest: idx.digest.toString('hex'), leaves: idx.tree.size, verifier: idx.verifier.name });
  }
  if (url.pathname === '/tokens') return send(200, [...idx.tokens.values()]);
  const m = url.pathname.match(/^\/token\/([A-Z0-9]{4})$/);
  if (m) return idx.token(m[1]) ? send(200, idx.token(m[1])) : send(404, { error: 'unknown ticker' });
  if (url.pathname === '/notes') {
    const from = Number(url.searchParams.get('from') ?? 0);
    const limit = Math.min(Number(url.searchParams.get('limit') ?? 1000), 5000);
    const page = notes.slice(from, from + limit).map((n) => ({
      pos: n.pos, height: n.height, txid: n.txid, leaf: hex(idx.tree.leaves[n.pos]), kind: 'MINT', t: n.tokenNum, v: n.v, npk: hex(n.npk), rho: hex(n.rho),
    }));
    return send(200, { from, total: notes.length, notes: page });
  }
  send(404, { error: 'not found' });
}).listen(API_PORT, '127.0.0.1');

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(root, path);
  if (!file.startsWith(root)) return res.writeHead(403).end();
  if (file.endsWith('/')) file = join(file, 'index.html');
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(STATIC_PORT, '127.0.0.1');

console.log(`vault   http://localhost:${STATIC_PORT}/vault/`);
console.log(`${real ? 'indexer API (real handler)' : 'mock indexer API'} http://127.0.0.1:${API_PORT}, mock Esplora at /esplora (demo chain, height ${idx.height})`);
