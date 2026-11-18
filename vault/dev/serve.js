// Development only. Serves the repository root (open http://localhost:8000/vault/)
// and the real indexer API (indexer/src/api.js) on :8020 and again on :8030 (two
// agreeing indexers), over the reference indexer fed with a small demo chain.
// :8031 is a lying indexer: same answers, except its own payScript for every token.
//
// It also mocks an Esplora server under :8020/esplora: one UTXO for any address,
// raw transactions and their status, and POST /tx mines the transaction in the
// next block of the demo chain, so the whole mint flow runs without a real
// wallet or signet coins (see e2e.js).
//
//   node vault/dev/serve.js [--port 8000] [--api-port 8020] [--api-port2 8030] [--liar-port 8031]

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Indexer } from '../../indexer/src/indexer.js';
import { apiHandler } from '../../indexer/src/api.js';
import { serializeEnvelope } from '../../indexer/src/codec.js';
import { deployEnv, opening } from '../../indexer/test/helpers.js';
import { parseTx, serializeTx, txid as txidOf, opReturnScript } from '../src/btc.js';
import { fromHex, toHex } from '../src/bytes.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const arg = (k, d) => (process.argv.includes(k) ? process.argv[process.argv.indexOf(k) + 1] : d);
const STATIC_PORT = Number(arg('--port', 8000));
const API_PORT = Number(arg('--api-port', 8020));
const API_PORT2 = Number(arg('--api-port2', 8030)); // a second, agreeing indexer
const LIAR_PORT = Number(arg('--liar-port', 8031)); // a lying indexer

const idx = new Indexer({ profile: { activationHeight: 1 } });
const api = apiHandler(idx, { network: 'signet' });
const chainTxs = new Map(); // txid -> { hex, height }

// Applies real, serialised transactions, so Esplora can serve them back.
function mine(txs) {
  const height = (idx.height ?? 0) + 1;
  const itxs = txs.map((t) => {
    const id = txidOf(t);
    chainTxs.set(id, { hex: toHex(serializeTx(t)), height });
    return {
      txid: id,
      vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
      vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
    };
  });
  return idx.applyBlock({ height, hash: `h${height}`, txs: itxs });
}

let n = 0;
const envTx = (env, value = 0n) => ({
  version: 2, locktime: 0,
  vin: [{ txid: (++n).toString(16).padStart(64, '0'), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(64)] }],
  vout: [{ value, script: opReturnScript(serializeEnvelope(env)) }],
});

// Demo chain: genesis GENE (burn 1000 sats per mint), mint open from block 2, two mints.
mine([envTx(deployEnv({ ticker: 'GENE', start: 2, unlock: 2, price: 1000n, payMode: 1 }))]);
mine([0, 1].map(() => envTx({ type: 'MINT', ticker: 'GENE', ...opening() }, 1000n)));

const json = (v) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x));

async function esplora(req, path, res) {
  const text = (code, v) => res.writeHead(code, { 'content-type': 'text/plain', 'access-control-allow-origin': '*' }).end(String(v));
  if (path === '/blocks/tip/height') return text(200, idx.height);
  if (path === '/fee-estimates') return text(200, json({ 2: 1.5 }));
  if (/^\/address\/[^/]+\/utxo$/.test(path)) return text(200, json([{ txid: '11'.repeat(32), vout: 0, value: 100000, status: { confirmed: true } }]));
  let m = path.match(/^\/tx\/([0-9a-f]{64})\/hex$/);
  if (m) return chainTxs.has(m[1]) ? text(200, chainTxs.get(m[1]).hex) : text(404, 'not found');
  m = path.match(/^\/tx\/([0-9a-f]{64})\/status$/);
  if (m) return text(200, json(chainTxs.has(m[1]) ? { confirmed: true, block_height: chainTxs.get(m[1]).height } : { confirmed: false }));
  if (path === '/tx' && req.method === 'POST') {
    let body = '';
    for await (const c of req) body += c;
    const r = mine([parseTx(fromHex(body.trim()))]);
    console.log(`mined block ${r.height}: events ${json(r.events)} rejected ${json(r.rejected)}`);
    return text(200, r.events[0]?.txid ?? txidOf(parseTx(fromHex(body.trim()))));
  }
  return text(404, 'not found');
}

const serveApi = (handler) => (req, res) => {
  const { pathname } = new URL(req.url, 'http://x');
  if (pathname.startsWith('/esplora/')) {
    return esplora(req, pathname.slice('/esplora'.length), res).catch((e) => res.writeHead(400).end(String(e.message)));
  }
  return handler(req, res);
};

// Rewrites payScript in token answers, as a dishonest indexer would.
const ATTACKER = '0014' + 'ee'.repeat(20);
const liar = (req, res) => {
  const fake = {
    writeHead: (code, headers) => { fake.code = code; fake.headers = headers; return fake; },
    end(body) {
      let out = body;
      if (/^\/tokens?(\/|$)/.test(new URL(req.url, 'http://x').pathname) && fake.code === 200) {
        const j = JSON.parse(body);
        const lie = (t) => ({ ...t, payMode: 2, payScript: ATTACKER });
        out = JSON.stringify(Array.isArray(j) ? j.map(lie) : lie(j));
      }
      res.writeHead(fake.code, fake.headers).end(out);
    },
  };
  api(req, fake);
};

createServer(serveApi(api)).listen(API_PORT, '127.0.0.1');
createServer(serveApi(api)).listen(API_PORT2, '127.0.0.1');
createServer(serveApi(liar)).listen(LIAR_PORT, '127.0.0.1');

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(root, path);
  if (!file.startsWith(root)) return res.writeHead(403).end();
  if (file.endsWith('/')) file = join(file, 'index.html');
  let body;
  try {
    body = await readFile(file);
  } catch {
    return res.writeHead(404).end('not found');
  }
  res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(body);
}).listen(STATIC_PORT, '127.0.0.1');

console.log(`vault http://localhost:${STATIC_PORT}/vault/`);
console.log(`indexer API http://127.0.0.1:${API_PORT} and :${API_PORT2}, lying indexer :${LIAR_PORT}, mock Esplora at /esplora (demo chain, height ${idx.height})`);
