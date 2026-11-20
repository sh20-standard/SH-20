// Development only. Serves the repository root (open http://localhost:8000/vault/)
// and the real indexer API (indexer/src/api.js) on :8020 and again on :8030 (two
// agreeing indexers), over the reference indexer fed with a small demo chain.
// :8031 is a lying indexer: same answers, except its own payScript for every token.
//
// The profile is the reference one (D = 1000: a DEPLOY burns SH20 with a proof), so
// the demo chain has only the genesis token SH20 and two mints of it. With
// --deploy-burn 0 it also deploys GENE (a proof-less DEPLOY, 1000 sats burned per mint).
//
// It also mocks an Esplora server under :8020/esplora: one UTXO for any address,
// raw transactions and their status, and POST /tx mines the transaction in the
// next block of the demo chain, so the whole mint flow runs without a real
// wallet or signet coins (see e2e.js).
//
//   node vault/dev/serve.js [--port 8000] [--api-port 8020] [--api-port2 8030] [--liar-port 8031] [--deploy-burn 1000] [--isolate]
//
// Spends are verified with the real PLONK verifier (vault/prover/sh20_circuit.wasm). --isolate sends
// the cross-origin isolation headers, so the page gets shared memory and proves on a thread pool;
// without it the page is not isolated and proves on one thread, as from an IPFS gateway.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
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

const DEPLOY_BURN = BigInt(arg('--deploy-burn', '1000'));

// spends are checked with the pinned PLONK verifier, from the vault's own single-thread module
const verifier = plonkVerifier({ wasm: new Uint8Array(readFileSync(new URL('../prover/sh20_circuit.wasm', import.meta.url))) });
const ISOLATE = process.argv.includes('--isolate'); // COOP/COEP: shared memory, so the prover's thread pool
const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: DEPLOY_BURN }, verifier });
const api = apiHandler(idx, { network: 'signet' });
const chainTxs = new Map(); // txid -> { hex, height }

// Applies real, serialised transactions, so Esplora can serve them back. Each input spending a
// transaction of this chain gets its height as prevHeight, which a DEPLOY's input 0 needs (SPEC-WIRE §5,
// DEPLOY maturity; a real indexer reads it from getblock verbosity 3 or Esplora). `prevHeights` sets it
// for inputs the demo chain did not mine (the fixtures).
function mine(txs, prevHeights = []) {
  const height = (idx.height ?? 0) + 1;
  const itxs = txs.map((t, k) => {
    const id = txidOf(t);
    chainTxs.set(id, { hex: toHex(serializeTx(t)), height });
    return {
      txid: id,
      vin: t.vin.map((i, j) => {
        const prev = chainTxs.get(i.txid)?.height ?? (j === 0 ? prevHeights[k] : undefined);
        return { txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)), ...(prev !== undefined ? { prevHeight: prev } : {}) };
      }),
      vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
    };
  });
  return idx.applyBlock({ height, hash: `h${height}`, txs: itxs });
}

let n = 0;
/** The DEPLOY of the demo: a reveal in the witness (never an OP_RETURN, SPEC-WIRE §5), of a fixture commit. */
const deployTx = (env) => {
  const bytes = serializeEnvelope(env);
  const script = Buffer.concat([Buffer.from([0x20]), Buffer.alloc(32, 7), Buffer.from([0xac, 0x00, 0x63, 0x04]), bytes.subarray(0, 4),
    ...chunks(bytes.subarray(4)).map((c) => Buffer.concat([pushOf(c), c])), Buffer.from([0x68])]);
  return {
    version: 2, locktime: 0,
    vin: [{ txid: (++n).toString(16).padStart(64, '0'), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(64), script, Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(32, 9)])] }],
    vout: [{ value: 330n, script: Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 3)]) }],
  };
};
const chunks = (b) => Array.from({ length: Math.ceil(b.length / 520) }, (_, i) => b.subarray(520 * i, 520 * (i + 1)));
const pushOf = (c) => (c.length <= 75 ? Buffer.from([c.length]) : c.length <= 255 ? Buffer.from([0x4c, c.length]) : Buffer.from([0x4d, c.length & 0xff, c.length >> 8]));
const envTx = (env, value = 0n) => ({
  version: 2, locktime: 0,
  vin: [{ txid: (++n).toString(16).padStart(64, '0'), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(64)] }],
  vout: [{ value, script: opReturnScript(serializeEnvelope(env)) }],
});

// Demo chain: SH20 from block 1 (free mint), two mints of it; with D = 0, GENE too
// (burn 1000 sats per mint, open from block 2) and two mints of it.
const D0 = DEPLOY_BURN === 0n;
// the GENE fixture's commit counts as confirmed N blocks before block 1 (the demo chain starts there)
mine(D0 ? [deployTx(deployEnv({ ticker: 'GENE', start: 2, unlock: 2, price: 1000n, payMode: 1 }))] : [], [1 - idx.profile.deployMaturity]);
mine([
  ...[0, 1].map(() => envTx({ type: 'MINT', ticker: 'SH20', ...opening() })),
  ...(D0 ? [0, 1].map(() => envTx({ type: 'MINT', ticker: 'GENE', ...opening() }, 1000n)) : []),
]);

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
  // development only: time passes. POST /esplora/mine?n=6 mines n empty blocks (a DEPLOY's commit matures)
  if (path === '/mine' && req.method === 'POST') {
    const count = Math.min(100, Number(new URL(req.url, 'http://x').searchParams.get('n')) || 1);
    for (let i = 0; i < count; i++) mine([]);
    return text(200, idx.height);
  }
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

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm' };
const ISOLATION = ISOLATE ? { 'cross-origin-opener-policy': 'same-origin', 'cross-origin-embedder-policy': 'require-corp' } : {};
createServer(async (req, res) => {
  // /ipfs/<cid>/… is served like a path gateway would (the same files), to check the page never
  // registers its service worker there; <cid>.ipfs.localhost:<port> is a subdomain gateway
  const pathname = new URL(req.url, 'http://x').pathname.replace(/^\/ip[fn]s\/[^/]+(?=\/)/, '');
  // the site's root sw.js (build.js puts vault/sw.js there): the repository root has none
  const path = pathname === '/sw.js' ? '/vault/sw.js' : normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(root, path);
  if (!file.startsWith(root)) return res.writeHead(403).end();
  if (file.endsWith('/')) file = join(file, 'index.html');
  let body;
  try {
    body = await readFile(file);
  } catch {
    return res.writeHead(404).end('not found');
  }
  res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream', ...ISOLATION }).end(body);
}).listen(STATIC_PORT, '127.0.0.1');

console.log(`vault http://localhost:${STATIC_PORT}/vault/`);
console.log(`indexer API http://127.0.0.1:${API_PORT} and :${API_PORT2}, lying indexer :${LIAR_PORT}, mock Esplora at /esplora (demo chain, height ${idx.height}, D = ${DEPLOY_BURN})`);
