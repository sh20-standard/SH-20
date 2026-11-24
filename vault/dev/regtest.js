// Development and CI only: the vault on a real Bitcoin Core regtest chain. Bitcoin Core checks every
// transaction the page and its wallet sign (scripts, signatures, standardness, fees); two reference
// indexers follow the chain over RPC, as indexer/bin/follow.js does, with the real PLONK verifier.
//
//   node vault/dev/regtest.js [--isolate] [--mirror] [--bitcoind <path>]   then   E2E_CHAIN=regtest node vault/dev/e2e.js
//
//   :8000            the repository root (open http://localhost:8000/vault/)
//   :8020, :8030     two indexers (indexer/src/api.js), each following the chain on its own
//   :8020/esplora    an Esplora API over Bitcoin Core's RPC, what the page needs of it: tip, fee
//                    estimates, an address's UTXOs, a transaction, its status and outspends, broadcast.
//                    A broadcast is mined at once, in a block of its own; POST /esplora/mine?n=N mines N
//                    empty blocks (time passes: a DEPLOY's commit matures).
//
// --mirror: the page reads static mirrors instead (docs/API.md, "The static mirror"), as on the site.
//   :8000/api/js/, :8000/api/rs/   indexer/bin/mirror.js of :8020 and of :8030, written again after every
//                    block (before a broadcast's answer returns, so the page reads the new tip), served as
//                    files; and the live indexers refuse any request a page makes (one with an Origin):
//                    only Esplora is read live. Run E2E_MIRROR=1 node vault/dev/e2e.js against it.
//
// The chain starts at the test profile's activation height (vault/src/profile.js PROFILES.test,
// block 0): the genesis token SH20 is open from there. The wallet of dev/test-wallet.js gets ten
// coinbases, matured by 100 blocks. bitcoind comes from vault/tools/bitcoind.sh (a pinned release,
// its SHA-256 checked) unless --bitcoind names one; its data lives in a temporary folder, removed on exit.

import { spawn, execFile, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Indexer } from '../../indexer/src/indexer.js';
import { BitcoindSource, Follower } from '../../indexer/src/follower.js';
import { apiHandler } from '../../indexer/src/api.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { PROFILES } from '../src/profile.js';
import { addressToScript } from '../src/btc.js';
import { toHex } from '../src/bytes.js';
import { staticServer } from './static.js';
import { WALLET } from './test-wallet.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const arg = (k, d) => (process.argv.includes(k) ? process.argv[process.argv.indexOf(k) + 1] : d);
const RPC_PORT = Number(arg('--rpc-port', 18543));
const PORTS = [8020, 8030];
const A = PROFILES.test.activationHeight;
const BURN = 'raw(51)'; // OP_TRUE: where the blocks that only pass time pay their coinbase
const MIRROR = process.argv.includes('--mirror');

const BITCOIND = arg('--bitcoind', null) ?? execFileSync(join(here, '..', 'tools', 'bitcoind.sh')).toString().trim();
const datadir = mkdtempSync(join(tmpdir(), 'sh20-regtest-'));
const node = spawn(BITCOIND, [
  '-regtest', `-datadir=${datadir}`, '-server', '-listen=0', '-disablewallet', '-txindex',
  `-rpcport=${RPC_PORT}`, '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-rpcuser=sh20', '-rpcpassword=sh20',
  '-acceptnonstdtxn=0', // the network's relay policy, not regtest's leniency: a non-standard transaction is refused
  '-printtoconsole=0',
], { stdio: 'inherit' });
let stopping = false;
const stop = (code = 0) => {
  if (stopping) return;
  stopping = true;
  node.once('exit', () => {
    rmSync(datadir, { recursive: true, force: true });
    process.exit(code);
  });
  node.kill('SIGTERM');
};
process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
node.on('exit', (c) => {
  if (!stopping) {
    console.error(`bitcoind exited (${c})`);
    rmSync(datadir, { recursive: true, force: true });
    process.exit(1);
  }
});

const source = new BitcoindSource(`http://127.0.0.1:${RPC_PORT}`, { user: 'sh20', pass: 'sh20' });
const rpc = (m, p) => source.rpc(m, p);
for (let i = 0; ; i++) {
  try {
    await rpc('getblockcount');
    break;
  } catch (e) {
    if (i > 100) throw new Error(`bitcoind did not answer: ${e.message}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}
const descriptor = async (d) => (await rpc('getdescriptorinfo', [d])).descriptor;
const burnTo = await descriptor(BURN);
await rpc('generatetodescriptor', [10, await descriptor(`raw(${toHex(WALLET.script)})`)]);
await rpc('generatetodescriptor', [100, burnTo]);

// two indexers, each its own state and follower, as two operators would run them
const verifier = plonkVerifier({ wasm: new Uint8Array(readFileSync(new URL('../prover/sh20_circuit.wasm', import.meta.url))) });
const indexers = PORTS.map(() => {
  const indexer = new Indexer({ profile: { activationHeight: A, network: PROFILES.test.network }, verifier });
  const follower = new Follower({
    indexer, source, startHeight: A,
    log: (r) => {
      if (r.error) console.error(`indexer: ${r.error}`);
      else if (r.events?.length || r.rejected?.length) console.log(`block ${r.height}: events ${JSON.stringify(r.events.map((e) => e.type ?? e.kind ?? e))} rejected ${JSON.stringify(r.rejected)}`);
    },
  });
  return { indexer, follower };
});
// --mirror: each indexer's mirror, written again by indexer/bin/mirror.js when its tip has moved
const site = join(datadir, 'site', 'api');
const mirrorOf = PORTS.map((port, k) => ({ api: `http://127.0.0.1:${port}`, out: join(site, ['js', 'rs'][k]), tip: null }));
let serving = false; // the mirrors are read from the indexers' HTTP API, once it listens
async function mirrors() {
  for (const m of mirrorOf) {
    const { height, digest } = await (await fetch(`${m.api}/status`)).json();
    if (m.tip === `${height}:${digest}`) continue;
    await new Promise((resolve, reject) => execFile(process.execPath, [join(root, 'indexer', 'bin', 'mirror.js'), '--api', m.api, '--out', m.out], (e, out, err) => (e ? reject(new Error(`mirror.js: ${err || e.message}`)) : resolve(out))));
    m.tip = `${height}:${digest}`;
  }
}

let following = Promise.resolve(); // one step at a time: a step that overlapped another would apply a block twice
const follow = () => (following = following.catch(() => {}).then(async () => {
  for (const { follower } of indexers) await follower.step();
  if (MIRROR && serving) await mirrors();
}));
await follow();

// ---- Esplora over RPC -------------------------------------------------------------------------

const spentBy = new Map(); // "txid:vout" -> the transaction that spent it, for /outspend
let scanned = -1;
async function scanSpends() {
  const tip = await rpc('getblockcount');
  for (; scanned < tip; ) {
    const b = await rpc('getblock', [await rpc('getblockhash', [scanned + 1]), 2]);
    for (const t of b.tx) for (const i of t.vin) if (i.txid) spentBy.set(`${i.txid}:${i.vout}`, t.txid);
    scanned++;
  }
}
const mine = async (n) => {
  await rpc('generatetodescriptor', [n, burnTo]);
  await follow();
  return rpc('getblockcount');
};
const json = (v) => JSON.stringify(v);

async function esplora(req, path, res) {
  const text = (code, v) => res.writeHead(code, { 'content-type': 'text/plain', 'access-control-allow-origin': '*' }).end(String(v));
  if (path === '/blocks/tip/height') return text(200, await rpc('getblockcount'));
  if (path === '/fee-estimates') return text(200, json({ 2: 1.5 })); // an empty regtest mempool has no estimate
  let m = path.match(/^\/address\/([^/]+)\/utxo$/);
  if (m) {
    const tip = await rpc('getblockcount');
    const scan = await rpc('scantxoutset', ['start', [`raw(${toHex(addressToScript(decodeURIComponent(m[1])))})`]]);
    const spendable = scan.unspents.filter((u) => !u.coinbase || tip - u.height + 1 >= 100);
    return text(200, json(spendable.map((u) => ({ txid: u.txid, vout: u.vout, value: Math.round(u.amount * 1e8), status: { confirmed: true, block_height: u.height } }))));
  }
  m = path.match(/^\/tx\/([0-9a-f]{64})\/hex$/);
  if (m) {
    try {
      return text(200, await rpc('getrawtransaction', [m[1], false]));
    } catch {
      return text(404, 'Transaction not found');
    }
  }
  m = path.match(/^\/tx\/([0-9a-f]{64})\/status$/);
  if (m) {
    let t;
    try {
      t = await rpc('getrawtransaction', [m[1], true]);
    } catch {
      return text(404, 'Transaction not found');
    }
    if (!t.blockhash) return text(200, json({ confirmed: false }));
    const header = await rpc('getblockheader', [t.blockhash]);
    return text(200, json({ confirmed: true, block_height: header.height, block_hash: t.blockhash }));
  }
  m = path.match(/^\/tx\/([0-9a-f]{64})\/outspend\/(\d+)$/);
  if (m) {
    await scanSpends();
    const by = spentBy.get(`${m[1]}:${m[2]}`);
    return text(200, json(by ? { spent: true, txid: by, vin: 0, status: { confirmed: true } } : { spent: false }));
  }
  if (path === '/mine' && req.method === 'POST') {
    const n = Math.min(100, Number(new URL(req.url, 'http://x').searchParams.get('n')) || 1);
    return text(200, await mine(n));
  }
  if (path === '/tx' && req.method === 'POST') {
    let body = '';
    for await (const c of req) body += c;
    let id;
    try {
      id = await rpc('sendrawtransaction', [body.trim()]);
    } catch (e) {
      console.error(`refused by Bitcoin Core: ${e.message}`);
      return text(400, `sendrawtransaction RPC error: ${e.message}`);
    }
    const height = await mine(1);
    console.log(`mined ${id} in block ${height}`);
    return text(200, id);
  }
  return text(404, 'not found');
}

const serve = (handler) => (req, res) => {
  const { pathname } = new URL(req.url, 'http://x');
  if (pathname.startsWith('/esplora/')) {
    return esplora(req, pathname.slice('/esplora'.length), res).catch((e) => res.writeHead(500).end(String(e.message)));
  }
  // --mirror: a page reads the mirrors, never the live indexer (the tools here send no Origin)
  if (MIRROR && req.headers.origin) {
    console.error(`refused a page's ${pathname}: with --mirror the page reads /api/js/ and /api/rs/`);
    return res.writeHead(403, { 'access-control-allow-origin': '*', 'content-type': 'application/json' }).end(JSON.stringify({ error: 'regtest.js --mirror: read the mirror' }));
  }
  return handler(req, res);
};
const servers = indexers.map(({ indexer }, k) => createServer(serve(apiHandler(indexer))).listen(PORTS[k], '127.0.0.1'));
servers.push(staticServer({ root, isolate: process.argv.includes('--isolate'), mounts: MIRROR ? { '/api/': site } : {} }).listen(8000, '127.0.0.1'));
if (MIRROR) {
  serving = true;
  await follow();
}
// blocks the page did not cause (none here, but a follower must not depend on it)
const timer = setInterval(() => follow().catch((e) => console.error(e.message)), 2000);
process.on('exit', () => clearInterval(timer));

console.log(`vault http://localhost:8000/vault/ on Bitcoin Core regtest (${(await rpc('getnetworkinfo')).subversion}), height ${await rpc('getblockcount')}`);
console.log(`indexers http://127.0.0.1:${PORTS.join(' and :')}, Esplora at /esplora; wallet ${WALLET.address}`);
if (MIRROR) console.log('their mirrors at http://localhost:8000/api/js/ and /api/rs/, written again after every block; the live indexers refuse the page');
