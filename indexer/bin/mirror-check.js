#!/usr/bin/env node
// The site's mirror end to end, as pages.yml builds it (bin/mirror-site.js): a random chain served as an Esplora API,
// both followers from empty block files, both mirrors; every route the vault and the explorer read is then answered
// from each mirror (src/mirror-read.js) and compared with a reference indexer that applied the chain itself. Then the
// chain grows and a second run starts from the block files, as the next scheduled run does.
//
//   node bin/mirror-check.js --rs <sh20-indexer-rs> [--seed mirror] [--blocks 60] [--chrome <binary>]
//
// With --chrome, the site is then served as pages.yml lays it out (/explorer/ beside /api/js/ and /api/rs/) and the
// explorer is opened in that Chrome, headless: it must read both mirrors by itself and find them in agreement.
//
// The mirror of follow.js must give the reference's answers byte for byte; the mirror of indexer-rs the same JSON
// apart from `implementation` and the free text of refusals (docs/API.md). Exit 1 on any difference.

import { mkdtempSync, existsSync, readFileSync, readdirSync, copyFileSync, mkdirSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { chain, blockJson, PROOF } from './chain-gen.js';
import { fakeEsplora } from './esplora-fake.js';
import { mirrorSite } from './mirror-site.js';
import { options } from './options.js';
import { Indexer } from '../src/indexer.js';
import { listen } from '../src/api.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { mirrorGet } from '../src/mirror-read.js';

const USAGE = 'usage: node bin/mirror-check.js --rs <sh20-indexer-rs> [--seed mirror] [--blocks 60] [--chrome <binary>]';
const opt = options(process.argv.slice(2), ['rs', 'seed', 'blocks', 'chrome'], USAGE);
opt.require('rs');
const SEED = opt('seed', 'mirror');
const BLOCKS = opt.int('blocks', 60);
const PROFILE = ['--activation', '1', '--deploy-burn', '1000', '--window', '12', '--min-depth', '1', '--maturity', '3'];
const REF_PROFILE = { activationHeight: 1, deployBurn: 1000n, anchorWindow: 12, anchorMinDepth: 1, deployMaturity: 3, network: 'regtest' };

const all = chain(SEED, { blocks: BLOCKS + 8, missingHeights: false }).map((b) => JSON.parse(blockJson(b)));
const esplora = await fakeEsplora(all.slice(0, BLOCKS));
const work = mkdtempSync(join(tmpdir(), 'sh20-mirror-check-'));
const data = join(work, 'data');
const out = join(work, 'site', 'api');
const quiet = process.env.SH20_VERBOSE ? console.error : () => {};

const read = (dir) => async (name) => {
  const path = join(dir, name);
  if (!existsSync(path)) throw Object.assign(new Error(`${name}: not in the mirror`), { status: 404 });
  return JSON.parse(readFileSync(path, 'utf8'));
};
const answer = async (route, get) => {
  try {
    return { status: 200, body: await get(route) };
  } catch (e) {
    if (e.status === 404 || e.status === 400) return { status: e.status, body: null };
    throw e;
  }
};
// What two implementations may say differently: their name, and the words of a refusal.
const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (k === 'implementation' || k === 'reason' ? '…' : k === 'rejected' && typeof x === 'string' ? '…' : x)));

async function check(label, blocks) {
  const ix = new Indexer({ profile: REF_PROFILE, verifier: { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) } });
  for (const b of blocks) ix.applyBlock(fromBitcoindBlock(b));
  const server = await listen(ix, { port: 0, host: '127.0.0.1', network: 'regtest' });
  const api = `http://127.0.0.1:${server.address().port}`;
  const live = async (route) => {
    const r = await fetch(api + route);
    if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status });
    return r.json();
  };
  const s = await live('/status');
  const tip = s.height;
  const listed = await live('/blocks?limit=200');
  const txids = [...new Set(listed.flatMap((b) => [...b.events, ...b.rejected].map((e) => e.txid).filter(Boolean)))];
  const routes = [
    '/status', '/tokens', '/listings', '/roots', '/nullifiers', '/notes', '/blocks', '/blocks?limit=200',
    ...(await live('/tokens')).map((t) => `/token/${t.ticker}`), '/token/ZZZZ',
    ...['ACTIVE', 'SOLD', 'CANCELLED', 'CLOSED', 'CLAIMED'].map((x) => `/listings?state=${x}`),
    ...(await live('/listings')).map((l) => `/listing/${l.listTxid}`),
    `/roots?from=${tip - 12}`, `/roots?from=${tip - 30}`, '/nullifiers?from=10',
    ...(await live('/nullifiers')).nullifiers.slice(0, 5).map((n) => `/nullifier/${n.nullifier}`),
    '/notes?from=0&limit=1000', `/notes?from=${Math.max(0, s.leaves - 5)}&limit=1000`, '/notes?from=0&limit=5000',
    `/blocks?before=${Math.floor(tip / 2)}&limit=5`,
    ...Array.from({ length: tip + 1 }, (_, h) => `/block/${h}`), ...Array.from({ length: tip + 1 }, (_, h) => `/digest/${h}`),
    ...txids.map((id) => `/tx/${id}`),
  ];
  let differ = 0;
  for (const name of ['js', 'rs']) {
    const get = read(join(out, name));
    for (const route of routes) {
      const want = await answer(route, live);
      const got = await answer(route, (r) => mirrorGet(r, get));
      const same = name === 'js' ? isDeepStrictEqual(got, want) : isDeepStrictEqual(plain(got), plain(want));
      if (!same) {
        differ++;
        if (differ <= 10) console.log(`${label}, mirror ${name}, ${route}: ${JSON.stringify(got).slice(0, 200)} instead of ${JSON.stringify(want).slice(0, 200)}`);
      }
    }
  }
  server.close();
  const files = ['js', 'rs'].map((n) => readdirSync(join(out, n, 'block')).length);
  console.log(`${label}: block ${tip}, ${routes.length} routes asked of each mirror (${files.join(' and ')} block files), ${differ} difference(s)`);
  return differ;
}

// The site as pages.yml lays it out, served from a folder; the explorer opened in headless Chrome, its DOM read back.
async function explorer(chromePath, tip) {
  const site = join(work, 'site');
  mkdirSync(join(site, 'explorer'), { recursive: true });
  copyFileSync(fileURLToPath(new URL('../../explorer/index.html', import.meta.url)), join(site, 'explorer', 'index.html'));
  const types = { '.html': 'text/html; charset=utf-8', '.json': 'application/json' };
  const server = createServer((req, res) => {
    let path = join(site, decodeURIComponent(new URL(req.url, 'http://x').pathname));
    if (existsSync(path) && statSync(path).isDirectory()) path = join(path, 'index.html');
    if (!path.startsWith(site) || !existsSync(path)) return res.writeHead(404, { 'content-type': 'text/html' }).end('<h1>404</h1>');
    res.writeHead(200, { 'content-type': types[path.slice(path.lastIndexOf('.'))] ?? 'application/octet-stream' }).end(readFileSync(path));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/explorer/`;
  try {
    const profile = mkdtempSync(join(tmpdir(), 'sh20-chrome-'));
    const { stdout } = await promisify(execFile)(chromePath, [
      '--headless=new', '--disable-gpu', '--no-first-run', `--user-data-dir=${profile}`, '--virtual-time-budget=15000', '--dump-dom', url,
    ], { maxBuffer: 1 << 26, timeout: 60_000 });
    const dom = stdout.replace(/<script[\s\S]*?<\/script>/g, ''); // what the page shows, not the code that shows it
    const want = [
      ["the site's copy of both indexers", /Reading this site's copy of both indexers, as of block/],
      [`block ${tip}`, new RegExp(`as of block ${tip.toLocaleString('en-US')}`)],
      ['both mirrors agree', /2 of 2 agree/],
      ['not the demo data', /^(?![\s\S]*<b>Demo data\.<\/b>)/],
    ];
    if (process.env.SH20_VERBOSE) console.error(dom.match(/<div id="notices">[\s\S]*?<\/div><\/div>/)?.[0] ?? '(no notices)', dom.match(/\d+ of \d+ agree/)?.[0]);
    const missing = want.filter(([, re]) => !re.test(dom)).map(([what]) => what);
    console.log(`explorer on the site (${url}): ${missing.length ? `missing ${missing.join(', ')}` : 'reads both mirrors, which agree'}`);
    return missing.length;
  } finally {
    server.close();
  }
}

let differ = 0;
const run = (label) => mirrorSite({ esplora: esplora.url, rs: opt('rs'), profile: PROFILE, network: 'regtest', verifierJs: 'test', verifierRs: 'test', data, out, waitMs: 120_000, log: quiet });
try {
  await run('first run');
  differ += await check('first run, from empty block files', all.slice(0, BLOCKS));
  const before = esplora.asked.get('/block/:hash') ?? 0;
  esplora.serve(all);
  await run('second run');
  const fetched = (esplora.asked.get('/block/:hash') ?? 0) - before;
  differ += await check('second run, from the block files', all);
  if (opt('chrome') !== undefined) differ += await explorer(opt('chrome'), all.at(-1).height);
  // each follower fetches only the 8 new blocks: the rest comes from its block file
  if (fetched !== 16) {
    differ++;
    console.log(`second run: the followers fetched ${fetched} block headers, not 2 × 8`);
  }
} finally {
  esplora.close();
}
process.exit(differ ? 1 : 0);
