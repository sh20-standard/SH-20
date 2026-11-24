// Building the static mirror of the API (docs/API.md, "The static mirror"): the answers of a running indexer, either
// implementation, written as files any static host serves with no query string. Each file holds the bytes the indexer
// sent, so the mirror of an indexer says exactly what that indexer says; src/mirror-read.js answers the API's routes
// from them.

import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { MIRROR_FORMAT, MIRROR_NOTE_PAGE, MIRROR_BLOCK_PAGE } from './mirror-read.js';

async function fetchText(api, route) {
  const r = await fetch(api + route);
  if (!r.ok) throw Object.assign(new Error(`${api}${route}: HTTP ${r.status}`), { status: r.status });
  return r.text();
}

// Runs `jobs` (functions returning promises) with at most `n` at a time.
async function pool(jobs, n) {
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) await jobs[next++]();
  };
  await Promise.all(Array.from({ length: Math.min(n, jobs.length) }, worker));
}

/**
 * Reads every route of the API at `api` and writes the mirror into `out` (replaced whole, through a sibling folder,
 * so that `out` holds one mirror or the other, never a mix). The indexer may follow a chain meanwhile: the mirror is
 * kept only if `/status` names the same tip and digest after the last file as before the first; otherwise it starts
 * again, `tries` times at most.
 *
 * @returns {Promise<{height: number|null, digest: string, files: number, bytes: number}>}
 */
export async function buildMirror({ api, out, notePage = MIRROR_NOTE_PAGE, blockPage = MIRROR_BLOCK_PAGE, concurrency = 16, tries = 5, now = () => new Date() }) {
  api = api.replace(/\/+$/, '');
  // the API's own caps: a larger page would be cut short by the indexer
  if (!(Number.isInteger(notePage) && notePage >= 1 && notePage <= 5000)) throw new Error(`notePage ${notePage}: 1 to 5000`);
  if (!(Number.isInteger(blockPage) && blockPage >= 1 && blockPage <= 200)) throw new Error(`blockPage ${blockPage}: 1 to 200`);
  for (let attempt = 1; attempt <= tries; attempt++) {
    const files = new Map();
    const take = async (name, route) => {
      const text = await fetchText(api, route);
      files.set(name, text);
      return JSON.parse(text);
    };
    const status = await take('status.json', '/status');
    const [tokens, listings] = await Promise.all([
      take('tokens.json', '/tokens'),
      take('listings.json', '/listings'),
      take('roots.json', '/roots'),
      take('nullifiers.json', '/nullifiers'),
      take('blocks.json', `/blocks?limit=${blockPage}`),
    ]);
    const jobs = [];
    const job = (name, route, then) => jobs.push(async () => {
      const j = await take(name, route);
      if (then) then(j);
    });
    for (const t of tokens) job(`token/${t.ticker}.json`, `/token/${t.ticker}`);
    for (const l of listings) job(`listing/${l.listTxid}.json`, `/listing/${l.listTxid}`);
    const pages = Math.max(1, Math.ceil(status.leaves / notePage));
    for (let k = 0; k < pages; k++) job(`notes/${k}.json`, `/notes?from=${k * notePage}&limit=${notePage}`);
    const txids = new Set();
    if (status.height !== null) {
      for (let h = status.activationHeight; h <= status.height; h++) {
        job(`digest/${h}.json`, `/digest/${h}`);
        job(`block/${h}.json`, `/block/${h}`, (b) => {
          for (const e of [...b.events, ...b.rejected]) if (e.txid) txids.add(e.txid);
        });
      }
    }
    await pool(jobs, concurrency);
    await pool([...txids].sort().map((id) => () => take(`tx/${id}.json`, `/tx/${id}`)), concurrency);

    const after = JSON.parse(await fetchText(api, '/status'));
    if (after.hash !== status.hash || after.digest !== status.digest) continue;

    const { implementation, network, activationHeight, height, hash, digest } = status;
    files.set('mirror.json', JSON.stringify({
      format: MIRROR_FORMAT, built: now().toISOString(), implementation, network, activationHeight, height, hash, digest,
      notePage, blockPage,
    }) + '\n');
    const tmp = `${out.replace(/\/+$/, '')}.building-${process.pid}`;
    rmSync(tmp, { recursive: true, force: true });
    let bytes = 0;
    for (const [name, text] of files) {
      const path = join(tmp, name);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text);
      bytes += Buffer.byteLength(text);
    }
    rmSync(out, { recursive: true, force: true });
    mkdirSync(dirname(out), { recursive: true });
    renameSync(tmp, out);
    return { height, digest, files: files.size, bytes };
  }
  throw new Error(`${api}: the tip moved during each of ${tries} attempts`);
}

/**
 * Waits until the indexer at `api` has the tip that the Esplora server at `esplora` names, polling every `everyMs`;
 * rejects after `timeoutMs`. A follower started from its block file catches up meanwhile. Before the chain reaches
 * the activation height there is nothing to follow: an indexer with no block yet is then at the tip.
 */
export async function waitForTip({ api, esplora, timeoutMs = 900_000, everyMs = 2000, log = () => {} }) {
  api = api.replace(/\/+$/, '');
  esplora = esplora.replace(/\/+$/, '');
  const json = async (url) => {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };
  const deadline = Date.now() + timeoutMs;
  let last = '';
  for (;;) {
    const [tip, status] = await Promise.all([json(`${esplora}/blocks/tip/height`).catch((e) => e), json(`${api}/status`).catch((e) => e)]);
    const at = status instanceof Error ? `unreachable (${status.message})` : status.height;
    if (Number.isInteger(tip) && Number.isInteger(at) && at >= tip) return at;
    if (Number.isInteger(tip) && at === null && tip < status.activationHeight) return null; // the chain is not at A yet
    const now = `${api} at ${at}, tip ${tip instanceof Error ? `unknown (${tip.message})` : tip}`;
    if (Date.now() > deadline) throw new Error(`the indexer did not reach the tip in time: ${now}`);
    if (now !== last) log(`waiting: ${now}`);
    last = now;
    await new Promise((r) => setTimeout(r, everyMs));
  }
}
