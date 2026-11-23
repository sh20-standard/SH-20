// Read-only HTTP API over an indexer, for wallets, explorers and relayers.
// JSON only, GET only, CORS open (the vault is a static page on any origin).
// Big integers are decimal strings; field elements and hashes are 64-char hex.
// Nothing here can change the state: it only reports what the chain implies.

import { createServer } from 'node:http';

const NOTE_PAGE_MAX = 5000;
const BLOCK_PAGE_MAX = 200;

import { hexFr as hex32 } from './notes.js';
import { encodeEvents } from './events.js';

const LISTING_STATES = ['ACTIVE', 'SOLD', 'CANCELLED', 'CLOSED', 'CLAIMED'];

// An event as the API shows it (docs/API.md, "Events"): its record of SPEC-WIRE §6, under the spec's names, which are
// the indexer's own; a LIST does not repeat its own txid as listTxid.
function apiEvent(e) {
  if (e.type !== 'LIST') return e;
  const { listTxid, ...out } = e;
  return out;
}
// A block as /blocks and /block/:height show it: its events in API shape, and eventsH, the bytes of SPEC-WIRE §6.
const apiBlock = (b) => ({ ...b, events: b.events.map(apiEvent), eventsH: encodeEvents(b.events).toString('hex') });
const HEX64 = /^[0-9a-f]{64}$/;

const json = (value) =>
  JSON.stringify(value, (_, v) => {
    if (typeof v === 'bigint') return v.toString();
    if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
    return v;
  });

function send(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'cache-control': 'no-store',
  });
  res.end(json(body));
}

const intParam = (url, name, def) => {
  const v = url.searchParams.get(name);
  if (v === null) return def;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : NaN;
};

/** Returns a request handler; pass it to http.createServer or use `listen`. */
export function apiHandler(indexer, { network } = {}) {
  const ix = indexer;
  const routes = [
    [/^\/status$/, () => ({
      network: network ?? ix.profile.network,
      implementation: 'sh20-indexer (reference, JavaScript)',
      activationHeight: ix.profile.activationHeight,
      height: ix.height,
      hash: ix.blocks.get(ix.height)?.hash ?? null,
      digest: ix.digest.toString('hex'),
      root: hex32(ix.tree.root),
      leaves: ix.tree.size,
      nullifiers: ix.nullifiers.size,
      tokens: ix.tokens.size,
      genesis: ix.genesis ?? null,
      deployBurn: ix.profile.deployBurn,
      deployMaturity: ix.profile.deployMaturity,
      anchorWindow: ix.profile.anchorWindow,
      anchorMinDepth: ix.profile.anchorMinDepth,
      verifier: ix.verifier.name ?? 'custom',
    })],
    [/^\/tokens$/, () => [...ix.tokens.values()]],
    [/^\/token\/([^/]+)$/, (_, [ticker]) => (/^[A-Z0-9]{4}$/.test(ticker) ? ix.token(ticker) ?? 404 : 400)],
    [/^\/notes$/, (url) => {
      const from = intParam(url, 'from', 0);
      const limit = Math.min(intParam(url, 'limit', 1000), NOTE_PAGE_MAX);
      if (Number.isNaN(from) || Number.isNaN(limit)) return 400;
      return { from, total: ix.notes.length, notes: ix.notes.slice(from, from + limit) };
    }],
    [/^\/path\/([^/]+)$/, (_, [pos]) => {
      if (!/^\d+$/.test(pos)) return 400;
      const p = Number(pos);
      if (p >= ix.tree.size) return 404;
      return { pos: p, height: ix.height, root: hex32(ix.tree.root), siblings: ix.tree.path(p).map(hex32) };
    }],
    [/^\/roots$/, (url) => {
      const from = intParam(url, 'from', Math.max(0, (ix.height ?? 0) - ix.profile.anchorWindow));
      if (Number.isNaN(from)) return 400;
      return [...ix.roots.entries()].filter(([h]) => h >= from).map(([height, root]) => ({ height, root: hex32(root) }));
    }],
    [/^\/nullifier\/([^/]+)$/, (_, [nf]) => (HEX64.test(nf) ? { nullifier: nf, spent: ix.nullifiers.has(nf) } : 400)],
    [/^\/listings$/, (url) => {
      const state = url.searchParams.get('state');
      if (state !== null && !LISTING_STATES.includes(state)) return 400;
      return [...ix.listings.values()].filter((l) => !state || l.state === state);
    }],
    [/^\/listing\/([^/]+)$/, (_, [txid]) => (HEX64.test(txid) ? ix.listings.get(txid) ?? 404 : 400)],
    // Every spent nullifier from block `from` on, in block order. A wallet downloads this list
    // and checks its own notes locally: asking /nullifier/:hex per note tells the indexer
    // which notes are yours.
    [/^\/nullifiers$/, (url) => {
      const from = intParam(url, 'from', ix.profile.activationHeight);
      if (Number.isNaN(from)) return 400;
      const out = [];
      for (const [h, b] of ix.history) {
        if (h < from) continue;
        for (const e of b.events) for (const nf of e.nullifiers ?? []) out.push({ height: h, nullifier: nf });
      }
      return { from, height: ix.height, nullifiers: out };
    }],
    // The digest after one block, to compare independent indexers at the same height.
    [/^\/digest\/([^/]+)$/, (_, [h]) => {
      if (!/^\d+$/.test(h)) return 400;
      const d = ix.digests.get(Number(h));
      return d === undefined ? 404 : { height: Number(h), digest: d };
    }],
    // Blocks with SH-20 activity, newest first: accepted events and rejected envelopes.
    [/^\/blocks$/, (url) => {
      const before = intParam(url, 'before', (ix.height ?? -1) + 1);
      const limit = Math.min(intParam(url, 'limit', 20), BLOCK_PAGE_MAX);
      if (Number.isNaN(before) || Number.isNaN(limit)) return 400;
      const out = [];
      for (const [h, b] of [...ix.history.entries()].reverse()) {
        if (h >= before) continue;
        out.push(apiBlock(b));
        if (out.length >= limit) break;
      }
      return out;
    }],
    // One block from A to the tip, with SH-20 activity or not.
    [/^\/block\/([^/]+)$/, (_, [hs]) => {
      if (!/^\d+$/.test(hs)) return 400;
      const h = Number(hs);
      if (ix.history.has(h)) return apiBlock(ix.history.get(h));
      const b = ix.blocks.get(h);
      if (!b) return 404;
      return apiBlock({ height: h, hash: b.hash, digest: ix.digests.get(h), root: hex32(ix.roots.get(h)), leaves: b.leaves, events: [], rejected: [] });
    }],
    // One SH-20 transaction: its accepted event (or rejection reason) and the notes it created. A batch of TRANSFERs
    // has a verdict per envelope, none for the whole: `events` and `rejections` list them all (each with its `envelope`),
    // and `event` and `rejected` are null, so that a reader written before batches does not take one for the other.
    [/^\/tx\/([^/]+)$/, (_, [txid]) => {
      if (!HEX64.test(txid)) return 400;
      const height = ix.txIndex.get(txid);
      if (height === undefined) return 404;
      const b = ix.history.get(height);
      const events = b.events.filter((e) => e.txid === txid);
      const rejections = b.rejected.filter((e) => e.txid === txid);
      const batch = [...events, ...rejections].some((e) => e.envelope !== undefined);
      // the verdict on the envelope: CLOSED is never one (a transaction that only spends a lock has no envelope)
      const own = events.find((e) => e.type !== 'CLOSED');
      return {
        txid, height,
        event: batch || !own ? null : apiEvent(own),
        rejected: batch ? null : rejections[0]?.reason ?? null,
        events: events.map(apiEvent),
        rejections: rejections.map(({ txid: _, ...r }) => r),
        notes: ix.notes.filter((n) => n.txid === txid),
      };
    }],
  ];

  return (req, res) => {
    if (req.method === 'OPTIONS') return send(res, 204, null);
    if (req.method !== 'GET') return send(res, 405, { error: 'GET only' });
    const url = new URL(req.url, 'http://localhost');
    for (const [re, fn] of routes) {
      const m = url.pathname.match(re);
      if (!m) continue;
      const out = fn(url, m.slice(1));
      if (out === 404) return send(res, 404, { error: 'not found' });
      if (out === 400) return send(res, 400, { error: 'bad parameter' });
      return send(res, 200, out);
    }
    return send(res, 404, { error: 'unknown route' });
  };
}

/** Starts the API. Resolves with the server once it listens. */
export function listen(indexer, { port = 8020, host = '127.0.0.1', network } = {}) {
  const server = createServer(apiHandler(indexer, { network }));
  return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
}
