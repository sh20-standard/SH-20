// Read-only HTTP API over an indexer, for wallets, explorers and relayers.
// JSON only, GET only, CORS open (the vault is a static page on any origin).
// Big integers are decimal strings; field elements and hashes are 64-char hex.
// Nothing here can change the state: it only reports what the chain implies.

import { createServer } from 'node:http';

const NOTE_PAGE_MAX = 5000;

const hex32 = (x) => x.toString(16).padStart(64, '0');

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
      activationHeight: ix.profile.activationHeight,
      height: ix.height,
      digest: ix.digest.toString('hex'),
      root: hex32(ix.tree.root),
      leaves: ix.tree.size,
      nullifiers: ix.nullifiers.size,
      tokens: ix.tokens.size,
      verifier: ix.verifier.name ?? 'custom',
    })],
    [/^\/tokens$/, () => [...ix.tokens.values()]],
    [/^\/token\/([A-Z0-9]{4})$/, (_, [ticker]) => ix.token(ticker) ?? 404],
    [/^\/notes$/, (url) => {
      const from = intParam(url, 'from', 0);
      const limit = Math.min(intParam(url, 'limit', 1000), NOTE_PAGE_MAX);
      if (Number.isNaN(from) || Number.isNaN(limit)) return 400;
      return { from, total: ix.notes.length, notes: ix.notes.slice(from, from + limit) };
    }],
    [/^\/path\/(\d+)$/, (_, [pos]) => {
      const p = Number(pos);
      if (p >= ix.tree.size) return 404;
      return { pos: p, height: ix.height, root: hex32(ix.tree.root), siblings: ix.tree.path(p).map(hex32) };
    }],
    [/^\/roots$/, (url) => {
      const from = intParam(url, 'from', Math.max(0, (ix.height ?? 0) - ix.profile.anchorWindow));
      if (Number.isNaN(from)) return 400;
      return [...ix.roots.entries()].filter(([h]) => h >= from).map(([height, root]) => ({ height, root: hex32(root) }));
    }],
    [/^\/nullifier\/([0-9a-f]{64})$/, (_, [nf]) => ({ nullifier: nf, spent: ix.nullifiers.has(nf) })],
    [/^\/listings$/, (url) => {
      const state = url.searchParams.get('state');
      return [...ix.listings.values()].filter((l) => !state || l.state === state);
    }],
    [/^\/listing\/([0-9a-f]{64})$/, (_, [txid]) => ix.listings.get(txid) ?? 404],
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
