// Development only: serves the repository root, as dev/serve.js and dev/regtest.js both do
// (open http://localhost:8000/vault/).

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm' };

/**
 * `isolate`: send COOP/COEP, so the page gets shared memory and proves on a thread pool.
 * `mounts`: { '/api/': folder }, a path prefix served from another folder (regtest.js --mirror's mirrors).
 */
export function staticServer({ root, isolate = false, mounts = {} }) {
  const isolation = isolate ? { 'cross-origin-opener-policy': 'same-origin', 'cross-origin-embedder-policy': 'require-corp' } : {};
  return createServer(async (req, res) => {
    // /ipfs/<cid>/… is served like a path gateway would (the same files), to check the page never
    // registers its service worker there; <cid>.ipfs.localhost:<port> is a subdomain gateway
    const pathname = new URL(req.url, 'http://x').pathname.replace(/^\/ip[fn]s\/[^/]+(?=\/)/, '');
    // the site's root sw.js (build.js puts vault/sw.js there): the repository root has none
    const path = pathname === '/sw.js' ? '/vault/sw.js' : normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
    const mount = Object.keys(mounts).find((m) => path.startsWith(m));
    const base = mount ? mounts[mount] : root;
    let file = mount ? join(base, path.slice(mount.length)) : join(root, path);
    if (!file.startsWith(base)) return res.writeHead(403).end();
    if (file.endsWith('/')) file = join(file, 'index.html');
    let body;
    try {
      body = await readFile(file);
    } catch {
      return res.writeHead(404).end('not found');
    }
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream', ...isolation }).end(body);
  });
}
