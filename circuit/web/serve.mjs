#!/usr/bin/env node
// Static server for the test page, with the cross-origin isolation headers the threaded prover needs.
//
//   node serve.mjs [dir] [--port 8080] [--host 0.0.0.0] [--no-isolation]
//
// --no-isolation leaves the headers out, to exercise the page's fallbacks. A phone on the same
// network reaches http://<this machine>:8080, but plain http is not a secure context there: the
// page then proves on one thread. For threads on a phone, serve the same folder over https
// (a tunnel to this server, or any static host: see README.md).

import { createServer } from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const flag = (name, def) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
const root = resolve(args[0] && !args[0].startsWith('--') ? args[0] : fileURLToPath(new URL('./dist', import.meta.url)));
const port = Number(flag('--port', 8080));
const host = flag('--host', '0.0.0.0');
const isolate = !args.includes('--no-isolation');

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.wasm': 'application/wasm', '.json': 'application/json', '.pk': 'application/octet-stream' };

createServer((req, res) => {
  let path;
  try {
    path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const file = normalize(join(root, path.endsWith('/') ? `${path}index.html` : path));
  if (file !== root && !file.startsWith(root + sep)) {
    res.writeHead(403).end();
    return;
  }
  let size;
  try {
    const st = statSync(file);
    if (!st.isFile()) throw new Error('not a file');
    size = st.size;
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found');
    return;
  }
  const headers = { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Content-Length': size, 'Cache-Control': 'no-store' };
  if (isolate) {
    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
    headers['Cross-Origin-Resource-Policy'] = 'same-origin';
  }
  res.writeHead(200, headers);
  if (req.method === 'HEAD') res.end();
  else createReadStream(file).pipe(res);
}).listen(port, host, () => {
  console.log(`serving ${root} on http://${host === '0.0.0.0' ? 'localhost' : host}:${port} (${isolate ? 'cross-origin isolated' : 'no isolation headers'})`);
});
