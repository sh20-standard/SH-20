#!/usr/bin/env node
// The known answers of subtle.js in a real browser: serves this folder on localhost, opens
// test/subtle.html in headless Chrome and reads the result from the page.
//
//   node test/browser.mjs            CHROME=<binary> overrides the path
//
// Node's WebCrypto and node:crypto are both OpenSSL, so `npm test` shows that webcrypto.js follows
// index.js, not that a browser's X25519, HKDF and AES-GCM give the same bytes. This does, for Chrome.
// For another browser, serve circuit/js over https (or from localhost) and open test/subtle.html.

import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const chrome = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

const server = createServer(async (req, res) => {
  const path = normalize(join(root, decodeURIComponent(new URL(req.url, 'http://x').pathname)));
  const type = TYPES[extname(path)];
  if (!path.startsWith(root.endsWith(sep) ? root : root + sep) || !type) return res.writeHead(404).end();
  try {
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' }).end(await readFile(path));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((ready) => server.listen(0, '127.0.0.1', ready));
const url = `http://127.0.0.1:${server.address().port}/test/subtle.html`;

const dom = await new Promise((resolve, reject) => {
  const child = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--virtual-time-budget=30000', '--dump-dom', url], { stdio: ['ignore', 'pipe', 'ignore'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.on('error', (e) => reject(new Error(`could not start Chrome (${chrome}): ${e.message}`)));
  child.on('exit', () => resolve(out));
});
server.close();

const attr = (name) => dom.match(new RegExp(`data-${name}="([^"]*)"`))?.[1];
const text = (id) => (dom.match(new RegExp(`<[a-z]+ id="${id}">([\\s\\S]*?)</`))?.[1] ?? '').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
console.log(text('out'));
console.log(text('summary'));
if (attr('result') !== 'pass') {
  console.error(`FAIL: result=${attr('result') ?? 'none (the page did not finish)'}`);
  process.exit(1);
}
