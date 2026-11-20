// Cross-origin isolation on IPFS: the service worker is the phone test page's, unchanged, and is
// registered on subdomain gateways only, never on a path gateway; the pool size is defaultThreads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gatewayKind, ensureIsolation } from '../src/isolation.js';
import { defaultThreads } from '../../circuit/web/host.js';
import { site, fsReader } from '../build.js';

const at = (url) => { const u = new URL(url); return { pathname: u.pathname, hostname: u.hostname }; };

test('the service worker is circuit/web/sw.js, byte for byte, at the root of the site', () => {
  const reference = readFileSync(new URL('../../circuit/web/sw.js', import.meta.url));
  assert.ok(readFileSync(new URL('../sw.js', import.meta.url)).equals(reference));
  const files = new Map(site(fsReader()));
  assert.ok(files.get('sw.js').equals(reference), 'served at the root');
  assert.ok(!files.has('vault/sw.js'));
  // registered with the root as its scope: the pool's threads (circuit/web/thread-worker.js) are outside vault/
  assert.match(readFileSync(new URL('../src/isolation.js', import.meta.url), 'utf8'), /register\(new URL\('\.\.\/\.\.\/sw\.js', import\.meta\.url\), \{ scope: new URL\('\.\.\/\.\.\/', import\.meta\.url\)\.href \}\)/);
});

test('only a subdomain gateway is one: path gateways and other hosts are not', () => {
  const cid = 'bafybeigfj45xzun5mek5zvqeby6bs76ukwkslx7ifa7ipzdoylfl4pnavi';
  assert.equal(gatewayKind(at(`https://${cid}.ipfs.dweb.link/vault/`)), 'subdomain');
  assert.equal(gatewayKind(at(`http://${cid}.ipfs.localhost:8080/vault/`)), 'subdomain');
  assert.equal(gatewayKind(at('https://vault-sh20.ipns.dweb.link/vault/')), 'subdomain');
  assert.equal(gatewayKind(at(`https://ipfs.io/ipfs/${cid}/vault/`)), 'path');
  assert.equal(gatewayKind(at(`https://${cid}.ipfs.dweb.link/ipfs/${cid}/vault/`)), 'path', 'a path inside a subdomain is still a path gateway');
  assert.equal(gatewayKind(at('http://localhost:8000/vault/')), 'other');
  assert.equal(gatewayKind(at('https://example.org/vault/')), 'other');
});

test('the service worker is never registered on a path gateway', async () => {
  let registered = false;
  const saved = { ...globalThis };
  Object.assign(globalThis, {
    location: { pathname: '/ipfs/bafy/vault/', hostname: 'ipfs.io' },
    isSecureContext: true,
    crossOriginIsolated: false,
  });
  const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', { value: { serviceWorker: { register: async () => { registered = true; return {}; } } }, configurable: true });
  try {
    assert.equal(await ensureIsolation(), 'not-a-subdomain-gateway');
    assert.equal(registered, false);
  } finally {
    for (const k of ['location', 'isSecureContext', 'crossOriginIsolated']) if (!(k in saved)) delete globalThis[k];
    if (nav) Object.defineProperty(globalThis, 'navigator', nav);
  }
});

test('a dropped reload does not leave the page blank: after a while it goes on with one thread', async () => {
  const saved = Object.fromEntries(['location', 'isSecureContext', 'crossOriginIsolated', 'sessionStorage'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const session = new Map();
  let reloads = 0;
  Object.defineProperty(globalThis, 'location', { value: { pathname: '/vault/', hostname: 'bafy.ipfs.localhost', reload: () => { reloads++; } }, configurable: true }); // a reload the browser drops
  Object.defineProperty(globalThis, 'sessionStorage', { value: { getItem: (k) => session.get(k) ?? null, setItem: (k, v) => session.set(k, v) }, configurable: true });
  Object.assign(globalThis, { isSecureContext: true, crossOriginIsolated: false });
  Object.defineProperty(globalThis, 'navigator', { value: { serviceWorker: { controller: null, register: async () => ({ active: { state: 'activated' } }) } }, configurable: true });
  try {
    const t = Date.now();
    assert.equal(await ensureIsolation({ reloadWaitMs: 50 }), 'refused');
    assert.ok(Date.now() - t >= 45, 'it waits for the reload first');
    assert.equal(reloads, 1);
    assert.equal(await ensureIsolation({ reloadWaitMs: 50 }), 'refused', 'and asks once per tab');
    assert.equal(reloads, 1);
  } finally {
    for (const [k, d] of Object.entries(saved)) {
      if (d) Object.defineProperty(globalThis, k, d);
      else delete globalThis[k];
    }
    if (nav) Object.defineProperty(globalThis, 'navigator', nav);
  }
  assert.ok(!/await new Promise\(\(\) => \{\}\);\n\n\/\/ Note keys/.test(readFileSync(new URL('../src/app.js', import.meta.url), 'utf8')), 'app.js no longer waits forever after ensureIsolation');
});

test('the pool size: the cores reported, at least 6 on an iPhone (circuit/web/host.js)', () => {
  assert.equal(defaultThreads({ hardwareConcurrency: 4, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X)' }), 6);
  assert.equal(defaultThreads({ hardwareConcurrency: 10, userAgent: 'Mozilla/5.0 (Macintosh)' }), 10);
  assert.match(readFileSync(new URL('../src/prover.js', import.meta.url), 'utf8'), /defaultThreads\(\)/);
});
