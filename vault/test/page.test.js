// The page must stay a static, relocatable bundle (IPFS) with a strict CSP.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');

test('CSP allows exactly the inline import map, by hash', () => {
  const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.equal(inline.length, 1, 'one inline script: the import map');
  const hash = createHash('sha256').update(inline[0]).digest('base64');
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.ok(csp.includes(`'sha256-${hash}'`), 'CSP hash matches the import map');
  assert.ok(!/unsafe-inline|(?<!wasm-)unsafe-eval/.test(csp), 'no eval of strings; only WebAssembly may compile');
  // scripts: this origin, the import map hash, and the wallet extensions' own scripts; no other domain
  // the prover and the proving key are fetched from the page's own origin, on any host (a local IPFS node is plain http)
  assert.ok(csp.match(/connect-src ([^;]+)/)[1].split(/\s+/).includes("'self'"), "connect-src has 'self'");
  const scriptSrc = csp.match(/script-src ([^;]+)/)[1].trim().split(/\s+/);
  for (const x of scriptSrc) assert.ok(["'self'", "'wasm-unsafe-eval'", 'chrome-extension:', 'moz-extension:'].includes(x) || /^'sha256-/.test(x), `script-src ${x}`);
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /style-src 'self'(;|$)/);
});

test('privacy: no source asks per-note routes (/path/:pos, /nullifier/:hex)', () => {
  for (const f of readdirSync(new URL('../src/', import.meta.url), { recursive: true }).filter((x) => x.endsWith('.js'))) {
    const src = readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8').replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '');
    assert.ok(!/\/path\/|\/nullifier\//.test(src), `${f} must not call /path/:pos or /nullifier/:hex`);
  }
});

test('only relative URLs, so the page works under any IPFS CID', () => {
  for (const [, url] of html.matchAll(/(?:src|href)="([^"]+)"/g)) assert.match(url, /^\.\//, url);
  for (const f of readdirSync(new URL('../src/', import.meta.url), { recursive: true }).filter((x) => x.endsWith('.js'))) {
    const src = readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
    for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)) assert.match(spec, /^\.\.?\//, `${f}: ${spec}`);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function/.test(src), `${f} writes no HTML from strings`);
  }
});
