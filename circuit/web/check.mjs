#!/usr/bin/env node
// Runs the test page in a local headless Chrome and prints what it measured, for each way the page
// can be served:
//
//   node check.mjs [--runs 1] [--threads 4]
//   node check.mjs --url https://host/path/      the page as served somewhere else (a tunnel, a static host)
//   node check.mjs --url … --sweep               the thread sweep, with the time of each phase
//   node check.mjs --url … --keyload             key loading on one thread, from cold starts
//   node check.mjs --url … --query 'order=2,1&passes=1'   more parameters for the page
//
//   headers           the server sends COOP/COEP                      → threaded prover
//   service worker    no headers, secure context: sw.js adds them     → threaded prover
//   one thread        the single-thread build, asked for explicitly
//   plain http        no headers, not a secure context (a LAN address) → falls back to one thread
//
// No dependency: Chrome is driven over its DevTools protocol. CHROME=<binary> overrides the path.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const flag = (name, def) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
const runs = flag('--runs', '1');
const threads = flag('--threads', '4');
const query = flag('--query', ''); // more of the page's parameters, as `a=1&b=2`
const chromePath = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const here = fileURLToPath(new URL('.', import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function serve(port, isolated) {
  const child = spawn(process.execPath, [join(here, 'serve.mjs'), join(here, 'dist'), '--port', String(port), ...(isolated ? [] : ['--no-isolation'])], { stdio: 'ignore' });
  return () => child.kill();
}

async function chrome() {
  const profile = mkdtempSync(join(tmpdir(), 'sh20-chrome-'));
  const child = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--disable-gpu', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const port = await new Promise((resolve, reject) => {
    let err = '';
    child.stderr.on('data', (d) => {
      err += d;
      const m = err.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
      if (m) resolve(Number(m[1]));
    });
    child.on('exit', () => reject(new Error(`Chrome exited: ${err.slice(0, 300)}`)));
  });
  return {
    async open(url, timeoutMs = 240000) {
      const target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' })).json();
      const ws = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((r, j) => {
        ws.onopen = r;
        ws.onerror = j;
      });
      let id = 0;
      const evaluate = (expression) =>
        new Promise((resolve) => {
          const mine = ++id;
          const on = (e) => {
            const m = JSON.parse(e.data);
            if (m.id === mine) {
              ws.removeEventListener('message', on);
              resolve(m.result?.result?.value);
            }
          };
          ws.addEventListener('message', on);
          ws.send(JSON.stringify({ id: mine, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
        });
      const until = Date.now() + timeoutMs;
      let result = null;
      while (Date.now() < until && !result) {
        await sleep(500);
        result = JSON.parse((await evaluate('JSON.stringify(window.__result ?? null)')) || 'null');
      }
      ws.close();
      await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`).catch(() => {});
      return result ?? { error: 'timed out' };
    },
    async close() {
      const gone = new Promise((r) => child.once('exit', r));
      child.kill();
      await gone;
      rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    },
  };
}

const given = flag('--url');
const lan = Object.values(networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal)?.address;
// name, port, isolated, host, what the page is asked for, what it should end up running
const cases = given
  ? [
      ...(args.includes('--sweep')
        ? [['sweep', null, null, null, 'sweep', 'sweep']]
        : args.includes('--keyload')
          ? [['key loading', null, null, null, 'keyload', 'keyload']]
          : [
            ['all cores', null, null, null, 'threads', 'threads'],
            ['one thread', null, null, null, 'single', 'single'],
          ]),
    ]
  : [
      ['headers', 8471, true, 'localhost', 'threads', 'threads'],
      ['service worker', 8472, false, 'localhost', 'threads', 'threads'],
      ['one thread', 8471, true, 'localhost', 'single', 'single'],
      ...(lan ? [['plain http', 8472, false, lan, 'threads', 'single']] : []),
    ];

const stops = given ? [] : [serve(8471, true), serve(8472, false)];
const browser = await chrome();
let failed = false;
try {
  await sleep(400);
  for (const [name, port, , host, auto, expected] of cases) {
    const base = given ? given.replace(/\/?$/, '/') : `http://${host}:${port}/`;
    const r = await browser.open(`${base}?auto=${auto}&runs=${runs}&threads=${threads}${query ? `&${query}` : ''}`, auto === 'sweep' || auto === 'keyload' ? 900000 : undefined);
    if (r.mode === 'keyload') {
      const ok = r.mode === expected && r.runs.length === r.variants.length && r.runs.every((x) => x.key_load_ms > 0 && x.prove_ms.length === r.proofs);
      failed ||= !ok;
      console.log(`${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(15)} ${r.runs.length} cold starts on one thread`);
      for (const g of r.growth) console.log(`       memory grown to ${g.total_mb} MB in ${g.grows} step${g.grows > 1 ? 's' : ''}${g.shared ? ', shared' : ''}: ${(g.ms / 1000).toFixed(2)} s`);
      for (const x of r.runs) console.log(`       ${x.variant.padEnd(9)} key ${(x.key_load_ms / 1000).toFixed(2)} s, again ${(x.key_reload_ms / 1000).toFixed(2)} s${x.reserved_mb ? `, ${x.reserved_mb} MB reserved in ${x.reserve_ms} ms` : ''}; proof ${x.prove_ms.map((v) => (v / 1000).toFixed(2)).join(' / ') || '–'} s; ${x.memory_mb_start} → ${x.memory_mb_key} → ${x.memory_mb_end} MB`);
      continue;
    }
    const ok = !r.error && r.mode === expected && r.proof_bytes === 480;
    if (r.mode === 'sweep') {
      failed ||= !ok;
      console.log(`${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(15)} sweep, ${r.runs.length} proofs`);
      for (const x of r.runs) console.log(`       ${x.threads} thr, pass ${x.pass}: proof ${(x.prove_ms / 1000).toFixed(2)} s = msm ${(x.msm_ms / 1000).toFixed(2)} + fft ${(x.fft_ms / 1000).toFixed(2)} + rest ${((x.prove_ms - x.msm_ms - x.fft_ms) / 1000).toFixed(2)}; key ${(x.key_load_ms / 1000).toFixed(2)} s; ${x.memory_mb} MB`);
      continue;
    }
    failed ||= !ok;
    console.log(
      `${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(15)} ` +
        (r.error ? r.error : `${r.mode}, ${r.threads} thread${r.threads > 1 ? 's' : ''}, isolated=${r.crossOriginIsolated}: prove ${r.prove_ms.map((x) => (x / 1000).toFixed(2)).join(' / ')} s, key ${(r.key_load_ms / 1000).toFixed(2)} s, ${r.memory_mb} MB`),
    );
  }
} finally {
  await browser.close();
  for (const stop of stops) stop();
}
process.exit(failed ? 1 : 0);
