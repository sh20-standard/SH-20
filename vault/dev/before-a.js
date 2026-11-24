// Development only: the signet release before its block A, on the site's mirrors (docs/API.md, "The static
// mirror"). Between the launch and block A, both mirrors have no height and the digest before A: the page must
// say that SH-20 starts at block A, sync without an error, and act on nothing.
//
//   node vault/dev/before-a.js [path to Chrome]
//
// The site is laid out as pages.yml lays it out: the release built on the signet profile with A fixed (as at
// launch, build.js), and beside it /api/js/ and /api/rs/, the mirrors of two indexers on that profile that have
// counted no block (indexer/src/mirror.js, what bin/mirror.js runs). The page is opened with its own defaults
// (servers.js: those two mirrors), in headless Chrome, with every host but this machine unreachable: nothing
// leaves it, the signet Esplora of the defaults included. It creates a vault, syncs, and reads what it shows.

import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { buildMirror } from '../../indexer/src/mirror.js';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { fsReader, site, writeSite } from '../build.js';
import { staticServer } from './static.js';

const A = 300000;
const AT = A.toLocaleString('en-US');
const CHROME = process.argv[2] || ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium'].find(existsSync);
if (!CHROME) throw new Error('no Chrome found: give its path');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (s) => console.log(`· ${s}`);

// the release, A fixed, as the launch fixes it in profile.js
const fs = fsReader();
const reader = { ...fs, read: (p) => (p === 'vault/src/profile.js' ? Buffer.from(fs.read(p).toString('utf8').replace(/^export const SIGNET_ACTIVATION_HEIGHT = null;$/m, `export const SIGNET_ACTIVATION_HEIGHT = ${A};`)) : fs.read(p)) };
const dir = mkdtempSync(join(tmpdir(), 'sh20-before-a-'));
writeSite([...site(reader, { signet: true })], dir);

// two indexers on the signet profile of that A, with no block counted, and their mirrors beside the page
const live = [];
for (const name of ['js', 'rs']) {
  const server = await listen(new Indexer({ profile: { ...DEFAULT_PROFILE, activationHeight: A }, verifier: { name: 'none', verifySpend: () => false } }), { port: 0 });
  live.push(server);
  await buildMirror({ api: `http://127.0.0.1:${server.address().port}`, out: join(dir, 'api', name) });
}
live.forEach((s) => s.close()); // the page reads the files alone
const files = staticServer({ root: dir });
await new Promise((r) => files.listen(0, '127.0.0.1', r));
const PAGE = `http://localhost:${files.address().port}/vault/`;
step(`signet release with A = ${AT}, its mirrors before A beside it: ${PAGE.replace(/:\d+/, ':…')}`);

const profile = mkdtempSync(join(tmpdir(), 'sh20-chrome-'));
const PORT = 9300 + Math.floor(Math.random() * 500);
const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, '--no-first-run',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1', // nothing but this machine
  ...(process.env.CI ? ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] : []), 'about:blank'], { stdio: 'ignore' });
let failed = null;
try {
  let target;
  for (let i = 0; i < 150 && !target; i++) {
    await sleep(200);
    try {
      target = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page');
    } catch {}
  }
  if (!target) throw new Error('Chrome did not start');
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let id = 0;
  const pending = new Map();
  const exceptions = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.method === 'Runtime.exceptionThrown') exceptions.push(m.params.exceptionDetails.exception?.description);
    else if (m.method === 'Page.javascriptDialogOpening') ws.send(JSON.stringify({ id: ++id, method: 'Page.handleJavaScriptDialog', params: { accept: true } }));
  });
  const send = (method, params = {}) => new Promise((r) => {
    pending.set(++id, r);
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || expr);
    return r.result.result.value;
  };
  const text = (sel) => evaluate(`document.querySelector(${JSON.stringify(sel)})?.innerText ?? ''`);
  const waitFor = async (sel, re, what) => {
    for (let i = 0; i < 200; i++) {
      if (re.test(await text(sel))) return text(sel);
      await sleep(100);
    }
    throw new Error(`timeout waiting for ${what}: ${sel} says ${JSON.stringify(await text(sel))}; warnings: ${JSON.stringify(await text('#warnings'))}`);
  };
  await send('Runtime.enable');
  await send('Page.enable');
  await send('Page.navigate', { url: PAGE });

  step(`indexer line: ${await waitFor('#indexer-status', new RegExp(`before block ${AT}`), 'the indexer line before A')}`);
  if (!/a mirror of it/.test(await text('#indexer-status'))) throw new Error('the primary is not read as a mirror');
  if (await evaluate(`!!document.querySelector('#profile-problems')`)) throw new Error(`a profile problem: ${await text('#profile-problems')}`);
  step(`tickers: ${await waitFor('#tokens-body', new RegExp(`No ticker yet: SH20 exists from block ${AT} on`), 'the tickers before A')}`);

  await evaluate(`document.querySelector('#vault-body input[type=password]').value = 'before A'`);
  await evaluate(`[...document.querySelectorAll('#vault-body button')].find((b) => b.textContent.includes('Create vault')).click()`);
  await waitFor('#vault-body', /Unlocked/, 'the vault');
  for (const button of ['scan', 'rescan']) { // Sync, and Rescan from zero
    await evaluate(`document.querySelector('#${button}').click()`);
    step(`${button === 'scan' ? 'Sync' : 'Rescan from zero'}: ${await waitFor('#sync-status', new RegExp(`SH-20 starts at block ${AT}`), 'the sync before A')}`);
    await sleep(500);
  }
  const warnings = await text('#warnings');
  if (/no height|reports no|bad height|error/i.test(warnings)) throw new Error(`the sync failed: ${warnings}`);
  if (exceptions.length) throw new Error(`exceptions: ${exceptions.join(' | ')}`);
  step(`no error on screen${warnings.trim() ? ` (it shows: ${warnings.replace(/\s+/g, ' ').trim()})` : ''}`);
  ws.close();
  console.log(`\nOK: before block ${AT}, the signet release reads both mirrors, says where SH-20 starts and syncs without an error`);
} catch (e) {
  failed = e;
} finally {
  chrome.kill();
  await sleep(500);
  files.close();
  rmSync(dir, { recursive: true, force: true });
  rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
if (failed) {
  console.error(failed.message);
  process.exit(1);
}
