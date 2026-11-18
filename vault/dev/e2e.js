// Development only: drives the real page in headless Chrome (DevTools protocol,
// no dependency) through the whole mint flow, against dev/serve.js mocks.
// A fake UniSat is injected; it "signs" with a dummy Schnorr signature, which
// the mock Esplora accepts because indexers never check Bitcoin signatures.
//
//   node vault/dev/serve.js &   then   node vault/dev/e2e.js [path to Chrome]
//   (after `npm run build`, E2E_PATH=/vault/dist/vault/ tests the IPFS build)

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROME = process.argv[2] || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
// E2E_PATH=/vault/dist/vault/ runs the same flow on the IPFS build.
const PAGE = `http://localhost:8000${process.env.E2E_PATH || '/vault/'}?indexer=http://127.0.0.1:8020&esplora=http://127.0.0.1:8020/esplora`;
const PORT = 9333;

// Runs in the page before any of its scripts.
const FAKE_UNISAT = `(() => {
  const ADDR = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c';
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  // Adds PSBT_IN_TAP_KEY_SIG (64 zero bytes) to every input map.
  function sign(psbtHex) {
    const b = unhex(psbtHex);
    let p = 5;
    const cs = () => { const f = b[p++]; if (f < 0xfd) return f; const v = b[p] | (b[p + 1] << 8); p += 2; return v; };
    const skipMap = () => { for (;;) { const k = cs(); if (k === 0) return p - 1; p += k; const v = cs(); p += v; } };
    skipMap();
    const out = [];
    let last = 0;
    const nIn = window.__nIn;
    for (let i = 0; i < nIn; i++) {
      const end = skipMap();
      out.push(b.slice(last, end), Uint8Array.from([1, 0x13, 64, ...new Uint8Array(64)]));
      last = end;
      p = end + 1;
    }
    out.push(b.slice(last));
    return hex(Uint8Array.from(out.flatMap((x) => [...x])));
  }
  window.unisat = {
    requestAccounts: async () => [ADDR],
    getAccounts: async () => [ADDR],
    getChain: async () => ({ enum: 'BITCOIN_SIGNET' }),
    getPublicKey: async () => '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    signPsbt: async (h, opts) => { window.__nIn = opts.toSignInputs.length; window.__signed = opts; return sign(h); },
  };
})();`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let chrome;
let profile;

async function main() {
  profile = mkdtempSync(join(tmpdir(), 'sh20-e2e-'));
  chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  let target;
  for (let i = 0; i < 50 && !target; i++) {
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
  const problems = [];
  const dialogs = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.method === 'Page.javascriptDialogOpening') {
      dialogs.push(m.params.message);
      ws.send(JSON.stringify({ id: ++id, method: 'Page.handleJavaScriptDialog', params: { accept: true } }));
    } else if (m.method === 'Runtime.exceptionThrown') {
      problems.push('exception: ' + m.params.exceptionDetails.exception?.description);
    } else if (m.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(m.params.type)) {
      problems.push(`console.${m.params.type}: ` + m.params.args.map((a) => a.value ?? a.description).join(' '));
    } else if (m.method === 'Log.entryAdded' && ['error', 'warning'].includes(m.params.entry.level)) {
      problems.push(`log: ${m.params.entry.text} ${m.params.entry.url ?? ''}`);
    }
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
  const waitFor = async (expr, what) => {
    for (let i = 0; i < 100; i++) {
      if (await evaluate(expr)) return;
      await sleep(100);
    }
    throw new Error(`timeout waiting for ${what}; page says: ${await evaluate('document.body.innerText')}`);
  };
  const click = (sel, text) => evaluate(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(sel)})].find((x) => x.textContent.includes(${JSON.stringify(text)})); if (!b) throw new Error('no button ${text}'); if (b.disabled) throw new Error('button ${text} disabled: ' + b.title); b.click(); return true; })()`);

  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', { source: FAKE_UNISAT });
  await send('Page.navigate', { url: PAGE });

  const step = (s) => console.log('·', s);
  await waitFor(`document.querySelector('#warnings')?.innerText.includes('servers from the link')`, 'URL servers warning');
  if (!dialogs.some((d) => d.includes('127.0.0.1:8020'))) throw new Error('URL servers applied without confirmation');
  step('URL servers confirmed by a dialog and flagged on the page');
  await waitFor(`document.querySelector('#tokens-body td strong')?.textContent === 'GENE'`, 'ticker table');
  step('tickers loaded from /tokens: ' + (await evaluate(`document.querySelector('#tokens-body tbody tr').innerText.replace(/\\s+/g, ' ')`)));

  await evaluate(`document.querySelector('#vault-body input[type=password]').value = 'e2e passphrase'`);
  await click('#vault-body button', 'Create vault');
  await waitFor(`document.querySelector('#vault-body').innerText.includes('Unlocked')`, 'vault');
  const stored = await evaluate(`localStorage.getItem('sh20.vault.v0')`);
  if (/seed|GENE/.test(stored)) throw new Error('vault stored in clear');
  step('vault created, stored encrypted (' + stored.length + ' bytes)');

  await waitFor(`[...document.querySelectorAll('#wallet-body button')].some((b) => b.textContent === 'UniSat' && !b.disabled)`, 'UniSat detected');
  await click('#wallet-body button', 'UniSat');
  await waitFor(`document.querySelector('#wallet-body').innerText.includes('connected')`, 'wallet');
  step('wallet: ' + (await evaluate(`document.querySelector('#wallet-body p').innerText`)));

  await click('#tokens-body button', 'Mint');
  await waitFor(`[...document.querySelectorAll('#mint-body button')].some((b) => b.textContent.includes('Prepare'))`, 'mint panel');
  await click('#mint-body button', 'Prepare');
  await waitFor(`[...document.querySelectorAll('#mint-body button')].some((b) => b.textContent.includes('Sign with'))`, 'prepared tx');
  if (!(await evaluate(`document.querySelector('#mint-body').innerText.includes('checked against the DEPLOY')`))) throw new Error('deploy check not shown');
  step('prepared: ' + (await evaluate(`document.querySelector('#mint-body div dl').innerText.replace(/\\n/g, ' | ')`)));
  await click('#mint-body button', 'Sign with');
  await waitFor(`document.querySelector('#mint-body').innerText.includes('Broadcast:')`, 'broadcast');
  step(await evaluate(`document.querySelector('#mint-body .ok').innerText`));

  await click('#notes button', 'Check indexer');
  await waitFor(`document.querySelector('#notes-body').innerText.includes('in tree')`, 'note found in the tree');
  step('my notes: ' + (await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`)));

  ws.close();
  const real = problems.filter((p) => !/favicon/.test(p));
  if (real.length) {
    throw new Error('page problems:\n' + real.join('\n'));
  }
  console.log('\nOK: no console error, no CSP violation');
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (chrome && chrome.exitCode === null) {
      const exited = new Promise((r) => chrome.once('exit', r));
      chrome.kill();
      await exited;
    }
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });
