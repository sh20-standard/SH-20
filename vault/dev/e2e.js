// Development only: drives the real page in headless Chrome (DevTools protocol,
// no dependency) through the whole mint flow, against dev/serve.js mocks.
// A fake UniSat is injected; it "signs" with a dummy Schnorr signature, which
// the mock Esplora accepts because indexers never check Bitcoin signatures.
//
//   node vault/dev/serve.js &   then   node vault/dev/e2e.js [path to Chrome]
//   (after `npm run build`, E2E_PATH=/vault/dist/vault/ tests the IPFS build)
//   With `serve.js --deploy-burn 0`, run E2E_D0=1: mints GENE, whose terms come from its DEPLOY.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

const CHROME = process.argv[2] || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
// E2E_PATH=/vault/dist/vault/ runs the same flow on the IPFS build.
// E2E_LIAR=1 adds the lying indexer (:8031) and expects the mint to be refused.
const LIAR = !!process.env.E2E_LIAR;
// Default profile (D = 1000): mint the genesis token SH20, checked against the profile.
// E2E_D0=1 (serve.js --deploy-burn 0): mint GENE, checked against its DEPLOY transaction.
const D0 = !!process.env.E2E_D0;
const TICKER = D0 ? 'GENE' : 'SH20';
// a wallet of circuit/js/vectors.json to send to: its own scan must find the note (checked in test/spend.test.js)
const RECIPIENT = JSON.parse(readFileSync(new URL('../../circuit/js/vectors.json', import.meta.url), 'utf8')).wallets.find((w) => w.name === 'recipient').addressTest;
// a fresh ticker each run: the dev chain lives as long as serve.js, across runs
const NEW_TICKER = 'T' + Array.from(crypto.getRandomValues(new Uint8Array(3)), (x) => String.fromCharCode(65 + (x % 26))).join('');
const LONG = 3000; // × 100 ms: a proof on one thread in a browser takes about half a minute
const INDEXERS = ['http://127.0.0.1:8020', 'http://127.0.0.1:8030', ...(LIAR ? ['http://127.0.0.1:8031'] : [])].join(',');
const PAGE = `http://localhost:8000${process.env.E2E_PATH || '/vault/'}?indexer=${INDEXERS}&esplora=http://127.0.0.1:8020/esplora`;
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
  const urls = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.method === 'Network.requestWillBeSent') {
      urls.push(m.params.request.url);
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
  const waitFor = async (expr, what, tries = 100) => {
    for (let i = 0; i < tries; i++) {
      if (await evaluate(expr)) return;
      await sleep(100);
    }
    throw new Error(`timeout waiting for ${what}; page says: ${await evaluate('document.body.innerText')}`);
  };
  const click = (sel, text) => evaluate(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(sel)})].find((x) => x.textContent.includes(${JSON.stringify(text)})); if (!b) throw new Error('no button ${text}'); if (b.disabled) throw new Error('button ${text} disabled: ' + b.title); b.click(); return true; })()`);

  await send('Network.enable');
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', { source: FAKE_UNISAT });
  await send('Page.navigate', { url: PAGE });

  const step = (s) => console.log('·', s);
  await waitFor(`document.querySelector('#warnings')?.innerText.includes('servers from the link')`, 'URL servers warning');
  if (!dialogs.some((d) => d.includes('127.0.0.1:8020'))) throw new Error('URL servers applied without confirmation');
  step('URL servers confirmed by a dialog and flagged on the page');
  const row = `[...document.querySelectorAll('#tokens-body tbody tr')].find((r) => r.querySelector('strong')?.textContent === '${TICKER}')`;
  await waitFor(`!!${row}`, 'ticker table');
  if (!(await evaluate(`document.querySelector('#tokens-body tbody tr').innerText.includes('SH20 genesis')`))) throw new Error('SH20 is not first, or not marked genesis');
  step('tickers loaded from /tokens: ' + (await evaluate(`[...document.querySelectorAll('#tokens-body tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' ')).join(' / ')`)));

  await evaluate(`document.querySelector('#vault-body input[type=password]').value = 'e2e passphrase'`);
  await click('#vault-body button', 'Create vault');
  await waitFor(`document.querySelector('#vault-body').innerText.includes('Unlocked')`, 'vault');
  const stored = await evaluate(`localStorage.getItem('sh20.vault.v0')`);
  if (/seed|GENE/.test(stored)) throw new Error('vault stored in clear');
  step('vault created, stored encrypted (' + stored.length + ' bytes)');
  const address = await evaluate(`document.querySelector('#address')?.textContent`);
  if (!/^tsh201[02-9ac-hj-np-z]{162}$/.test(address)) throw new Error('no signet sh20 address shown: ' + address);
  step('sh20 address: ' + address.slice(0, 24) + '…');
  const words = await evaluate(`[...document.querySelectorAll('#words li')].map((li) => li.textContent).join(' ')`);
  if (words.split(' ').length !== 12) throw new Error('the 12 recovery words are not shown on creation');
  step('recovery words shown once: ' + words.split(' ').slice(0, 2).join(' ') + ' … (12)');

  await waitFor(`[...document.querySelectorAll('#wallet-body button')].some((b) => b.textContent === 'UniSat' && !b.disabled)`, 'UniSat detected');
  await click('#wallet-body button', 'UniSat');
  await waitFor(`document.querySelector('#wallet-body').innerText.includes('connected')`, 'wallet');
  step('wallet: ' + (await evaluate(`document.querySelector('#wallet-body p').innerText`)));

  await evaluate(`${row}.querySelector('button').click()`);
  await waitFor(`[...document.querySelectorAll('#mint-body button')].some((b) => b.textContent.includes('Prepare'))`, 'mint panel');
  if (LIAR) {
    await waitFor(`document.querySelector('#mint-body').innerText.includes('Mint refused')`, 'refusal');
    const refused = await evaluate(`document.querySelector('#mint-body .err').innerText`);
    if (!/payScript/.test(refused)) throw new Error('refused for the wrong reason: ' + refused);
    if (!(await evaluate(`[...document.querySelectorAll('#mint-body button')].find((b) => b.textContent.includes('Prepare')).disabled`))) throw new Error('Prepare still enabled');
    step(refused);
    ws.close();
    console.log('\nOK: the lying indexer blocked the mint');
    return;
  }
  // a batch of 2 mints (wire v0.3): one note of 2 × lim
  await evaluate(`(() => { const k = document.querySelector('#mint-body input[name=k]'); k.value = '2'; k.dispatchEvent(new Event('input')); })()`);
  if (!(await evaluate(`document.querySelector('#mint-body dl').innerText.includes('2,000 ${TICKER} (one public note, 2 mints)')`))) throw new Error('batch not shown');
  await click('#mint-body button', 'Prepare');
  await waitFor(`[...document.querySelectorAll('#mint-body button')].some((b) => b.textContent.includes('Sign with'))`, 'prepared tx');
  const source = D0 ? 'checked against the DEPLOY' : 'checked against the profile constants';
  if (!(await evaluate(`document.querySelector('#mint-body').innerText.includes(${JSON.stringify(source)})`))) throw new Error(`"${source}" not shown`);
  if (!(await evaluate(`document.querySelector('#mint-body').innerText.includes('2 agree on these terms')`))) throw new Error('cross-check not shown');
  step('prepared: ' + (await evaluate(`document.querySelector('#mint-body div dl').innerText.replace(/\\n/g, ' | ')`)));
  await click('#mint-body button', 'Sign with');
  await waitFor(`document.querySelector('#mint-body').innerText.includes('Broadcast:')`, 'broadcast');
  step(await evaluate(`document.querySelector('#mint-body .ok').innerText`));

  await click('#notes button', 'Sync');
  await waitFor(`document.querySelector('#notes-body').innerText.includes('in tree')`, 'note found in the tree', 600); // the first sync derives 50 note keys
  if (!(await evaluate(`document.querySelector('#notes-body tbody').innerText.includes('2,000')`))) throw new Error('the batch note is not 2,000');
  step('my notes: ' + (await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`)));
  step('sync: ' + (await evaluate(`document.querySelector('#sync-status').innerText`)));
  const leaks = urls.filter((u) => /\/path\/|\/nullifier\//.test(u));
  if (leaks.length) throw new Error('per-note requests sent: ' + leaks.join(', '));
  step(`${urls.filter((u) => u.includes(':80')).length} requests to the indexers and Esplora, none per note`);

  // a private TRANSFER of 700, proved in the page (thread pool if isolated, else one thread)
  const setField = (sel, value) => evaluate(`(() => { const i = document.querySelector(${JSON.stringify(sel)}); i.value = ${JSON.stringify(value)}; i.dispatchEvent(new Event('input')); i.dispatchEvent(new Event('change')); })()`);
  await waitFor(`!document.querySelector('#send-body button[name=send]')?.disabled`, 'send enabled');
  await setField('#send-body input[name=amount]', '700');
  await setField('#send-body input[name=to]', RECIPIENT);
  const isolated = await evaluate('self.crossOriginIsolated === true');
  const t0 = Date.now();
  await click('#send-body button', 'Prove and send');
  await waitFor(`document.querySelector('#send-out')?.innerText.includes('broadcast.')`, 'transfer broadcast', LONG);
  step(`TRANSFER (${isolated ? 'isolated: thread pool' : 'not isolated: one thread'}, ${((Date.now() - t0) / 1000).toFixed(0)} s in all): ` + (await evaluate(`document.querySelector('#send-out .ok').innerText`)));
  await click('#notes button', 'Sync');
  await waitFor(`document.querySelector('#notes-body').innerText.includes('received, sealed')`, 'change found by scanning', 600);
  const notesNow = await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`);
  if (!/1,300 in tree/.test(notesNow) || !/yes, block/.test(notesNow)) throw new Error('after the transfer: ' + notesNow);
  step('after the transfer: ' + notesNow);

  // a DEPLOY: with D > 0 it burns 1,000 SH20 with a proof (paid by the 1,300 of change); with D = 0, one OP_RETURN
  await evaluate(`(() => { const i = document.querySelector('#deploy-body input'); i.value = '${NEW_TICKER}'; i.dispatchEvent(new Event('change')); })()`);
  await waitFor(`document.querySelector('#deploy-body').innerText.includes('Envelope')`, 'deploy plan');
  const plan = await evaluate(`document.querySelector('#deploy-body dl').innerText.replace(/\\n/g, ' | ')`);
  const want = D0 ? ['D = 0', '56 bytes in one OP_RETURN'] : ['1,000 SH20 burned with a proof', '2 indexers agree on D', 'one note would pay the burn', '880 bytes in a tapscript witness'];
  for (const w of want) if (!plan.includes(w)) throw new Error(`deploy screen lacks "${w}": ${plan}`);
  step('deploy screen: ' + plan);
  await waitFor(`!document.querySelector('#deploy-body button[name=deploy]').disabled`, 'deploy enabled');
  await evaluate(`document.querySelector('#deploy-body button[name=deploy]').click()`);
  await waitFor(`/broadcast/.test(document.querySelector('#deploy-out')?.innerText ?? '')`, 'deploy broadcast', LONG);
  step('DEPLOY: ' + (await evaluate(`document.querySelector('#deploy-out .ok').innerText`)));
  await click('#tokens h2 button', 'Refresh');
  await waitFor(`[...document.querySelectorAll('#tokens-body strong')].some((x) => x.textContent === '${NEW_TICKER}')`, 'the new ticker deployed');
  step('tickers now: ' + (await evaluate(`[...document.querySelectorAll('#tokens-body strong')].map((x) => x.textContent).join(', ')`)));
  await click('#notes button', 'Sync');
  if (!D0) await waitFor(`document.querySelector('#notes-body').innerText.replace(/\\s+/g, ' ').includes(' 300 in tree')`, 'the change of the burn', 600);
  await waitFor(`!document.querySelector('#scan').disabled`, 'the sync to finish', 600);
  const before = await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`);
  step('notes: ' + before);

  // restore on an empty device from the 12 words alone: the same notes come back, public and sealed
  await waitFor(`!document.querySelector('#scan').disabled`, 'the sync to finish', 600);
  await click('#vault-body button', 'Lock');
  await evaluate(`localStorage.removeItem('sh20.vault.v0')`);
  await send('Page.reload');
  await waitFor(`!!document.querySelector('#vault-body textarea[name=words]')`, 'restore form');
  await evaluate(`document.querySelector('#vault-body textarea[name=words]').value = ${JSON.stringify(words)}`);
  await click('#vault-body button', 'Restore from words');
  await waitFor(`document.querySelector('#notes-body').innerText.includes('received, sealed')`, 'notes found again from the words', 900);
  await sleep(500);
  const after = await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`);
  const amounts = (t) => [...t.matchAll(/(\d[\d,]*) (in tree|spending)/g)].map((m) => m[1]).sort().join(' ');
  if (amounts(after) !== amounts(before)) throw new Error(`restored from words: ${after}\nwas: ${before}`);
  if ((await evaluate(`document.querySelector('#address').textContent`)) !== address) throw new Error('another address after the restore');
  step('restored from the 12 words: same address, same notes: ' + after);

  ws.close();
  // a 404 on /nullifiers is expected from an indexer without the route (before PR #5): spends shown as unknown
  const real = problems.filter((p) => !/favicon/.test(p) && !/404.*\/nullifiers\?from=/.test(p));
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
