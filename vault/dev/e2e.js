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
// E2E_HOST=<cid>.ipfs.localhost: a subdomain gateway (the page isolates itself with its service worker)
// E2E_PATH=/ipfs/<cid>/vault/: a path gateway (the page refuses to run there: docs/AUDIT.md §8.1)
const HOST = process.env.E2E_HOST || 'localhost';
const PAGE = `http://${HOST}:8000${process.env.E2E_PATH || '/vault/'}?indexer=${INDEXERS}&esplora=http://127.0.0.1:8020/esplora`;
const PATH_GATEWAY = /^\/ip[fn]s\//.test(process.env.E2E_PATH || '');
const PORT = 9333;

// Runs in the page before any of its scripts.
const FAKE_UNISAT = `(() => {
  const ADDR = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c';
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  // Adds PSBT_IN_TAP_KEY_SIG (64 zero bytes) to the input maps it is asked to sign (toSignInputs),
  // as a wallet does; an input signed already (a seller's lock) is left as it is.
  function sign(psbtHex, indexes) {
    const b = unhex(psbtHex);
    let p = 5;
    const cs = () => { const f = b[p++]; if (f < 0xfd) return f; const v = b[p] | (b[p + 1] << 8); p += 2; return v; };
    let nIn = 0;
    for (;;) { // the global map; its unsigned transaction gives the number of inputs
      const k = cs();
      if (k === 0) break;
      const type = b[p];
      p += k;
      const v = cs();
      if (type === 0x00) nIn = b[p + 4];
      p += v;
    }
    const skipMap = () => { for (;;) { const k = cs(); if (k === 0) return p - 1; p += k; const v = cs(); p += v; } };
    const out = [];
    let last = 0;
    for (let i = 0; i < nIn; i++) {
      const end = skipMap();
      out.push(b.slice(last, end));
      if (indexes.includes(i)) out.push(Uint8Array.from([1, 0x13, 64, ...new Uint8Array(64)]));
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
    signPsbt: async (h, opts) => { window.__signed = opts; return sign(h, opts.toSignInputs.map((x) => x.index)); },
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
    throw new Error(`timeout waiting for ${what}; page problems: ${problems.join(' | ') || 'none'}; page says: ${await evaluate('document.body.innerText')}`);
  };
  const click = (sel, text) => evaluate(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(sel)})].find((x) => x.textContent.includes(${JSON.stringify(text)})); if (!b) throw new Error('no button ${text}'); if (b.disabled) throw new Error('button ${text} disabled: ' + b.title); b.click(); return true; })()`);

  await send('Network.enable');
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', { source: FAKE_UNISAT });
  await send('Page.navigate', { url: PAGE });

  const step = (s) => console.log('·', s);
  if (PATH_GATEWAY) {
    // docs/AUDIT.md §8.1: nothing runs on a path gateway, not even the servers of the link
    await waitFor(`!!document.querySelector('#path-gateway')`, 'the path gateway refusal');
    const page = await evaluate(`(async () => ({ text: document.body.innerText, forms: document.querySelectorAll('form, input, textarea').length, links: [...document.querySelectorAll('#path-gateway a')].map((a) => a.href), registrations: navigator.serviceWorker ? (await navigator.serviceWorker.getRegistrations()).length : 0, stored: Object.keys(localStorage) }))()`);
    if (page.forms) throw new Error('a form on a path gateway');
    if (page.registrations) throw new Error('a service worker on a path gateway');
    if (dialogs.length) throw new Error('the page asked about the link servers on a path gateway: ' + dialogs.join(' / '));
    if (page.stored.length) throw new Error('the page stored something on a path gateway: ' + page.stored.join(', '));
    const cid = process.env.E2E_PATH.split('/')[2];
    if (!page.links.some((u) => u.startsWith(`https://${cid}.ipfs.dweb.link/`))) throw new Error('no subdomain gateway named: ' + page.links.join(' '));
    step('refused: ' + page.links.join(' · '));
    ws.close();
    console.log('\nOK: the path gateway page refuses to run and names its subdomain address');
    return;
  }
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
  const iso = await evaluate(`(async () => ({ isolated: self.crossOriginIsolated === true, controlled: !!navigator.serviceWorker?.controller, registrations: navigator.serviceWorker ? (await navigator.serviceWorker.getRegistrations()).length : 0, mode: document.querySelector('#prover-mode')?.textContent }))()`);
  if (/\.ipfs\./.test(HOST) && !(iso.isolated && iso.controlled)) throw new Error('the subdomain gateway page did not isolate itself: ' + JSON.stringify(iso));
  step(`isolation: ${iso.mode}${iso.registrations ? ` (${iso.registrations} service worker)` : ''}`);
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

  // a DEPLOY: with D > 0 it burns 1,000 SH20 with a proof (paid by the 1,300 of change). Either way a commit,
  // then the reveal once the commit is N blocks deep (SPEC-WIRE §5); the vault is reloaded in the middle
  await evaluate(`(() => { const i = document.querySelector('#deploy-body input'); i.value = '${NEW_TICKER}'; i.dispatchEvent(new Event('change')); })()`);
  await waitFor(`document.querySelector('#deploy-body').innerText.includes('Envelope')`, 'deploy plan');
  const plan = await evaluate(`document.querySelector('#deploy-body dl').innerText.replace(/\\n/g, ' | ')`);
  const want = D0 ? ['D = 0', '56 bytes in a tapscript witness (a commit, then the reveal 6 blocks later'] : ['1,000 SH20 burned with a proof', '2 indexers agree on D', 'one note would pay the burn', '880 bytes in a tapscript witness (a commit, then the reveal 6 blocks later'];
  for (const w of want) if (!plan.includes(w)) throw new Error(`deploy screen lacks "${w}": ${plan}`);
  step('deploy screen: ' + plan);
  await waitFor(`!document.querySelector('#deploy-body button[name=deploy]').disabled`, 'deploy enabled');
  await evaluate(`document.querySelector('#deploy-body button[name=deploy]').click()`);
  await waitFor(`/the commit is broadcast/.test(document.querySelector('#deploy-out')?.innerText ?? '')`, 'the DEPLOY commit', LONG);
  step('DEPLOY: ' + (await evaluate(`document.querySelector('#deploy-out .ok').innerText`)));
  const countdown = () => evaluate(`document.querySelector('#pending-body .countdown')?.textContent ?? ''`);
  await waitFor(`/reveal in 5 blocks/.test(document.querySelector('#pending-body .countdown')?.textContent ?? '')`, 'the countdown');
  step('countdown: ' + (await countdown()));
  if (!D0 && !/ 1,300 spending/.test(await evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`))) throw new Error('the SH20 note the burn spends is not reserved');
  const mine = (count) => fetch(`http://127.0.0.1:8020/esplora/mine?n=${count}`, { method: 'POST' }).then((r) => r.text());
  // two blocks pass, then the page is reloaded: the signed reveal and the countdown come back from the encrypted vault
  await mine(2);
  await send('Page.reload');
  await waitFor(`!!document.querySelector('#vault-body input[type=password]')`, 'the unlock form after the reload');
  await evaluate(`document.querySelector('#vault-body input[type=password]').value = 'e2e passphrase'`);
  await click('#vault-body button', 'Unlock');
  await waitFor(`/reveal in 3 blocks/.test(document.querySelector('#pending-body .countdown')?.textContent ?? '')`, 'the countdown after the reload', 300);
  step('after a reload: ' + (await countdown()));
  await waitFor(`[...document.querySelectorAll('#wallet-body button')].some((b) => b.textContent === 'UniSat' && !b.disabled)`, 'UniSat after the reload');
  await click('#wallet-body button', 'UniSat');
  await waitFor(`document.querySelector('#wallet-body').innerText.includes('connected')`, 'the wallet again');
  await mine(2); // 4 of 6: still waiting
  await click('#tokens h2 button', 'Refresh');
  await waitFor(`/reveal in 1 block/.test(document.querySelector('#pending-body .countdown')?.textContent ?? '')`, 'one block to go');
  await mine(1);
  await click('#tokens h2 button', 'Refresh');
  await waitFor(`/the reveal is broadcast/.test(document.querySelector('#deploy-out')?.innerText ?? '')`, 'the reveal, once the commit is 6 blocks deep', 300);
  step('DEPLOY: ' + (await evaluate(`document.querySelector('#deploy-out .ok').innerText`)));
  await click('#tokens h2 button', 'Refresh');
  await waitFor(`[...document.querySelectorAll('#tokens-body strong')].some((x) => x.textContent === '${NEW_TICKER}')`, 'the new ticker deployed');
  step('tickers now: ' + (await evaluate(`[...document.querySelectorAll('#tokens-body strong')].map((x) => x.textContent).join(', ')`)));
  await click('#notes button', 'Sync');
  if (!D0) await waitFor(`document.querySelector('#notes-body').innerText.replace(/\\s+/g, ' ').includes(' 300 in tree')`, 'the change of the burn', 600);
  await waitFor(`!document.querySelector('#scan').disabled`, 'the sync to finish', 600);

  // BURN, then LIST → offer → TAKE (bought by this vault itself), and a LIST cancelled
  const notesText = () => evaluate(`document.querySelector('#notes-body tbody').innerText.replace(/\\s+/g, ' ')`);
  const syncDone = async () => {
    await click('#notes button', 'Sync');
    await waitFor(`!document.querySelector('#scan').disabled`, 'the sync to finish', 600);
  };
  const spend = async (action, fields, what, label) => {
    await evaluate(`(() => { const a = document.querySelector('#send-body select[name=action]'); a.value = '${action}'; a.dispatchEvent(new Event('change')); })()`);
    await waitFor(`document.querySelector('#send-body select[name=ticker]')?.value === '${TICKER}'`, 'ticker in the send panel');
    for (const [k, val] of Object.entries(fields)) await setField(`#send-body input[name=${k}]`, val);
    await evaluate(`document.querySelector('#send-body button[name=send]').click()`);
    await waitFor(`document.querySelector('#send-out .ok')?.innerText.startsWith(${JSON.stringify(label)})`, what, LONG);
    step(what + ': ' + (await evaluate(`document.querySelector('#send-out .ok').innerText`)));
    await syncDone();
  };
  await spend('burn', { amount: '100' }, 'BURN', `BURN of 100 ${TICKER}: broadcast`);
  await spend('list', { amount: '150', price: '5000' }, 'LIST', `LIST of 150 ${TICKER} for 5,000 sats: broadcast`);
  const listingRow = (amount) => `[...document.querySelectorAll('#market-body tbody tr')].find((r) => r.children[1].textContent === '${amount}')`;
  await waitFor(`${listingRow(150)}?.children[3].textContent === 'ACTIVE'`, 'the listing ACTIVE');
  await evaluate(`${listingRow(150)}.querySelector('button[name=offer]').click()`);
  await waitFor(`!!document.querySelector('#offer-text')`, 'the offer');
  const offer = await evaluate(`document.querySelector('#offer-text').textContent`);
  if (!/^sh20offer1:[0-9a-f]{64}:[0-9a-f]{130}$/.test(offer)) throw new Error('offer: ' + offer);
  const signedFor = await evaluate(`document.querySelector('#listing-out').innerText`);
  if (!new RegExp(`Offer signed for: 150 ${TICKER} for 5,000 sats, paid to tb1`).test(signedFor) || !/vouched for by the listing this vault sent/.test(signedFor)) throw new Error('the signed terms are not shown: ' + signedFor);
  if (dialogs.some((d) => d.includes('cannot vouch'))) throw new Error('asked about a listing this vault sent');
  step('offer: ' + offer.slice(0, 40) + '… (' + signedFor.split('\n')[0] + ')');
  await evaluate(`(() => { const t = document.querySelector('#market-body textarea[name=offer]'); t.value = ${JSON.stringify(offer)}; t.dispatchEvent(new Event('input')); })()`);
  await evaluate(`document.querySelector('#market-body button[name=check]').click()`);
  await waitFor(`!!document.querySelector('#market-body button[name=buy]')`, 'the offer checked');
  step('checked: ' + (await evaluate(`document.querySelector('#market-body dl').innerText.replace(/\\n/g, ' | ')`)));
  await evaluate(`document.querySelector('#market-body button[name=buy]').click()`);
  await waitFor(`/broadcast/.test(document.querySelector('#buy-out')?.innerText ?? '')`, 'the TAKE broadcast');
  await syncDone();
  await waitFor(`${listingRow(150)}?.children[3].textContent === 'SOLD'`, 'the listing SOLD');
  if (!/ 150 in tree/.test(await notesText())) throw new Error('no public note of 150 after the TAKE: ' + (await notesText()));
  step('TAKE: listing SOLD, a public note of 150 in the tree');
  // paid to another address: a TAKE whose change goes to the payee's address would count as paid (SOLD to oneself)
  await spend('list', { amount: '50', price: '1000', payTo: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' }, 'LIST', `LIST of 50 ${TICKER} for 1,000 sats: broadcast`);
  await waitFor(`${listingRow(50)}?.children[3].textContent === 'ACTIVE'`, 'the second listing ACTIVE');
  await evaluate(`${listingRow(50)}.querySelector('button[name=cancel]').click()`);
  await waitFor(`/broadcast/.test(document.querySelector('#listing-out')?.innerText ?? '')`, 'the cancel broadcast');
  await syncDone();
  await waitFor(`${listingRow(50)}?.children[3].textContent === 'CANCELLED'`, 'the listing CANCELLED');
  if (!/ 50 in tree/.test(await notesText())) throw new Error('no public note of 50 after the cancel');
  step('cancel: listing CANCELLED, the 50 back as a public note');
  const listingsBefore = await evaluate(`[...document.querySelectorAll('#market-body tbody tr')].map((r) => r.children[1].textContent + ' ' + r.children[3].textContent).sort().join(', ')`);

  // restore on an empty device from the 12 words alone: the same notes come back, public and sealed
  await waitFor(`!document.querySelector('#scan').disabled`, 'the sync to finish', 600);
  const before = await notesText();
  step('notes: ' + before);
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
  await waitFor(`document.querySelectorAll('#market-body tbody tr').length === 2`, 'the listings found again by their lock keys');
  const listingsAfter = await evaluate(`[...document.querySelectorAll('#market-body tbody tr')].map((r) => r.children[1].textContent + ' ' + r.children[3].textContent).sort().join(', ')`);
  if (listingsAfter !== listingsBefore) throw new Error(`listings after the restore: ${listingsAfter}, before: ${listingsBefore}`);
  step('listings found again from the words: ' + listingsAfter);

  // docs/AUDIT.md §8.4: restored without a passphrase, no backup in clear; a passphrase added here, then the words behind it
  if (!(await evaluate(`document.querySelector('#vault-body button[name=backup]').disabled`))) throw new Error('a backup offered in clear');
  await click('#vault-body button', 'Set a passphrase');
  await evaluate(`(() => { for (const n of ['new-pass', 'new-pass-again']) document.querySelector('#vault-body input[name=' + n + ']').value = 'e2e second'; })()`);
  await click('#vault-body button', 'Set passphrase');
  await waitFor(`document.querySelector('#vault-body').innerText.includes('encrypted with your passphrase')`, 'the passphrase set');
  if (/plain|seed/.test(await evaluate(`localStorage.getItem('sh20.vault.v0')`))) throw new Error('still stored in clear after setting a passphrase');
  if (await evaluate(`document.querySelector('#vault-body button[name=backup]').disabled`)) throw new Error('no backup once encrypted');
  await click('#vault-body button', 'Show recovery words');
  await waitFor(`!!document.querySelector('#vault-body input[name=words-pass]')`, 'the passphrase asked for the words');
  if (await evaluate(`!!document.querySelector('#words')`)) throw new Error('the words shown before the passphrase');
  await evaluate(`document.querySelector('#vault-body input[name=words-pass]').value = 'e2e second'`);
  await click('#vault-body button', 'Show the words');
  await waitFor(`document.querySelectorAll('#words li').length === 12`, 'the words after the passphrase');
  step('passphrase added after the restore: stored encrypted, backup enabled, words shown after the passphrase');

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
