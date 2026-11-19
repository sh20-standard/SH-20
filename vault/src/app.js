// SH-20 vault page. Plain DOM, no framework; data from the network is only
// ever written with textContent.

import { Vault, LOCK_GAP } from './keys.js';
import { WALLETS } from './wallets.js';
import { IndexerApi, Esplora } from './api.js';
import { buildMint, mintProblems, mintsLeft } from './mint.js';
import { verifyMintTerms } from './deploy.js';
import { planDeploy } from './deploy-plan.js';
import { crossCheck, TERMS, profileOf } from './consensus.js';
import { finalizePsbt, sameUnsignedTx, scriptType, addressToScript } from './btc.js';
import { frHex, frFromHex } from './fr.js';
import { Sync } from './sync.js';
import { defaultCache } from './cache.js';
import { PAY_MODE, PUBLIC_RHO, MINT_BATCH_MAX, noteLeaf, tickerT } from './sh20.js';
import { toHex, fromHex } from './bytes.js';
import { loadProver } from './prover.js';
import { ensureIsolation } from './isolation.js';
import { available } from './sh20.js';
import { planTransfer, planDeployBurn, proveSpend, planCarrier, revealFor, pendingRecord, planFromPending, planPlainDeploy, revealSchedule } from './send.js';
import { poolProblem, claimProblem, planBurn, planList, listOutputs, signOffer, encodeOffer, decodeOffer, offerValid, listingFromChain, buildTake, buildCancel, buildClaim } from './market.js';

if (window.top !== window.self) {
  document.documentElement.textContent = 'The SH-20 vault refuses to run inside a frame.';
  throw new Error('framed');
}

// On a subdomain gateway the page isolates itself with the service worker and reloads once
// (isolation.js), before anything else runs; never on a path gateway.
const isolation = await ensureIsolation();
if (isolation === 'reloading') await new Promise(() => {});

// Note keys and sealing go through WebCrypto's X25519 (circuit/js/webcrypto.js): without it, stop here.
if (!(await available())) {
  document.querySelector('main').replaceChildren();
  document.getElementById('warnings').textContent = window.isSecureContext
    ? 'This browser has no X25519 in WebCrypto, which the vault needs for its keys and sealed notes: use Chrome 133, Firefox 130, Safari 17 or newer.'
    : 'WebCrypto needs a secure context: open the vault over https, or from localhost.';
  document.getElementById('warnings').className = 'warn err';
  await new Promise(() => {});
}

// ---- settings -----------------------------------------------------------------

const SETTINGS_KEY = 'sh20.vault.settings';
// `indexer` holds one or more URLs (one per line, or comma-separated); the first is the primary.
const DEFAULTS = { indexer: 'http://127.0.0.1:8020', esplora: 'https://mempool.space/signet/api' }; // 8020: indexer/bin/follow.js
const urlList = (s) => [...new Set(s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))];

// Servers given in the URL (?indexer=…&esplora=…) are never applied silently: a
// link could point the vault at a lying indexer (wrong payScript or price) or
// Esplora. They need a confirmation naming them, last for this tab only, and
// keep a warning on screen.
let urlServers = null;

function loadSettings() {
  let s = { ...DEFAULTS };
  try {
    s = { ...s, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') };
  } catch {}
  const q = new URLSearchParams(location.search);
  const asked = Object.fromEntries(['indexer', 'esplora'].filter((k) => q.get(k) && q.get(k) !== s[k]).map((k) => [k, q.get(k)]));
  if (Object.keys(asked).length) {
    const list = Object.entries(asked).map(([k, v]) => `${k}: ${v}`).join('\n');
    if (confirm(`This link asks the vault to use other servers for this tab:\n\n${list}\n\nA dishonest server can show a wrong price or payment address. Use them?`)) {
      s = { ...s, ...asked };
      urlServers = asked;
    }
  }
  return s;
}

let settings = loadSettings();
const MAX_FEE_SATS = 20000n; // above this, ask before signing
let indexers = urlList(settings.indexer).map((u) => new IndexerApi(u));
let indexer = indexers[0]; // primary: lists tokens and notes
let esplora = new Esplora(settings.esplora);
const explorerTx = (id) => settings.esplora.replace(/\/api\/?$/, '') + '/tx/' + id;

// ---- state ----------------------------------------------------------------------

const st = { vault: null, wallet: null, tokens: [], status: null, tip: null, sync: null, profiles: [], results: {} };

/** Shows `nodes` in the panel `id` and keeps them there across renders. */
function result(id, ...nodes) {
  st.results[id] = nodes.flat().filter(Boolean);
  $(id)?.replaceChildren(...st.results[id]);
}
const resultBox = (id) => h('div', { id }, ...(st.results[id] ?? []));

// ---- DOM helpers ----------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v === null || v === undefined) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  return el;
}

const fill = (id, ...kids) => $(id).replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
const sats = (v) => `${BigInt(v).toLocaleString('en-US')} sats`;
const units = (v) => BigInt(v).toLocaleString('en-US');
const short = (x) => (x.length > 20 ? `${x.slice(0, 10)}…${x.slice(-8)}` : x);

function busy(button, fn) {
  return async (...args) => {
    button.disabled = true;
    try {
      await fn(...args);
    } catch (e) {
      report(e);
    } finally {
      button.disabled = false;
    }
  };
}

function report(e) {
  console.error(e);
  const box = h('div', { class: 'warn err' }, e.message || String(e));
  $('warnings').append(box);
  setTimeout(() => box.remove(), 12000);
}

// ---- warnings that do not go away ------------------------------------------------

function staticWarnings() {
  const w = [];
  if (/\/ip[fn]s\//.test(location.pathname)) {
    w.push('This page is served from a path gateway (…/ipfs/<cid>/). Every site on this gateway shares one origin and could read the vault. Open it from a subdomain gateway (<cid>.ipfs.dweb.link), a local IPFS node or a local copy.');
  }
  if (urlServers) {
    w.push(`Using servers from the link, not your saved settings: ${Object.entries(urlServers).map(([k, v]) => `${k} ${v}`).join(', ')}. Check the price and outputs before signing.`);
  }
  if (!window.isSecureContext) w.push('Not a secure context: passphrase encryption is unavailable. Use https or localhost.');
  w.push('Note keys and sealing follow docs/SPEC-NOTES.md, draft v0.3, not audited yet: signet only.');
  fill('warnings', w.map((t) => h('div', { class: 'warn' }, t)));
}

// ---- vault ----------------------------------------------------------------------

function renderVault() {
  if (st.vault) {
    const v = st.vault;
    fill('vault-body',
      h('p', {}, h('span', { class: 'ok' }, 'Unlocked. '), `${v.state.next} public note key(s) used, ${v.encrypted ? 'encrypted with your passphrase' : 'stored without passphrase'}.`),
      h('p', {}, 'Your sh20 address (signet), for receiving sealed notes: '),
      h('p', { class: 'mono', id: 'address' }, v.address),
      v.state.obsolete?.length ? h('p', { class: 'muted' }, `${v.state.obsolete.length} note(s) made with the provisional keys of draft v0.2 are kept aside in the backup: they cannot exist on a v0.3 chain.`) : null,
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'secondary', onclick: () => navigator.clipboard?.writeText(v.address).catch(report) }, 'Copy address'),
        v.words ? h('button', { type: 'button', class: 'secondary', onclick: () => { st.showWords = !st.showWords; renderVault(); } }, st.showWords ? 'Hide recovery words' : 'Show recovery words') : null,
        h('button', { type: 'button', class: 'secondary', onclick: downloadBackup }, 'Download backup'),
        h('button', { type: 'button', class: 'secondary', onclick: () => { v.lock(); st.vault = null; st.showWords = false; renderAll(); } }, 'Lock')),
      st.showWords && v.words ? wordsBox(v.words) : null,
      h('p', { class: 'muted' }, v.words
        ? 'The 12 recovery words restore everything (keys, notes, address) in any wallet that follows SPEC-NOTES. Write them on paper; anyone who reads them owns your notes. A new version of this page on IPFS has a new origin and an empty storage: restore there from the words or the backup.'
        : 'This vault was made before recovery words existed: only its backup file restores it (encrypted if you set a passphrase).'));
    return;
  }
  if (Vault.exists(localStorage)) {
    const pass = h('input', { type: 'password', placeholder: 'passphrase (empty if none)', autocomplete: 'current-password' });
    const btn = h('button', { type: 'submit' }, 'Unlock');
    const form = h('form', { class: 'row' }, pass, btn);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(btn, async () => {
        st.vault = await Vault.open(localStorage, pass.value);
        renderAll();
        syncNotes().catch(report);
      })();
    });
    fill('vault-body', h('p', {}, 'A vault exists on this device.'), form);
    return;
  }
  const pass = h('input', { type: 'password', placeholder: 'passphrase (recommended)', autocomplete: 'new-password' });
  const create = h('button', { type: 'submit' }, 'Create vault');
  const form = h('form', { class: 'row' }, pass, create);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    busy(create, async () => {
      if (!pass.value && !confirm('Create the vault without a passphrase? Anyone using this browser profile could read it.')) return;
      st.vault = await Vault.create(localStorage, pass.value);
      st.showWords = true; // shown once on creation, to be written down
      navigator.storage?.persist?.().catch(() => {});
      renderAll();
    })();
  });
  const file = h('input', { type: 'file', accept: '.json,application/json' });
  const rpass = h('input', { type: 'password', placeholder: 'backup passphrase', autocomplete: 'off' });
  const restore = h('button', { type: 'button', class: 'secondary' }, 'Restore backup');
  restore.addEventListener('click', busy(restore, async () => {
    if (!file.files[0]) throw new Error('choose a backup file');
    st.vault = await Vault.restore(localStorage, await file.files[0].text(), rpass.value);
    renderAll();
    syncNotes({ full: true }).catch(report); // a restored vault looks for its notes in every leaf
  }));
  const words = h('textarea', { rows: '2', name: 'words', spellcheck: 'false', autocomplete: 'off', placeholder: '12 recovery words' });
  const wpass = h('input', { type: 'password', placeholder: 'new passphrase for this device', autocomplete: 'new-password' });
  const fromWords = h('button', { type: 'button', class: 'secondary' }, 'Restore from words');
  fromWords.addEventListener('click', busy(fromWords, async () => {
    st.vault = await Vault.fromWords(localStorage, words.value, wpass.value);
    words.value = '';
    renderAll();
    syncNotes({ full: true }).catch(report); // looks for its notes in every leaf
  }));
  fill('vault-body',
    h('p', {}, 'No vault on this device. Its 12 recovery words are generated here and never leave it.'),
    form,
    h('p', { class: 'muted' }, 'Or restore one:'),
    h('label', {}, 'From its recovery words', words),
    h('div', { class: 'row' }, wpass, fromWords),
    h('div', { class: 'row' }, file, rpass, restore));
}

function wordsBox(words) {
  return h('div', { class: 'words' },
    h('p', {}, h('strong', {}, 'Recovery words. '), 'Write them down in this order and keep them offline.'),
    h('ol', { id: 'words' }, words.split(' ').map((w) => h('li', { class: 'mono' }, w))));
}

function downloadBackup() {
  const blob = new Blob([st.vault.exportBackup()], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'sh20-vault-backup.json' });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---- wallet ----------------------------------------------------------------------

function renderWallet() {
  if (st.wallet) {
    const w = st.wallet;
    fill('wallet-body',
      h('p', {}, h('span', { class: 'ok' }, `${w.adapter.name} connected: `), h('code', {}, w.address), ` (${w.type})`),
      h('button', { type: 'button', class: 'secondary', onclick: () => { st.wallet = null; renderAll(); } }, 'Disconnect'));
    return;
  }
  fill('wallet-body', h('div', { class: 'row' }, WALLETS.map((ad) => {
    const b = h('button', { type: 'button', disabled: !ad.detect() }, ad.name);
    b.addEventListener('click', busy(b, async () => {
      const acc = await ad.connect();
      let type;
      try {
        type = scriptType(addressToScript(acc.address));
      } catch {
        throw new Error(`${ad.name} gave ${acc.address}, which is not a signet address. Switch the wallet to Signet.`);
      }
      // a second address of the wallet (Xverse's and Leather's taproot one): only a cancel's change goes there
      let otherAddress = null;
      try {
        if (acc.otherAddress && acc.otherAddress !== acc.address) otherAddress = (addressToScript(acc.otherAddress), acc.otherAddress);
      } catch {}
      st.wallet = { adapter: ad, ...acc, type, otherAddress };
      renderAll();
    }));
    return b;
  })), h('p', { class: 'muted' }, WALLETS.some((w) => w.detect()) ? 'Pick a wallet set to Signet.' : 'No wallet extension detected (Xverse, UniSat or Leather).'));
}

// ---- tokens ----------------------------------------------------------------------

const payText = (t) => (t.payMode === PAY_MODE.NONE ? 'free' : `${sats(t.price)} ${t.payMode === PAY_MODE.BURN ? 'burned' : 'to deployer'}`);

async function refresh() {
  try {
    const [status, tokens] = await Promise.all([indexer.status(), indexer.tokens()]);
    st.status = status;
    st.tokens = tokens;
    const wrongNet = status.network && status.network !== 'signet';
    fill('indexer-status',
      wrongNet ? h('span', { class: 'err' }, `Indexer follows ${status.network}, not signet. `) : null,
      `Indexer at block ${status.height ?? '?'}`,
      status.digest ? ` · digest ${short(String(status.digest))}` : '',
      status.verifier === 'reject-all' ? ' · spends not verified yet' : '',
      ` · ${indexers.length} indexer${indexers.length > 1 ? 's' : ''} configured`);
    if (wrongNet) st.tokens = [];
  } catch (e) {
    st.tokens = [];
    fill('indexer-status', h('span', { class: 'err' }, `Indexer unreachable (${indexer.base}): ${e.message}`));
  }
  // the other indexers' profiles (D, activation height), for the deploy screen
  const others = await Promise.allSettled(indexers.slice(1).map((a) => a.status()));
  st.profiles = [st.status ? { base: indexer.base, ...profileOf(st.status) } : null,
    ...others.map((r, i) => (r.status === 'fulfilled' ? { base: indexers[i + 1].base, ...profileOf(r.value) } : null))].filter(Boolean);
  try {
    st.tip = await esplora.tipHeight();
  } catch {
    st.tip = null;
  }
  renderTokens();
  renderDeploy();
  processDeploys().catch(report);
}

function chainHeight() {
  return st.tip ?? st.status?.height ?? null;
}

function renderTokens() {
  if (!st.tokens.length) {
    fill('tokens-body', h('p', { class: 'muted' }, 'No ticker to show.'));
    return;
  }
  const H = chainHeight();
  const rows = st.tokens.map((t) => {
    const problems = H === null ? ['chain height unknown'] : mintProblems(t, H + 1);
    const b = h('button', { type: 'button', class: 'small', disabled: problems.length > 0, title: problems.join('; ') }, 'Mint');
    b.addEventListener('click', () => openMint(t.ticker));
    return h('tr', {},
      h('td', {}, h('strong', {}, t.ticker), t.genesis ? h('span', { class: 'muted' }, ' genesis') : null),
      h('td', { class: 'num' }, units(t.lim)),
      h('td', { class: 'num' }, `${units(t.mints)} / ${units((t.max - t.pre) / t.lim)}`),
      h('td', {}, payText(t)),
      h('td', {}, `${t.start}${t.end ? `–${t.end}` : '→'}`),
      h('td', { class: 'num' }, t.pre > 0n ? `${units(t.pre)} @ ${t.unlock}` : '0'),
      h('td', {}, problems.length ? h('span', { class: 'muted' }, problems[0]) : b));
  });
  fill('tokens-body', h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Ticker', 'Per mint', 'Mints', 'Price', 'Window', 'Team', ''].map((x) => h('th', {}, x)))),
    h('tbody', {}, rows))),
  h('p', { class: 'muted' }, `Chain tip ${H ?? '?'}; a mint sent now confirms at ${H === null ? '?' : H + 1} or later.`));
}

// ---- mint ------------------------------------------------------------------------

async function openMint(ticker) {
  $('mint').hidden = false;
  fill('mint-ticker', ticker);
  fill('mint-body', h('p', { class: 'muted' }, 'Loading…'));
  $('mint').scrollIntoView({ behavior: 'smooth' });
  try {
    const check = await crossCheck(indexers, ticker);
    renderMint(check, await esplora.feeRate());
  } catch (e) {
    fill('mint-body', h('p', { class: 'err' }, e.message));
  }
}

function checkNotes(check) {
  return [
    ...check.problems.map((p) => h('div', { class: 'warn err' }, `Mint refused: ${p}`)),
    ...check.warnings.map((w) => h('div', { class: 'warn' }, w)),
  ];
}

function renderMint(check, defaultFee) {
  const token = check.token;
  const need = check.problems.length ? ['resolve the indexer disagreement'] : [];
  if (!st.vault) need.push('unlock the vault');
  if (!st.wallet) need.push('connect a wallet');
  const fee = h('input', { type: 'number', min: '0.1', step: '0.1', value: String(defaultFee), class: 'narrow' });
  // batch mint (wire v0.3): k mints in one envelope, one note of k × lim for k × price, never more than what is left
  const most = Math.min(MINT_BATCH_MAX, Number(mintsLeft(token)));
  const count = h('input', { type: 'number', min: '1', max: String(Math.max(1, most)), step: '1', value: '1', class: 'narrow', name: 'k' });
  const receive = h('dd');
  const showCount = () => {
    const k = BigInt(Math.max(1, Math.min(most, Number(count.value) | 0)));
    receive.textContent = `${units(token.lim * k)} ${token.ticker} (one public note${k > 1n ? `, ${k} mints` : ''}) for ${token.payMode === PAY_MODE.NONE ? 'network fees only' : sats(token.price * k)}`;
  };
  count.addEventListener('input', showCount);
  showCount();
  const prep = h('button', { type: 'button', disabled: need.length > 0 }, 'Prepare transaction');
  const out = h('div');
  prep.addEventListener('click', busy(prep, () => prepareMint(token, Number(fee.value), Number(count.value), out)));
  fill('mint-body',
    h('dl', {},
      h('dt', {}, 'You receive'), receive,
      h('dt', {}, 'Price per mint'), h('dd', {}, payText(token)),
      h('dt', {}, 'Mints left'), h('dd', {}, units(mintsLeft(token))),
      h('dt', {}, 'Window'), h('dd', {}, `block ${token.start} to ${token.end || 'no end'}`)),
    checkNotes(check),
    h('div', { class: 'row' }, h('label', {}, `Mints (1 to ${Math.max(1, most)}) `, count), h('label', {}, 'Fee rate (sat/vB) ', fee), prep),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(' and ')}.`) : null,
    out);
}

async function prepareMint(shown, feeRate, k, out) {
  // ask every indexer again: the terms signed must be the ones shown, agreed on, and on chain
  const check = await crossCheck(indexers, shown.ticker);
  if (check.problems.length) throw new Error(`mint refused: ${check.problems.join('; ')}`);
  const token = check.token;
  if (TERMS.some((k) => String(token[k]) !== String(shown[k]))) throw new Error('the token terms changed since they were shown; open the mint again');
  // the mint terms come from the chain (the DEPLOY) or the profile (SH20), not from the indexer alone
  const source = await verifyMintTerms(esplora, token, check.profile);
  const tip = await esplora.tipHeight();
  const w = st.wallet;
  let utxos = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  if (!utxos) utxos = await esplora.utxos(w.address);
  if (!utxos.length) throw new Error(`no UTXO at ${w.address}; get signet coins from a faucet first`);
  const opening = await st.vault.opening(st.vault.state.next); // reserved only when signed
  const m = buildMint({ token, opening, payer: w, utxos, feeRate, tipHeight: tip, k });

  const sign = h('button', { type: 'button' }, `Sign with ${w.adapter.name} and broadcast`);
  sign.addEventListener('click', busy(sign, () => signAndSend(token, m, opening, out)));
  out.replaceChildren(
    h('dl', {},
      h('dt', {}, 'Inputs'), h('dd', {}, `${m.tx.vin.length} from ${short(w.address)}`),
      h('dt', {}, 'Outputs'), h('dd', {}, m.tx.vout.map((o, i) => `#${i} ${scriptType(o.script)} ${sats(o.value)}`).join(' · ')),
      h('dt', {}, 'Size'), h('dd', {}, `≈ ${m.vsizeEstimate} vB (a plain P2TR payment is ≈ 154 vB)`),
      h('dt', {}, 'Network fee'), h('dd', {}, sats(m.fee)),
      h('dt', {}, 'You receive'), h('dd', {}, `${units(m.v)} ${token.ticker}${m.k > 1 ? ` (${m.k} mints in one note)` : ''}`),
      h('dt', {}, 'Mint price'), h('dd', {}, token.payMode === PAY_MODE.NONE ? 'free' : m.k > 1 ? `${sats(m.price)} (${m.k} × ${sats(token.price)})` : sats(m.price)),
      h('dt', {}, 'Total'), h('dd', {}, h('strong', {}, sats(m.fee + m.price))),
      h('dt', {}, 'Terms'), h('dd', {}, source === 'genesis'
        ? `genesis token: price, payment, window and supply checked against the profile constants in this vault (start = activation block ${check.profile.activationHeight})`
        : 'price, payment, window and supply checked against the DEPLOY transaction on chain'),
      check.agreed > 1 ? [h('dt', {}, 'Indexers'), h('dd', {}, `${check.agreed} agree on these terms`)] : null,
      h('dt', {}, 'Envelope'), h('dd', {}, h('code', {}, toHex(m.envelope)))),
    checkNotes(check),
    h('p', { class: 'muted' }, m.k > 1
      ? 'A mint rejected by the indexers is not refunded. If other mints in the same block leave fewer than k, the indexers give you what is left and keep the whole payment.'
      : 'A mint rejected by the indexers (for example sold out by a mint in the same block) is not refunded.'),
    sign);
}

async function signAndSend(token, m, opening, out) {
  const w = st.wallet;
  if (m.fee > MAX_FEE_SATS && !confirm(`The network fee is ${sats(m.fee)}, which is unusually high. Sign anyway?`)) return;
  const signed = await w.adapter.signPsbt(m.psbt, m.inputIndexes, w.address);
  const done = finalizePsbt(signed);
  if (!sameUnsignedTx(done.tx, m.tx)) throw new Error('the wallet changed the transaction; nothing was sent');
  const reserved = await st.vault.reserveNote();
  if (reserved.index !== opening.index) throw new Error('note index moved; prepare the transaction again');
  const note = await st.vault.addNote({ index: reserved.index, ticker: token.ticker, v: m.v, txid: done.txid, status: 'signed' });
  let id;
  try {
    id = await esplora.broadcast(done.hex);
  } catch (e) {
    await st.vault.updateNote(note.id, { status: 'broadcast failed' });
    renderNotes();
    throw e;
  }
  await st.vault.updateNote(note.id, { status: 'broadcast', txid: id });
  out.replaceChildren(
    h('p', { class: 'ok' }, `Broadcast: ${done.vsize} vB, fee ${sats(m.fee)}.`),
    h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer' }, id)));
  renderAll();
}

// ---- deploy ----------------------------------------------------------------------

const deployForm = { ticker: '', max: '21000000', lim: '1000', pre: '0', start: '', end: '0', unlock: '', payMode: '0', price: '0', payTo: '' };

const bigField = (x) => (/^[0-9]{1,20}$/.test(x.trim()) ? BigInt(x.trim()) : null);
const heightField = (x) => (/^[0-9]{1,10}$/.test(x.trim()) ? Number(x.trim()) : null);

/** D as the configured indexers report it: one value, or null with the reason. */
function deployBurn() {
  const ps = st.profiles;
  if (!ps.length) return { D: null, why: 'no indexer answered' };
  const values = new Set(ps.map((p) => String(p.deployBurn)));
  if (values.size > 1) return { D: null, why: `indexers disagree: ${ps.map((p) => `${p.base} ${p.deployBurn}`).join(', ')}` };
  if (ps[0].deployBurn === null) return { D: null, why: 'the indexer does not report deployBurn' };
  return { D: ps[0].deployBurn, agreed: ps.length };
}

/** The DEPLOY terms the form holds now, as deploy-plan.js reads them. */
function currentTerms() {
  const f = deployForm;
  let payScript = new Uint8Array(0);
  let payProblem = null;
  if (f.payMode === '2' && f.payTo.trim()) {
    try {
      payScript = addressToScript(f.payTo.trim());
    } catch {
      payProblem = 'the payment address is not a signet address';
    }
  }
  const d = {
    ticker: f.ticker.trim().toUpperCase(), max: bigField(f.max), lim: bigField(f.lim), pre: bigField(f.pre),
    start: heightField(f.start), end: heightField(f.end), unlock: heightField(f.unlock),
    payMode: Number(f.payMode), price: f.payMode === '0' ? 0n : bigField(f.price), payScript,
  };
  return { d, payProblem };
}

function renderDeploy() {
  const H = chainHeight();
  const f = deployForm;
  if (!f.start && H !== null) f.start = String(H + 12);
  if (!f.unlock && f.start) f.unlock = f.start;
  const { d, payProblem } = currentTerms();
  const { D, why, agreed } = deployBurn();
  const plan = planDeploy(d, {
    nextHeight: H === null ? null : H + 1,
    taken: st.tokens.map((t) => t.ticker),
    deployBurn: D,
    notes: st.vault ? st.vault.state.notes : [],
  });
  if (payProblem) plan.problems.push(payProblem);

  const field = (key, label, attrs = {}) => {
    const el = h('input', { value: f[key], spellcheck: 'false', autocomplete: 'off', ...attrs });
    el.addEventListener('change', () => { f[key] = el.value; renderDeploy(); });
    return h('label', {}, label, ' ', el);
  };
  const mode = h('select', {}, [['0', 'free'], ['1', 'burned (OP_RETURN)'], ['2', 'paid to an address']].map(([v, t]) => h('option', { value: v, selected: f.payMode === v }, t)));
  mode.addEventListener('change', () => { f.payMode = mode.value; renderDeploy(); });

  let burnRow;
  let yours = null;
  if (D === null) burnRow = h('span', { class: 'err' }, `unknown (${why}): nothing can be deployed`);
  else if (D === 0n) burnRow = 'none: this profile has D = 0, so a DEPLOY carries no proof';
  else {
    burnRow = [h('strong', {}, `${units(D)} SH20`), ` burned with a proof: a spend of your SH20 notes (vPub = ${units(D)}, tPub = SH20), the change comes back to you as a shielded note`,
      agreed > 1 ? ` · ${agreed} indexers agree on D` : ' · D as reported by one indexer'];
    const inp = plan.inputs;
    yours = !st.vault ? 'unlock the vault to see your SH20'
      : !st.sync?.nullifiersKnown ? 'sync your notes first: spends of your SH20 notes are not known yet'
      : inp.pick ? `${units(inp.total)} SH20 in ${inp.count} note(s); ${inp.pick.length === 1 ? 'one note' : 'two notes'} would pay the burn`
      : h('span', { class: 'err' }, `${units(inp.total)} SH20 in ${inp.count} note(s): not enough, a spend takes at most two notes (mint SH20 first)`);
  }

  fill('deploy-body',
    h('p', { class: 'muted' }, 'Pick a free 4-character ticker and its terms. The first valid DEPLOY of a ticker wins; the terms are public and final.'),
    h('div', { class: 'grid' },
      field('ticker', 'Ticker', { maxlength: '4', class: 'narrow', placeholder: 'ABCD' }),
      field('max', 'Max supply', { inputmode: 'numeric' }),
      field('lim', 'Per mint', { inputmode: 'numeric' }),
      field('pre', 'Team allocation', { inputmode: 'numeric' }),
      field('unlock', 'Team unlock block', { inputmode: 'numeric' }),
      field('start', 'Mint start block', { inputmode: 'numeric' }),
      field('end', 'Mint end block (0 = none)', { inputmode: 'numeric' }),
      h('label', {}, 'Mint price ', mode),
      f.payMode !== '0' ? field('price', 'Price (sats)', { inputmode: 'numeric' }) : null,
      f.payMode === '2' ? field('payTo', 'Paid to (signet address)') : null),
    h('dl', {},
      h('dt', {}, 'Deploy burn'), h('dd', {}, burnRow),
      yours ? [h('dt', {}, 'Your SH20'), h('dd', {}, yours)] : null,
      plan.mints !== null ? [h('dt', {}, 'Public mints'), h('dd', {}, `${units(plan.mints)} × ${units(d.lim)} ${d.ticker}`)] : null,
      plan.bytes !== null ? [h('dt', {}, 'Envelope'), h('dd', {}, `${units(plan.bytes)} bytes in a tapscript witness (a commit, then the reveal ${deployMaturity() ?? 'N'} blocks later; ≈ ${Math.ceil(plan.bytes / 4)} vB for the envelope)`)] : null),
    plan.problems.map((p) => h('div', { class: 'warn' }, p)),
    deployButton(d, plan, D),
    resultBox('deploy-out'));
}

function deployButton(d, plan, D) {
  const need = [];
  if (plan.problems.length || plan.bytes === null) need.push('fix the terms');
  if (D === null) need.push('agree on D');
  if (!st.vault) need.push('unlock the vault');
  if (!st.wallet) need.push('connect a wallet');
  if (D > 0n && !plan.inputs?.pick) need.push('hold enough unspent SH20');
  if (deployMaturity() === null) need.push('indexers that report the DEPLOY maturity N (SPEC-WIRE §5)');
  const fee = h('input', { type: 'number', min: '0.1', step: '0.1', value: '2', class: 'narrow', name: 'deploy-fee' });
  const b = h('button', { type: 'button', disabled: need.length > 0, name: 'deploy' }, D > 0n ? `Prove the burn of ${units(D)} SH20, sign and broadcast` : 'Sign and broadcast');
  b.addEventListener('click', busy(b, () => sendDeploy(d, D, Number(fee.value))));
  return [h('div', { class: 'row' }, h('label', {}, 'Fee rate (sat/vB) ', fee), b),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(', ')}.`) : null,
    h('p', { class: 'muted' }, `${D > 0n
      ? 'The burn is a spend: the vault proves it on this device (about half a minute on one thread). '
      : ''}Your wallet signs a commit transaction, which hides the ticker; the vault keeps the signed reveal and broadcasts it once the commit is ${deployMaturity() ?? 'N'} blocks deep, so nobody who sees the ticker can deploy it first (SPEC-WIRE §5). Keep the vault open, or come back: the countdown survives a reload. A DEPLOY rejected by the indexers is not refunded.`)];
}

const termsKey = (d) => JSON.stringify(d, (_, v) => (typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? toHex(v) : v));

async function sendDeploy(shown, D, feeRate) {
  const out = 'deploy-out';
  await refresh(); // D, the tickers taken and the tip, now
  if (String(deployBurn().D) !== String(D)) throw new Error('D changed: check again');
  const tip = await esplora.tipHeight();
  const plan = planDeploy(shown, { nextHeight: tip + 1, taken: st.tokens.map((t) => t.ticker), deployBurn: D, notes: st.vault.state.notes });
  if (plan.problems.length) throw new Error(plan.problems.join('; '));
  if (termsKey(currentTerms().d) !== termsKey(shown)) throw new Error('the terms changed: check them again');
  if (!confirm(`Deploy ${shown.ticker}${D > 0n ? `, burning ${units(D)} SH20` : ''}? The terms are public and final.`)) return;
  const N = deployMaturity();
  if (N === null) throw new Error('the indexers do not report deployMaturity (or disagree on it): they predate SPEC-WIRE §5\'s DEPLOY maturity');
  // the team note, if any, is a public note of this vault, created at block `unlock`
  const team = shown.pre > 0n ? { npk: (await st.vault.reserveNote()).npk } : null;
  if (D > 0n) await checkPool('SH20', D, 'DEPLOY burn');
  const s = D > 0n ? await getSyncer() : null;
  await carry({
    kind: 'DEPLOY', out, feeRate, tip,
    plan: () => (D > 0n ? planDeployBurn({ vault: st.vault, sync: s, tip, d: shown, D, team }) : planPlainDeploy({ d: shown, team })),
    label: D > 0n ? `DEPLOY of ${shown.ticker}, burning ${units(D)} SH20` : `DEPLOY of ${shown.ticker}`,
    deploy: { terms: encodeTerms(shown), team: team ? frHex(team.npk) : null, D: String(D), N, W: anchorWindow(), ticker: shown.ticker },
  });
}

/** N, the DEPLOY maturity, as every configured indexer reports it (one value), or null. */
function deployMaturity() {
  const values = new Set(st.profiles.map((p) => p.deployMaturity));
  return values.size === 1 && Number.isInteger([...values][0]) ? [...values][0] : null;
}
const anchorWindow = () => (Number.isInteger(st.status?.anchorWindow) ? st.status.anchorWindow : 100);

const encodeTerms = (d) => JSON.parse(JSON.stringify(d, (_, v) => (typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? `0x${toHex(v)}` : v)));
const decodeTerms = (t) => JSON.parse(JSON.stringify(t), (_, v) => (typeof v === 'string' && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : typeof v === 'string' && /^0x[0-9a-f]*$/.test(v) ? fromHex(v.slice(2)) : v));

let deploysRunning = false;

/**
 * The only way a DEPLOY reveal is broadcast: never before its commit is N blocks deep (SPEC-WIRE §5).
 * A reveal sent early is rejected, loses its fees and shows the ticker to whoever watches the mempool.
 */
async function broadcastDeployReveal(p) {
  const [cs, tip] = await Promise.all([esplora.txStatus(p.commitTxid).catch(() => null), esplora.tipHeight()]);
  const sched = revealSchedule({ commitHeight: cs?.confirmed ? cs.block_height : null, tip, N: p.deploy.N, anchorHeight: p.anchorHeight ?? null, W: p.deploy.W });
  if (sched.state !== 'ready') throw new Error(`the DEPLOY reveal is not due: ${sched.state}${sched.blocks ? `, ${sched.blocks} block(s) to go` : ''}`);
  await esplora.broadcast(p.revealHex);
}

/**
 * The DEPLOYs waiting for their commit to mature (SPEC-WIRE §5): their reveal is signed and kept in
 * the encrypted state, and goes out once the commit is N blocks deep, if the ticker is still free.
 * A DEPLOY whose proof's anchor would be out of the window W by then must be proved again.
 * Runs on every refresh and every minute while the vault is open.
 */
async function processDeploys() {
  const v = st.vault;
  if (!v || deploysRunning) return;
  deploysRunning = true;
  try {
    for (const p of (v.state.pending ?? []).filter((x) => x.kind === 'DEPLOY' && x.status === 'waiting maturity')) {
      const [cs, tip] = await Promise.all([esplora.txStatus(p.commitTxid).catch(() => null), esplora.tipHeight()]);
      const commitHeight = cs?.confirmed ? cs.block_height : null;
      const sched = revealSchedule({ commitHeight, tip, N: p.deploy.N, anchorHeight: p.anchorHeight ?? null, W: p.deploy.W });
      await v.updatePending(p.id, { commitHeight, revealIn: sched.blocks, schedule: sched.state });
      if (sched.state === 'expired') {
        await v.updatePending(p.id, { status: 'anchor expired' });
        continue;
      }
      if (sched.state !== 'ready') continue;
      // the ticker may have been taken meanwhile (another DEPLOY confirmed first): then the reveal would be rejected.
      // From the full lists: asking /token/<ticker> would tell the indexer the ticker before the reveal shows it.
      const lists = await Promise.allSettled(indexers.map((a) => a.tokens()));
      if (lists.some((r) => r.status === 'fulfilled' && r.value.some((t) => t.ticker === p.deploy.ticker))) {
        await v.releaseInputs(p.inputs);
        await v.updatePending(p.id, { status: 'ticker taken' });
        continue;
      }
      await broadcastDeployReveal(p);
      await v.updatePending(p.id, { status: 'broadcast' });
      result('deploy-out', h('p', { class: 'ok' }, `DEPLOY of ${p.deploy.ticker}: the commit is ${p.deploy.N} blocks deep, the reveal is broadcast.`), txLink(p.revealTxid));
    }
  } finally {
    deploysRunning = false;
    renderPending();
  }
}
setInterval(() => processDeploys().catch(report), 60000);

/** A DEPLOY whose proof's anchor went out of the window: proved again on today's tree, with a new commit that takes the old one's sats back. */
async function reproveDeploy(p) {
  if (!st.wallet) throw new Error('connect the wallet first: it pays the new commit');
  const d = decodeTerms(p.deploy.terms);
  const D = BigInt(p.deploy.D);
  const team = p.deploy.team ? { npk: frFromHex(p.deploy.team) } : null;
  await st.vault.releaseInputs(p.inputs);
  await syncNotes();
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  await carry({
    kind: 'DEPLOY', out: 'deploy-out', feeRate: p.feeRate, tip,
    plan: () => planDeployBurn({ vault: st.vault, sync: s, tip, d, D, team }),
    label: `DEPLOY of ${d.ticker}, proved again`,
    deploy: p.deploy,
    sweep: p,
  });
  await st.vault.updatePending(p.id, { status: 'replaced' });
}

// ---- spends: proved here; the wallet signs the commit, the vault the reveal --------------------

const txLink = (id) => h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, id));

async function walletUtxos() {
  const w = st.wallet;
  let utxos = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  if (!utxos) utxos = await esplora.utxos(w.address);
  if (!utxos.length) throw new Error(`no UTXO at ${w.address}; get signet coins from a faucet first`);
  return utxos;
}

/** Has the wallet sign a PSBT the vault built, and checks it signed exactly that transaction. */
async function signFunded(m) {
  const w = st.wallet;
  if (m.fee > MAX_FEE_SATS && !confirm(`The network fee is ${sats(m.fee)}, which is unusually high. Sign anyway?`)) throw new Error('not signed');
  const signed = await w.adapter.signPsbt(m.psbt, m.inputIndexes, w.address);
  const done = finalizePsbt(signed);
  if (!sameUnsignedTx(done.tx, m.tx)) throw new Error('the wallet changed the transaction; nothing was sent');
  return done;
}

/**
 * A proof-carrying spend: plan (witness), prove, commit (wallet), reveal (vault), broadcast both.
 * The one-time key is saved before the wallet signs, so the reveal can always be sent again.
 */
async function carry(args) {
  try {
    await carryOnce(args);
  } catch (e) {
    result(args.out, h('p', { class: 'err' }, e.message || String(e)));
    throw e;
  }
}

async function carryOnce({ kind, out, feeRate, tip, plan, label, outputs, onRevealed, deploy, sweep }) {
  const status = (t) => result(out, h('p', { class: 'muted' }, t));
  status('Building the envelope: note keys, sealed outputs, signatures…');
  await new Promise((r) => setTimeout(r, 30));
  const built = await plan();
  let envelope = built.envelope; // a DEPLOY with no burn carries no spend, hence no proof
  let proveS = null;
  if (!envelope) {
    const prover = await loadProver({ onStatus: status });
    status(`Proving on ${prover.threads} thread${prover.threads > 1 ? 's' : ''}… keep this tab open.`);
    const t0 = performance.now();
    envelope = await proveSpend(prover, built);
    proveS = ((performance.now() - t0) / 1000).toFixed(1);
  }
  const cp = planCarrier({ envelope, payer: st.wallet, utxos: await walletUtxos(), feeRate, tipHeight: tip, outputs, sweep });
  const draft = revealFor(cp, '00'.repeat(32));
  const wait = deploy ? ` The reveal goes out once the commit is ${deploy.N} blocks deep (SPEC-WIRE §5): keep the vault open, or come back.` : '';
  if (!confirm(`${label}${proveS ? `: proved in ${proveS} s` : ''}. Commit ≈ ${cp.commit.vsizeEstimate} vB, reveal ${draft.vsize} vB, network fees ≈ ${sats(cp.commit.fee + draft.fee)}.${wait} Sign the commit with ${st.wallet.adapter.name}?`)) {
    status('Not sent.');
    return;
  }
  const pid = await st.vault.addPending({ ...pendingRecord(kind, cp, envelope, built.inputs), ...(deploy ? { deploy, anchorHeight: built.anchorHeight ?? null } : {}) });
  const done = await signFunded(cp.commit);
  const reveal = revealFor(cp, done.txid);
  await st.vault.updatePending(pid, { commitTxid: done.txid, commitHex: done.hex, revealHex: reveal.hex, revealTxid: reveal.txid, status: 'signed' });
  await onRevealed?.(reveal);
  await esplora.broadcast(done.hex);
  await st.vault.updatePending(pid, { status: deploy ? 'waiting maturity' : 'commit broadcast' });
  if (deploy) {
    // the signed reveal stays in the encrypted state until the commit is N blocks deep (processDeploys)
    renderAll();
    result(out,
      h('p', { class: 'ok' }, `${label}: the commit is broadcast. The reveal waits until it is ${deploy.N} blocks deep, against ticker sniping; the notes it burns stay reserved meanwhile.`),
      h('p', { class: 'muted' }, 'Commit:'), txLink(done.txid),
      h('p', { class: 'muted', id: 'deploy-countdown' }, 'Spends sent from this vault (below) shows the countdown.'));
    await processDeploys();
    return;
  }
  await esplora.broadcast(reveal.hex);
  await st.vault.updatePending(pid, { status: 'broadcast' });
  renderAll();
  result(out,
    h('p', { class: 'ok' }, `${label}: broadcast. ${proveS ? `Proved in ${proveS} s; ` : ''}${envelope.length}-byte envelope; reveal ${reveal.vsize} vB.`),
    h('p', { class: 'muted' }, 'Commit, then reveal:'), txLink(done.txid), txLink(reveal.txid),
    h('p', { class: 'muted' }, 'Sync after the next block: the notes spent show their block, and the change shows as a received note.'));
}

// ---- send ------------------------------------------------------------------------

const sendForm = { action: 'transfer', ticker: '', amount: '', to: '', fee: '2', price: '', payTo: '' };

function balances() {
  const out = new Map();
  for (const n of st.vault?.state.notes ?? []) {
    if (n.status !== 'in tree' || n.spent !== 'no' || BigInt(n.v) === 0n) continue;
    out.set(n.ticker, (out.get(n.ticker) ?? 0n) + BigInt(n.v));
  }
  return out;
}

function proverModeText() {
  if (isolation === 'headers') return `Prover: thread pool (this page is cross-origin isolated${navigator.serviceWorker?.controller ? ' by its service worker' : ''}).`;
  return `Prover: one thread, about half a minute a proof (${{
    'not-a-subdomain-gateway': 'the page is not isolated; on an IPFS subdomain gateway it isolates itself',
    unavailable: 'no service worker here',
    refused: 'the browser refused cross-origin isolation',
  }[isolation] ?? 'not isolated'}).`;
}

function renderSend() {
  if (!st.vault) {
    fill('send-body', h('p', { class: 'muted' }, 'Unlock the vault to send.'));
    fill('pending-body');
    return;
  }
  const bal = balances();
  const f = sendForm;
  if (!bal.has(f.ticker)) f.ticker = [...bal.keys()][0] ?? '';
  const ticker = h('select', { name: 'ticker' }, [...bal].map(([t, v]) => h('option', { value: t, selected: t === f.ticker }, `${t} (${units(v)})`)));
  ticker.addEventListener('change', () => { f.ticker = ticker.value; });
  const input = (key, attrs) => {
    const el = h('input', { value: f[key], spellcheck: 'false', autocomplete: 'off', ...attrs });
    el.addEventListener('input', () => { f[key] = el.value; });
    return el;
  };
  const out = resultBox('send-out');
  const need = [];
  if (!bal.size) need.push('hold a note that is in the tree and known unspent (sync)');
  if (!st.wallet) need.push('connect a wallet (it pays the network fees)');
  if (!f.payTo && st.wallet) f.payTo = st.wallet.address;
  const action = h('select', { name: 'action' }, [['transfer', 'Send privately (TRANSFER)'], ['burn', 'Burn (BURN)'], ['list', 'Sell for BTC (LIST)']].map(([v, t]) => h('option', { value: v, selected: f.action === v }, t)));
  action.addEventListener('change', () => { f.action = action.value; renderSend(); });
  const label = { transfer: 'Prove and send', burn: 'Prove and burn', list: 'Prove and list' }[f.action];
  const b = h('button', { type: 'button', disabled: need.length > 0, name: 'send' }, label);
  b.addEventListener('click', busy(b, () => ({ transfer: sendTransfer, burn: sendBurn, list: sendList })[f.action]('send-out')));
  fill('send-body',
    h('p', { class: 'muted' }, {
      transfer: 'A private TRANSFER, proved on this device: the amount, the ticker, the sender and the recipient stay hidden. Your Bitcoin wallet pays the network fees.',
      burn: 'A BURN takes tokens out of the supply for good, in public: the amount and the ticker are shown, not which notes paid it.',
      list: 'A LIST moves the amount into a public escrow with a lock output only this vault can spend; you then share a signed offer, and whoever completes it pays the price to your address and gets the tokens.',
    }[f.action]),
    h('p', { class: 'muted', id: 'prover-mode' }, proverModeText()),
    h('div', { class: 'grid' },
      h('label', {}, 'Action ', action),
      h('label', {}, 'Ticker ', ticker),
      h('label', {}, 'Amount ', input('amount', { inputmode: 'numeric', name: 'amount' })),
      f.action === 'list' ? h('label', {}, 'Price (sats) ', input('price', { inputmode: 'numeric', name: 'price' })) : null,
      h('label', {}, 'Fee rate (sat/vB) ', input('fee', { type: 'number', min: '0.1', step: '0.1', name: 'fee' }))),
    f.action === 'transfer' ? h('label', {}, 'To (an sh20 address, tsh20…) ', input('to', { name: 'to', class: 'wide' })) : null,
    f.action === 'list' ? h('label', {}, 'Paid to (a signet address) ', input('payTo', { name: 'payTo', class: 'wide' })) : null,
    h('div', { class: 'row' }, b),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(' and ')}.`) : null,
    out);
  renderPending();
  renderMarket();
}

const amountOf = (x) => {
  if (!/^[0-9]{1,20}$/.test(x.trim())) throw new Error('amounts and prices are whole numbers');
  return BigInt(x.trim());
};

/**
 * Before proving a spend that takes `amount` of `ticker` out of the pool: every configured indexer's
 * /token/:ticker must have room for it (the turnstile), else the spend would be rejected and its fees lost.
 */
async function checkPool(ticker, amount, what) {
  const answers = await Promise.allSettled(indexers.map((a) => a.token(ticker)));
  const tokens = answers.filter((a) => a.status === 'fulfilled').map((a) => a.value);
  const problem = poolProblem(tokens, ticker, amount, what);
  if (problem) throw new Error(`Not sent: ${problem}.`);
}

async function sendBurn(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  await checkPool(f.ticker, amount, 'BURN');
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  if (!confirm(`Burn ${units(amount)} ${f.ticker}? They leave the supply for good.`)) return;
  await carry({
    kind: 'BURN', out, feeRate: Number(f.fee), tip,
    plan: () => planBurn({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount }),
    label: `BURN of ${units(amount)} ${f.ticker}`,
  });
}

async function sendList(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  const price = amountOf(f.price);
  const payScript = addressToScript(f.payTo.trim());
  await checkPool(f.ticker, amount, 'LIST');
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  const lockIndex = await st.vault.reserveLock();
  const lock = await st.vault.lockOutput(lockIndex);
  await carry({
    kind: 'LIST', out, feeRate: Number(f.fee), tip,
    plan: () => planList({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount, price, payScript, lockKey: lock.key }),
    outputs: listOutputs(lock.script),
    label: `LIST of ${units(amount)} ${f.ticker} for ${sats(price)}`,
    onRevealed: (reveal) => st.vault.addListing({ lockIndex, ticker: f.ticker, amount: amount.toString(), price: price.toString(), payScript: toHex(payScript), listTxid: reveal.txid, state: 'broadcast' }),
  });
}

async function sendTransfer(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  await carry({
    kind: 'TRANSFER', out, feeRate: Number(f.fee), tip,
    plan: () => planTransfer({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount, to: f.to }),
    label: `TRANSFER of ${units(amount)} ${f.ticker}`,
  });
}

/** Spends whose reveal may still need sending: their one-time key is in the vault. */
function renderPending() {
  const open = (st.vault?.state.pending ?? []).filter((p) => p.status !== 'prepared' && p.status !== 'replaced');
  if (!open.length) return fill('pending-body');
  fill('pending-body', h('h3', {}, 'Spends sent from this vault'), h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['What', 'Status', 'Commit', 'Reveal', ''].map((x) => h('th', {}, x)))),
    h('tbody', {}, open.map((p) => {
      if (p.status === 'anchor expired') {
        const re = h('button', { type: 'button', class: 'small', name: 'reprove' }, 'Prove again');
        re.addEventListener('click', busy(re, () => reproveDeploy(p)));
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, 'the proof\'s anchor left the window W: prove again'), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, '—'), h('td', {}, re));
      }
      if (p.kind === 'DEPLOY' && p.status === 'signed') {
        // signed but the commit may never have gone out: send the commit only, then the countdown
        const commit = h('button', { type: 'button', class: 'small secondary' }, 'Broadcast the commit');
        commit.addEventListener('click', busy(commit, async () => {
          try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
          await st.vault.updatePending(p.id, { status: 'waiting maturity' });
          await processDeploys();
        }));
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, 'signed; the commit may not be out yet'), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, 'kept, signed'), h('td', {}, commit));
      }
      if (p.kind === 'DEPLOY' && p.status !== 'broadcast' && p.status !== 'waiting maturity') {
        // ticker taken, replaced: nothing to broadcast
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, p.status), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, '—'), h('td', {}));
      }
      if (p.status === 'waiting maturity') {
        const left = p.schedule === 'unconfirmed' || p.revealIn === undefined ? 'the commit is not confirmed yet' : `reveal in ${p.revealIn} block${p.revealIn === 1 ? '' : 's'}`;
        const commitAgain = h('button', { type: 'button', class: 'small secondary' }, 'Broadcast the commit again');
        commitAgain.addEventListener('click', busy(commitAgain, async () => {
          try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
        }));
        return h('tr', {}, h('td', {}, p.kind), h('td', { class: 'countdown' }, `${p.deploy.ticker}: ${left}`), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, 'kept, signed'), h('td', {}, commitAgain));
      }
      const again = h('button', { type: 'button', class: 'small secondary', disabled: !p.commitHex }, 'Broadcast again');
      again.addEventListener('click', busy(again, async () => {
        // the same signed transactions; a reveal is signed again only if it was never made
        const reveal = p.revealHex ? { hex: p.revealHex, txid: p.revealTxid } : revealFor(planFromPending(p), p.commitTxid);
        try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
        if (p.kind === 'DEPLOY') await broadcastDeployReveal({ ...p, revealHex: reveal.hex }); // only once mature
        else await esplora.broadcast(reveal.hex);
        await st.vault.updatePending(p.id, { status: 'broadcast', revealHex: reveal.hex, revealTxid: reveal.txid });
        renderPending();
      }));
      return h('tr', {},
        h('td', {}, p.kind), h('td', {}, p.status),
        h('td', { class: 'mono' }, p.commitTxid ? short(p.commitTxid) : '—'),
        h('td', { class: 'mono' }, p.revealTxid ? short(p.revealTxid) : '—'),
        h('td', {}, again));
    })))));
}

// ---- notes -----------------------------------------------------------------------

function spentText(n) {
  if (n.spent === undefined || n.spent === 'unknown') return n.pos === null ? '—' : 'unknown';
  return n.spent === 'no' ? 'no' : `yes, ${n.spent}`;
}

function renderNotes() {
  const ss = st.sync;
  fill('sync-status', ss
    ? [`Synced to block ${ss.height}: ${ss.leaves} leaves, rebuilt here; the root matches the indexer. `,
      ss.nullifiersKnown ? 'Spends from the full nullifier list.' : h('span', { class: 'err' }, 'This indexer has no /nullifiers yet: spends unknown.')]
    : 'Not synced yet.');
  if (!st.vault) {
    fill('notes-body', h('p', { class: 'muted' }, 'Unlock the vault to see your notes.'));
    return;
  }
  const notes = st.vault.state.notes;
  if (!notes.length) {
    fill('notes-body', h('p', { class: 'muted' }, 'No note yet.'));
    return;
  }
  fill('notes-body', h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Ticker', 'Amount', 'Status', 'Position', 'Merkle path', 'Spent', 'Transaction', 'Key'].map((x) => h('th', {}, x)))),
    h('tbody', {}, notes.map((n) => h('tr', {},
      h('td', {}, n.ticker),
      h('td', { class: 'num' }, units(n.v)),
      h('td', { class: n.status === 'in tree' ? 'ok' : '' }, n.status),
      h('td', { class: 'num' }, n.pos ?? '—'),
      h('td', {}, n.pathAt ? `checked at block ${n.pathAt}` : '—'),
      h('td', {}, spentText(n)),
      h('td', {}, n.txid ? h('a', { href: explorerTx(n.txid), target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, short(n.txid)) : '—'),
      h('td', { class: 'muted' }, n.kind === 'sealed' ? 'received, sealed' : `public #${n.index}`)))))));
}

let syncer = null;

async function getSyncer() {
  if (!syncer || syncer.base !== indexer.base) {
    syncer = new Sync(await defaultCache(), indexer.base);
    syncer.base = indexer.base;
    await syncer.load();
  }
  return syncer;
}

/**
 * Finds the vault's notes among the notes read by a sync, on the device (docs/SPEC-NOTES.md §4, §5):
 * public notes by npk (leaf recomputed with rho = 0), sealed outputs by opening them with the
 * viewing key (leaf checked by circuit/js). Notes are told apart by position, never by leaf.
 */
async function matchNotes(pub) {
  const v = st.vault;
  let found = 0;
  for (const n of pub) if (n.kind === 'OUT' && n.pkEph && n.ct && n.leaf !== null && n.pos !== null && (await v.receive(n))) found++;
  // public notes: repeat while a match moves the window of keys to look for (a restore)
  for (let before = -1; before !== v.state.next;) {
    before = v.state.next;
    const keys = await v.npkWindow({ onProgress: (d, n) => fill('sync-status', `Deriving note keys on this device: ${d} / ${n} (once per key)…`) });
    for (const n of pub) {
      if (n.kind === 'OUT' || n.npk === null || n.ticker === null || n.v === null || n.pos === null) continue;
      const index = keys.get(frHex(n.npk));
      if (index === undefined) continue;
      // never trust the API's (ticker, v) alone: they must give back the leaf it put in the tree
      const leaf = frHex(noteLeaf(tickerT(n.ticker), n.v, n.npk, PUBLIC_RHO));
      if (n.leaf !== null && frHex(n.leaf) !== leaf) continue;
      const txid = n.txid ? { txid: n.txid } : {};
      const here = v.state.notes.find((x) => x.pos === n.pos);
      if (here) {
        if (here.leaf === leaf && here.status !== 'in tree' && here.status !== 'spending') {
          await v.updateNote(here.id, { status: 'in tree', ...txid });
          found++;
        }
        continue;
      }
      // our own mint confirmed; its amount is the indexer's when a late batch got fewer than k mints
      const pending = v.state.notes.find((x) => x.kind === 'public' && x.index === index && x.pos === null);
      if (pending) await v.updateNote(pending.id, { status: 'in tree', pos: n.pos, ticker: n.ticker, v: n.v.toString(), leaf, ...txid });
      else await v.addNote({ index, ticker: n.ticker, v: n.v, txid: n.txid, status: 'in tree', pos: n.pos });
      found++;
    }
  }
  return found;
}

/** Merkle path and spent status of every owned note, from the local tree and nullifier set only. */
async function checkOwned(s) {
  const v = st.vault;
  for (const n of [...v.state.notes]) {
    if (n.pos === null || n.pos === undefined) continue;
    const leaf = BigInt('0x' + n.leaf);
    if (n.pos >= s.tree.size || s.tree.leaf(n.pos) !== leaf) {
      if (n.kind === 'sealed') await v.dropNote(n.id); // scanning finds it again wherever it now is
      else await v.updateNote(n.id, { status: 'not in tree (reorg?)', pos: null, pathAt: null, spent: undefined });
      continue;
    }
    s.witness(n.pos, leaf); // throws if the local path does not reach the local root
    const at = s.spentAt(frHex(await v.nullifier(n)));
    await v.updateNote(n.id, { pathAt: s.height, spent: at === undefined ? 'unknown' : at === null ? 'no' : `block ${at}` });
  }
}

/**
 * Private sync: downloads every leaf and every spent nullifier (only what is
 * new since the cached block), rebuilds the tree here, then finds the vault's
 * notes, their Merkle paths and their spends on the device.
 */
async function syncNotes({ full = false } = {}) {
  const s = await getSyncer();
  const r = await s.sync(indexer, { full });
  st.sync = { height: r.height, leaves: r.leaves, nullifiersKnown: r.nullifiersKnown };
  let found = 0;
  if (st.vault) {
    found = await matchNotes(r.notes);
    await checkOwned(s);
    await syncListings();
  }
  renderAll();
  staticWarnings();
  processDeploys().catch(report);
  if (found) $('warnings').append(h('div', { class: 'warn' }, `${found} note(s) found in the tree.`));
}

// ---- settings --------------------------------------------------------------------

function initSettings() {
  const f = $('settings-form');
  f.indexer.value = urlList(settings.indexer).join('\n');
  f.esplora.value = settings.esplora;
  f.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const list = urlList(f.indexer.value);
    const bad = [...list, f.esplora.value.trim()].filter((u) => !/^https?:\/\/[^/\s]+/.test(u));
    if (!list.length || bad.length) return report(new Error(`not an http(s) URL: ${bad.join(', ') || '(no indexer)'}`));
    settings = { indexer: list.join('\n'), esplora: f.esplora.value.trim() };
    urlServers = null;
    staticWarnings();
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    indexers = urlList(settings.indexer).map((u) => new IndexerApi(u));
    indexer = indexers[0];
    esplora = new Esplora(settings.esplora);
    refresh();
  });
}

// ---- market: the vault's listings, and buying from an offer --------------------------------------

/**
 * Brings the vault's listings up to date from the indexer's full list (never asking about one
 * listing of its own), and finds them again after a restore by their lock keys.
 */
async function syncListings() {
  const v = st.vault;
  if (!v) return;
  let all;
  try {
    all = await indexer.listings();
  } catch {
    return; // an indexer without /listings: states stay as they were
  }
  const byTxid = new Map(all.filter((l) => l.listTxid).map((l) => [l.listTxid, l]));
  for (const rec of v.state.listings ?? []) {
    const l = byTxid.get(rec.listTxid);
    if (l && l.state !== rec.state) await v.updateListing(rec.id, { state: l.state });
  }
  const known = new Set((v.state.listings ?? []).map((r) => r.listTxid));
  const keys = new Map();
  for (let i = 0; i < (v.state.nextLock ?? 0) + LOCK_GAP; i++) keys.set(toHex((await v.lockOutput(i)).key), i);
  for (const l of all) {
    const i = keys.get(l.lockKey);
    if (i === undefined || known.has(l.listTxid)) continue;
    // found again by its lock key: its terms come from the LIST on chain, not from the indexer's word
    let chain;
    try {
      chain = listingFromChain(l.listTxid, await esplora.txHex(l.listTxid), { ...l, amount: String(l.amount), price: String(l.price) });
    } catch {
      continue;
    }
    if ((v.state.nextLock ?? 0) <= i) v.state.nextLock = i + 1; // before addListing saves: a lock key is never used twice
    await v.addListing({ lockIndex: i, ticker: chain.ticker, amount: String(chain.amount), price: String(chain.price), payScript: toHex(chain.payScript), listTxid: l.listTxid, state: l.state });
  }
}

/** A listing read from the chain and agreed on by every configured indexer (warnings if only one answers). */
async function checkedListing(listTxid) {
  const answers = await Promise.allSettled(indexers.map((a) => a.listing(listTxid)));
  const ok = answers.filter((a) => a.status === 'fulfilled' && a.value).map((a) => a.value);
  if (!ok.length) throw new Error('no indexer knows this listing');
  const key = (l) => JSON.stringify(l, (_, x) => (typeof x === 'bigint' ? String(x) : x));
  if (ok.some((l) => key(l) !== key(ok[0]))) throw new Error('the indexers disagree on this listing');
  const indexed = ok[0];
  const l = listingFromChain(listTxid, await esplora.txHex(listTxid), { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
  return { l, state: indexed.state, agreed: ok.length };
}

/**
 * One of the vault's own listings, from the indexer's full list (asking /listing/:txid would tell
 * the indexer it is ours) and the LIST transaction this vault sent (else fetched from Esplora).
 */
async function ownListing(rec) {
  const indexed = (await indexer.listings()).find((l) => l.listTxid === rec.listTxid);
  if (!indexed) throw new Error('the indexer does not list it (yet): sync after the next block');
  const sent = (st.vault.state.pending ?? []).find((p) => p.revealTxid === rec.listTxid)?.revealHex;
  const l = listingFromChain(rec.listTxid, sent ?? (await esplora.txHex(rec.listTxid)), { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
  return { l, state: indexed.state };
}

const marketForm = { offer: '', checked: null };

function renderMarket() {
  if (!st.vault) return fill('market-body', h('p', { class: 'muted' }, 'Unlock the vault to trade.'));
  const mine = st.vault.state.listings ?? [];
  const rows = mine.map((rec) => {
    const act = [];
    if (rec.state === 'ACTIVE') {
      const offer = h('button', { type: 'button', class: 'small', name: 'offer' }, 'Copy offer');
      offer.addEventListener('click', busy(offer, () => copyOffer(rec)));
      const cancel = h('button', { type: 'button', class: 'small secondary', disabled: !st.wallet, name: 'cancel' }, 'Cancel');
      cancel.addEventListener('click', busy(cancel, () => sendCancel(rec)));
      act.push(offer, ' ', cancel);
    } else if (rec.state === 'CLOSED') {
      const claim = h('button', { type: 'button', class: 'small', disabled: !st.wallet, name: 'claim' }, 'Claim back');
      claim.addEventListener('click', busy(claim, () => sendClaim(rec)));
      act.push(claim);
    }
    return h('tr', {},
      h('td', {}, rec.ticker), h('td', { class: 'num' }, units(rec.amount)), h('td', { class: 'num' }, sats(rec.price)),
      h('td', {}, rec.state), h('td', { class: 'mono' }, short(rec.listTxid)), h('td', {}, act));
  });
  const offer = h('textarea', { rows: '2', name: 'offer', spellcheck: 'false', placeholder: 'sh20offer1:…' }, marketForm.offer);
  offer.addEventListener('input', () => { marketForm.offer = offer.value; marketForm.checked = null; });
  const check = h('button', { type: 'button', class: 'secondary', name: 'check' }, 'Check the offer');
  check.addEventListener('click', busy(check, checkOffer));
  const c = marketForm.checked;
  let buy = null;
  if (c) {
    buy = h('button', { type: 'button', disabled: !st.wallet || c.state !== 'ACTIVE', name: 'buy' }, `Buy ${units(c.l.amount)} ${c.l.ticker} for ${sats(c.l.price)}`);
    buy.addEventListener('click', busy(buy, () => sendTake(c)));
  }
  fill('market-body',
    h('h3', {}, 'Your listings'),
    rows.length
      ? h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Ticker', 'Amount', 'Price', 'State', 'Listing', ''].map((x) => h('th', {}, x)))), h('tbody', {}, rows)))
      : h('p', { class: 'muted' }, 'None. List tokens from the panel above (Sell for BTC).'),
    resultBox('listing-out'),
    h('h3', {}, 'Buy from an offer'),
    h('label', {}, 'Offer (a line the seller shared)', offer),
    h('div', { class: 'row' }, check),
    c ? h('dl', {},
      h('dt', {}, 'Tokens'), h('dd', {}, `${units(c.l.amount)} ${c.l.ticker}, as a public note of this vault`),
      h('dt', {}, 'Price'), h('dd', {}, `${sats(c.l.price)} to ${toHex(c.l.payScript)}`),
      h('dt', {}, 'State'), h('dd', {}, c.state),
      h('dt', {}, 'Checked'), h('dd', {}, `the LIST on chain, the seller's signature for this price and payee${c.agreed > 1 ? `, ${c.agreed} indexers agree` : ' (one indexer: add others in Settings to cross-check)'}`)) : null,
    buy,
    resultBox('buy-out'));
}

async function copyOffer(rec) {
  const { l } = await ownListing(rec);
  const offer = encodeOffer(rec.listTxid, signOffer((await st.vault.lockOutput(rec.lockIndex)).secret, l));
  await navigator.clipboard?.writeText(offer).catch(() => {});
  result('listing-out', h('p', {}, 'Offer (copied): anyone who completes it pays the price to you and gets the tokens. Share it anywhere.'), h('p', { class: 'mono', id: 'offer-text' }, offer));
}

async function checkOffer() {
  const { listTxid, sig } = decodeOffer(marketForm.offer);
  const c = await checkedListing(listTxid);
  if (!offerValid(c.l, sig)) throw new Error('the offer is not signed by the listing\'s lock key for this price and payee');
  marketForm.checked = { ...c, sig };
  renderMarket();
}

/** Signs a transaction with a pre-signed or vault-signed lock input, broadcasts it, records the public note. */
async function sendFunded(m, outId, label, note) {
  const done = await signFunded(m);
  const id = await esplora.broadcast(done.hex);
  if (note) await st.vault.addNote({ ...note, txid: id, status: 'broadcast' });
  renderAll();
  result(outId, h('p', { class: 'ok' }, `${label}: broadcast (${done.vsize} vB).`), txLink(id), h('p', { class: 'muted' }, 'Sync after the next block to see the note.'));
}

async function sendTake(c) {
  const fresh = await checkedListing(c.l.listTxid); // still ACTIVE, same terms, now
  if (fresh.state !== 'ACTIVE') throw new Error(`the listing is ${fresh.state} now`);
  const tip = await esplora.tipHeight();
  const o = await st.vault.reserveNote(); // the tokens come as this public note
  const m = buildTake({ l: fresh.l, sig: c.sig, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: tip });
  if (!confirm(`Pay ${sats(fresh.l.price)} plus ${sats(m.fee)} of fees for ${units(fresh.l.amount)} ${fresh.l.ticker}?`)) return;
  await sendFunded(m, 'buy-out', `TAKE of ${units(fresh.l.amount)} ${fresh.l.ticker}`, { index: o.index, ticker: fresh.l.ticker, v: fresh.l.amount });
  marketForm.checked = null;
}

async function sendCancel(rec) {
  const { l, state } = await ownListing(rec);
  if (state !== 'ACTIVE') throw new Error(`the listing is ${state}`);
  if (!confirm(`Take ${units(l.amount)} ${l.ticker} back? The listing ends.`)) return;
  const o = await st.vault.reserveNote();
  const m = buildCancel({ l, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: await esplora.tipHeight() });
  await sendFunded(m, 'listing-out', `Cancel of ${units(l.amount)} ${l.ticker}`, { index: o.index, ticker: l.ticker, v: l.amount });
}

async function sendClaim(rec) {
  // CLOSED by every configured indexer (their full lists, never a question about this listing), and on
  // chain: the lock spent by a transaction with no TAKE. Else the CLAIM would be rejected and its fees lost.
  const lists = await Promise.allSettled(indexers.map((a) => a.listings()));
  const states = lists.filter((r) => r.status === 'fulfilled').map((r) => r.value.find((x) => x.listTxid === rec.listTxid)?.state ?? 'unknown');
  if (!states.length || states.some((s) => s !== 'CLOSED')) throw new Error(`not claimed: the indexers say ${[...new Set(states)].join(', ') || 'nothing'}, not CLOSED everywhere`);
  const { l } = await ownListing(rec);
  const out = await esplora.outspend(l.listTxid, l.lockVout);
  const problem = claimProblem(l, out.spent && out.txid ? await esplora.txHex(out.txid) : null);
  if (problem) throw new Error(`not claimed: ${problem}`);
  const o = await st.vault.reserveNote();
  const m = buildClaim({ listTxid: rec.listTxid, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: await esplora.tipHeight() });
  await sendFunded(m, 'listing-out', `CLAIM of ${units(rec.amount)} ${rec.ticker}`, { index: o.index, ticker: rec.ticker, v: BigInt(rec.amount) });
}

// ---- boot ------------------------------------------------------------------------

function renderAll() {
  renderVault();
  renderWallet();
  renderTokens();
  renderDeploy();
  renderNotes();
  renderSend();
}

staticWarnings();
initSettings();
renderAll();
refresh();
$('refresh').addEventListener('click', busy($('refresh'), refresh));
$('scan').addEventListener('click', busy($('scan'), () => syncNotes()));
$('rescan').addEventListener('click', busy($('rescan'), () => syncNotes({ full: true })));
// extensions inject their providers a little after load
setTimeout(renderWallet, 600);
