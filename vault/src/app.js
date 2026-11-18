// SH-20 vault page. Plain DOM, no framework; data from the network is only
// ever written with textContent.

import { Vault } from './keys.js';
import { WALLETS } from './wallets.js';
import { IndexerApi, Esplora } from './api.js';
import { buildMint, mintProblems, mintsLeft } from './mint.js';
import { verifyDeploy } from './deploy.js';
import { crossCheck, TERMS } from './consensus.js';
import { finalizePsbt, sameUnsignedTx, scriptType, addressToScript } from './btc.js';
import { frHex } from './fr.js';
import { NPK_SCHEME } from './npk.js';
import { Sync } from './sync.js';
import { defaultCache } from './cache.js';
import { PAY_MODE, noteLeaf, tickerT } from './sh20.js';
import { toHex } from './bytes.js';

if (window.top !== window.self) {
  document.documentElement.textContent = 'The SH-20 vault refuses to run inside a frame.';
  throw new Error('framed');
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

const st = { vault: null, wallet: null, tokens: [], status: null, tip: null, sync: null };

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
  w.push(`Note keys use the provisional derivation "${NPK_SCHEME}" until the spend circuit is fixed. Notes minted now are for signet testing and may not be spendable by the final circuit.`);
  fill('warnings', w.map((t) => h('div', { class: 'warn' }, t)));
}

// ---- vault ----------------------------------------------------------------------

function renderVault() {
  if (st.vault) {
    const v = st.vault;
    fill('vault-body',
      h('p', {}, h('span', { class: 'ok' }, 'Unlocked. '), `${v.state.next} note key(s) used, ${v.encrypted ? 'encrypted with your passphrase' : 'stored without passphrase'}.`),
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'secondary', onclick: downloadBackup }, 'Download backup'),
        h('button', { type: 'button', class: 'secondary', onclick: () => { v.lock(); st.vault = null; renderAll(); } }, 'Lock')),
      h('p', { class: 'muted' }, 'The backup holds the seed (encrypted if you set a passphrase). A new version of this page on IPFS has a new origin and an empty storage: restore the backup there.'));
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
  fill('vault-body',
    h('p', {}, 'No vault on this device. The seed is generated here and never leaves it.'),
    form,
    h('div', { class: 'row' }, file, rpass, restore));
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
      st.wallet = { adapter: ad, ...acc, type };
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
  try {
    st.tip = await esplora.tipHeight();
  } catch {
    st.tip = null;
  }
  renderTokens();
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
      h('td', {}, h('strong', {}, t.ticker)),
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
  const prep = h('button', { type: 'button', disabled: need.length > 0 }, 'Prepare transaction');
  const out = h('div');
  prep.addEventListener('click', busy(prep, () => prepareMint(token, Number(fee.value), out)));
  fill('mint-body',
    h('dl', {},
      h('dt', {}, 'You receive'), h('dd', {}, `${units(token.lim)} ${token.ticker} (one public note)`),
      h('dt', {}, 'Price'), h('dd', {}, payText(token)),
      h('dt', {}, 'Mints left'), h('dd', {}, units(mintsLeft(token))),
      h('dt', {}, 'Window'), h('dd', {}, `block ${token.start} to ${token.end || 'no end'}`)),
    checkNotes(check),
    h('div', { class: 'row' }, h('label', {}, 'Fee rate (sat/vB) ', fee), prep),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(' and ')}.`) : null,
    out);
}

async function prepareMint(shown, feeRate, out) {
  // ask every indexer again: the terms signed must be the ones shown, agreed on, and on chain
  const check = await crossCheck(indexers, shown.ticker);
  if (check.problems.length) throw new Error(`mint refused: ${check.problems.join('; ')}`);
  const token = check.token;
  if (TERMS.some((k) => String(token[k]) !== String(shown[k]))) throw new Error('the token terms changed since they were shown; open the mint again');
  await verifyDeploy(esplora, token); // the mint terms come from the chain, not from the indexer alone
  const tip = await esplora.tipHeight();
  const w = st.wallet;
  let utxos = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  if (!utxos) utxos = await esplora.utxos(w.address);
  if (!utxos.length) throw new Error(`no UTXO at ${w.address}; get signet coins from a faucet first`);
  const opening = st.vault.opening(st.vault.state.next); // reserved only when signed
  const m = buildMint({ token, opening, payer: w, utxos, feeRate, tipHeight: tip });

  const sign = h('button', { type: 'button' }, `Sign with ${w.adapter.name} and broadcast`);
  sign.addEventListener('click', busy(sign, () => signAndSend(token, m, opening, out)));
  out.replaceChildren(
    h('dl', {},
      h('dt', {}, 'Inputs'), h('dd', {}, `${m.tx.vin.length} from ${short(w.address)}`),
      h('dt', {}, 'Outputs'), h('dd', {}, m.tx.vout.map((o, i) => `#${i} ${scriptType(o.script)} ${sats(o.value)}`).join(' · ')),
      h('dt', {}, 'Size'), h('dd', {}, `≈ ${m.vsizeEstimate} vB (a plain P2TR payment is ≈ 154 vB)`),
      h('dt', {}, 'Network fee'), h('dd', {}, sats(m.fee)),
      h('dt', {}, 'Mint price'), h('dd', {}, sats(m.price)),
      h('dt', {}, 'Total'), h('dd', {}, h('strong', {}, sats(m.fee + m.price))),
      h('dt', {}, 'Terms'), h('dd', {}, 'price, payment, window and supply checked against the DEPLOY transaction on chain'),
      check.agreed > 1 ? [h('dt', {}, 'Indexers'), h('dd', {}, `${check.agreed} agree on these terms`)] : null,
      h('dt', {}, 'Envelope'), h('dd', {}, h('code', {}, toHex(m.envelope)))),
    checkNotes(check),
    h('p', { class: 'muted' }, 'A mint rejected by the indexers (for example sold out by a mint in the same block) is not refunded.'),
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
  await st.vault.addNote({ ...reserved, ticker: token.ticker, v: token.lim, txid: done.txid, status: 'signed' });
  let id;
  try {
    id = await esplora.broadcast(done.hex);
  } catch (e) {
    await st.vault.updateNote(reserved.index, { status: 'broadcast failed' });
    renderNotes();
    throw e;
  }
  await st.vault.updateNote(reserved.index, { status: 'broadcast', txid: id });
  out.replaceChildren(
    h('p', { class: 'ok' }, `Broadcast: ${done.vsize} vB, fee ${sats(m.fee)}.`),
    h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer' }, id)));
  renderAll();
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
      h('td', { class: 'muted' }, `#${n.index} ${n.scheme}`)))))));
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

/** Recognises the vault's public notes among notes read by a sync (by npk, leaf recomputed). */
async function matchNotes(pub) {
  const v = st.vault;
  const keys = v.npkWindow(20);
  let found = 0;
  for (const n of pub) {
    if (n.npk === null || n.ticker === null || n.v === null) continue; // OUT notes: wait for the ct format
    const index = keys.get(frHex(n.npk));
    if (index === undefined) continue;
    const o = v.opening(index);
    if (n.rho !== null && n.rho !== o.rho) continue;
    // never trust the API's (ticker, v) alone: they must give back the leaf it put in the tree
    const leaf = frHex(noteLeaf(tickerT(n.ticker), n.v, o.npk, o.rho));
    if (n.leaf !== null && frHex(n.leaf) !== leaf) continue;
    const mine = v.state.notes.find((x) => x.index === index);
    if (mine) {
      if (mine.leaf !== leaf) continue; // same key, other amount or ticker: not the note we minted
      if (mine.status !== 'in tree') found++;
      await v.updateNote(index, { status: 'in tree', pos: n.pos, ...(n.txid ? { txid: n.txid } : {}) });
    } else {
      await v.addNote({ ...o, ticker: n.ticker, v: n.v, txid: n.txid, status: 'in tree' });
      await v.updateNote(index, { pos: n.pos });
      if (v.state.next <= index) v.state.next = index + 1;
      found++;
    }
  }
  return found;
}

/** Merkle path and spent status of every owned note, from the local tree and nullifier set only. */
async function checkOwned(s) {
  const v = st.vault;
  for (const n of v.state.notes) {
    if (n.pos === null || n.pos === undefined) continue;
    const leaf = BigInt('0x' + n.leaf);
    if (n.pos >= s.tree.size || s.tree.leaf(n.pos) !== leaf) {
      await v.updateNote(n.index, { status: 'not in tree (reorg?)', pos: null, pathAt: null, spent: undefined });
      continue;
    }
    s.witness(n.pos, leaf); // throws if the local path does not reach the local root
    const at = s.spentAt(frHex(v.nullifier(n.index, leaf, n.pos)));
    await v.updateNote(n.index, { pathAt: s.height, spent: at === undefined ? 'unknown' : at === null ? 'no' : `block ${at}` });
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
  }
  renderAll();
  staticWarnings();
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

// ---- boot ------------------------------------------------------------------------

function renderAll() {
  renderVault();
  renderWallet();
  renderTokens();
  renderNotes();
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
