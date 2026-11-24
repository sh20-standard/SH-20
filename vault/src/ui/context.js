// What every panel shares: the servers (settings), the page's state, the DOM helpers and the
// warnings that stay on screen. The servers are live bindings, set by initContext() once the page
// has passed its checks (app.js) and by applySettings() from the settings panel.

import { Esplora, IndexerApi } from '../api.js';
import { actProblems, profileCheck } from '../consensus.js';
import { CHAIN, IS_MAINNET, PROFILE, PROFILE_NAME } from '../profile.js';
import { defaultSettings } from '../servers.js';

// ---- settings -----------------------------------------------------------------

export const SETTINGS_KEY = 'sh20.vault.settings';

// The network the page follows, as it names it (profile.js CHAIN): signet, or mainnet.
export const NET = CHAIN.label;
export const NET_TITLE = NET[0].toUpperCase() + NET.slice(1);
/** What the page says when the wallet's address holds nothing to pay with. */
export const noCoins = (address) => (CHAIN.bitcoin === 'signet' ? `no UTXO at ${address}; get signet coins from a faucet first` : `no UTXO at ${address}: send it some bitcoin first`);
/** What the page says with no indexer configured (the mainnet profile has no default: servers.js). */
export const NO_INDEXER = 'No indexer is configured: add one in Settings (your own indexer/bin/follow.js, or indexers you trust). The vault reads nothing and acts on nothing without one.';
// `indexer` holds one or more URLs (one per line, or comma-separated); the first is the primary.
// The defaults are those of the profile this page follows (servers.js): none is a server of ours.
const DEFAULTS = defaultSettings(PROFILE_NAME);
export const urlList = (s) => [...new Set(s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))];

// Servers given in the URL (?indexer=…&esplora=…) are never applied silently: a
// link could point the vault at a lying indexer (wrong payScript or price) or
// Esplora. They need a confirmation naming them, last for this tab only, and
// keep a warning on screen.
export let urlServers = null;

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

export let settings = null;
export const MAX_FEE_SATS = 20000n; // above this, ask before signing
export let indexers = [];
export let indexer = null; // primary: lists tokens and notes
export let esplora = null;

/** The servers, from this browser's settings and the link (after the page's checks: app.js). */
export function initContext() {
  useServers(loadSettings());
}

/** New servers from the settings panel: saved, and the link's no longer apply. */
export function applySettings(s) {
  urlServers = null;
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  useServers(s);
}

function useServers(s) {
  settings = s;
  indexers = urlList(settings.indexer).map((u) => new IndexerApi(u));
  indexer = indexers[0];
  esplora = new Esplora(settings.esplora);
}

/** How the page got (or not) cross-origin isolation (isolation.js), for the prover's panel. */
export let isolation = null;
export const setIsolation = (v) => { isolation = v; };
export const explorerTx = (id) => settings.esplora.replace(/\/api\/?$/, '') + '/tx/' + id;

// ---- state ----------------------------------------------------------------------

// profile: what the last /status of every indexer said against the vault's profile (consensus.js profileCheck)
export const st = { vault: null, wallet: null, tokens: [], status: null, tip: null, feeRate: null, sync: null, profile: { answered: 0, problems: [] }, results: {} };

/**
 * The fee rate the page proposes (docs/audit/2026-11-24-vault.md, vault-17): Esplora's estimate for about two
 * blocks, read with the tip. A commit at a rate the network does not take waits for days, and then its spend is
 * never mined or its DEPLOY reveal lands late. Without an estimate, 2 sat/vB on signet and the test chains, and
 * none on mainnet, where the rate is then typed.
 */
export const proposedFee = () => st.feeRate ?? (IS_MAINNET ? null : 2);

/** The rate a transaction is built at: the one typed, else the one proposed; none is an error, never a guess. */
export function feeRateOf(typed) {
  const r = Number(String(typed ?? '').trim() || proposedFee());
  if (!(r > 0)) throw new Error('no fee rate: Esplora gives no estimate now, so type one (sat/vB)');
  return r;
}

/**
 * Before any action (a DEPLOY and its reveal, a burn, a spend, a TAKE, a cancel, a CLAIM): every
 * indexer that answers must follow the vault's own profile (profile.js). Asked now, not from the
 * last refresh; throws naming each indexer that differs and on what.
 */
export async function requireProfile() {
  st.profile = await profileCheck(indexers);
  if (st.profile.problems.length) throw new Error(`nothing was done: ${st.profile.problems.join('. ')}. Remove that indexer in Settings, or use one that follows this vault's profile.`);
  // nor on the notes and the tree of a primary that verifies no spend (vault-16)
  const act = actProblems(st.profile, indexer?.base);
  if (act.length) throw new Error(`nothing was done: ${act.join('. ')}.`);
}

/** Shows `nodes` in the panel `id` and keeps them there across renders. */
export function result(id, ...nodes) {
  st.results[id] = nodes.flat().filter(Boolean);
  $(id)?.replaceChildren(...st.results[id]);
}
export const resultBox = (id) => h('div', { id }, ...(st.results[id] ?? []));

// ---- DOM helpers ----------------------------------------------------------------

export const $ = (id) => document.getElementById(id);

export function h(tag, attrs = {}, ...kids) {
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

export const fill = (id, ...kids) => $(id).replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
export const sats = (v) => `${BigInt(v).toLocaleString('en-US')} sats`;
export const units = (v) => BigInt(v).toLocaleString('en-US');
export const short = (x) => (x.length > 20 ? `${x.slice(0, 10)}…${x.slice(-8)}` : x);

/** Actions under way (a button's, a sync): while one runs, the vault does not lock itself (autolock.js). */
export const activity = { running: 0 };

/** Runs `fn` as an action under way. */
export async function during(fn) {
  activity.running++;
  try {
    return await fn();
  } finally {
    activity.running--;
  }
}

export function busy(button, fn) {
  return async (...args) => {
    button.disabled = true;
    try {
      await during(() => fn(...args));
    } catch (e) {
      report(e);
    } finally {
      button.disabled = false;
    }
  };
}

export function report(e) {
  console.error(e);
  const box = h('div', { class: 'warn err' }, e.message || String(e));
  $('warnings').append(box);
  setTimeout(() => box.remove(), 12000);
}

// ---- warnings that do not go away ------------------------------------------------

export function staticWarnings() {
  const w = [];
  if (urlServers) {
    w.push(`Using servers from the link, not your saved settings: ${Object.entries(urlServers).map(([k, v]) => `${k} ${v}`).join(', ')}. Check the price and outputs before signing.`);
  }
  if (PROFILE_NAME === 'test') w.push(`This page follows the ${PROFILE_NAME} profile (activation at block ${PROFILE.activationHeight}), for development: a release follows the signet or the mainnet profile.`);
  if (!window.isSecureContext) w.push('Not a secure context: passphrase encryption is unavailable. Use https or localhost.');
  w.push(CHAIN.bitcoin === 'signet'
    ? 'Note keys and sealing follow docs/SPEC-NOTES.md, draft v0.3, not audited yet: signet only.'
    : 'Note keys, sealing and the proofs follow drafts that are not audited yet (docs/SPEC-NOTES.md, docs/AUDIT.md): hold only what you can afford to lose.');
  fill('warnings', w.map((t) => h('div', { class: 'warn' }, t)));
}
