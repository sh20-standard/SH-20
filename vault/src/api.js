// Read-only clients: the SH-20 indexer API (docs/API.md) and an Esplora server. An indexer's base
// may also be a static mirror of one (docs/API.md, "The static mirror"): the files a host serves,
// with no query string. Each base is asked for its mirror.json once; with the mirror's format, every
// route is worked out from the files by indexer/src/mirror-read.js, as the indexer would answer it.
// Only bulk routes are used for wallet state (/notes, /nullifiers): per-note
// routes (/path/:pos, /nullifier/:hex) would tell the indexer which notes are yours.
// Both URLs are settings; any honest indexer and any Esplora work.
// Everything they return is untrusted input: it is normalised here and only
// ever rendered as text.

const trim = (u) => u.replace(/\/+$/, '');
const NOTE_PAGE = 5000; // the API's maximum page
export const MAX_FEE_RATE = 200; // sat/vB, cap on a server's suggestion

import { MIRROR_FORMAT, mirrorGet } from '../../indexer/src/mirror-read.js';

async function getJson(url, init = {}) {
  const r = await fetch(url, { ...init, headers: { accept: 'application/json' } });
  if (!r.ok) throw Object.assign(new Error(`${url}: HTTP ${r.status}`), { status: r.status });
  return r.json();
}

const big = (x) => (x === undefined || x === null || x === '' ? 0n : BigInt(x));
const num = (x) => (x === undefined || x === null ? 0 : Number(x));

/** Field element from the API: 64-char hex (with or without 0x) or a decimal string. */
export function frOf(x) {
  if (x === undefined || x === null) return null;
  const s = String(x);
  if (/^(0x)?[0-9a-f]{64}$/i.test(s)) return BigInt(s.startsWith('0x') ? s : '0x' + s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

export function normToken(t) {
  return {
    ticker: String(t.ticker),
    t: t.t === undefined ? null : big(t.t), // the ticker's id in notes; checked against tickerT(ticker)
    max: big(t.max),
    lim: big(t.lim),
    pre: big(t.pre),
    start: num(t.start),
    end: num(t.end),
    unlock: num(t.unlock),
    price: big(t.price),
    payMode: num(t.payMode),
    payScript: typeof t.payScript === 'string' ? t.payScript.toLowerCase() : '',
    mints: big(t.mints),
    burned: big(t.burned),
    // the turnstile (SPEC-WIRE §5): what the shielded pool holds of the ticker; null if not reported
    pool: t.pool === undefined || t.pool === null ? null : big(t.pool),
    deployTxid: t.deployTxid ?? null,
    deployHeight: t.deployHeight ?? null,
    genesis: t.genesis === true, // SH20, from the profile: no DEPLOY (checked against profile.js)
  };
}

const hexBytes = (h, n) => {
  if (typeof h !== 'string' || !new RegExp(`^[0-9a-f]{${2 * n}}$`, 'i').test(h)) return null;
  return Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
};

const STATES = ['ACTIVE', 'SOLD', 'CANCELLED', 'CLOSED', 'CLAIMED'];
export function normListing(l) {
  const hex = (x, n) => (typeof x === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(x) ? x : null);
  return {
    listTxid: hex(l.listTxid, 64),
    ticker: typeof l.ticker === 'string' && /^[A-Z0-9]{4}$/.test(l.ticker) ? l.ticker : null,
    amount: big(l.amount),
    price: big(l.price),
    payScript: typeof l.payScript === 'string' && /^([0-9a-f]{2}){1,34}$/.test(l.payScript) ? l.payScript : null,
    lock: typeof l.lock === 'string' && /^[0-9a-f]{64}:\d+$/.test(l.lock) ? l.lock : null,
    lockKey: hex(l.lockKey, 64),
    state: STATES.includes(l.state) ? l.state : null,
    height: num(l.height),
  };
}

/** A tree leaf: MINT / TEAM / TAKE / CLAIM carry a public opening (ticker, v, npk); OUT carries pkEph and ct. */
export function normNote(n) {
  return {
    pos: n.pos ?? null,
    kind: n.kind ?? null,
    ticker: typeof n.ticker === 'string' && /^[A-Z0-9]{4}$/.test(n.ticker) ? n.ticker : null,
    v: n.v === undefined ? null : big(n.v),
    npk: frOf(n.npk), // public notes: their opening (rho is 0, v0.3)
    leaf: frOf(n.leaf),
    pkEph: hexBytes(n.pkEph, 32), // OUT notes: the sealed output (docs/SPEC-NOTES.md §3)
    ct: hexBytes(n.ct, 28),
    txid: n.txid ?? null,
    height: n.height ?? null,
  };
}

const list = (j, key) => {
  if (Array.isArray(j)) return j;
  if (Array.isArray(j?.[key])) return j[key];
  throw new Error('unexpected response shape from the indexer');
};

/**
 * What `base` is: its mirror.json with the mirror's format makes it a mirror ({ kind: 'mirror', mirror });
 * a live indexer answers that path 404 ({ kind: 'indexer' }). Anything else (a server down, a 5xx)
 * throws, and the next request asks again.
 */
async function probe(base) {
  try {
    const m = await getJson(`${base}/mirror.json`, { cache: 'no-cache' });
    return m?.format === MIRROR_FORMAT ? { kind: 'mirror', mirror: m } : { kind: 'indexer' };
  } catch (e) {
    if (e.status === 404) return { kind: 'indexer' };
    if (e instanceof SyntaxError) return { kind: 'indexer' }; // an answer that is not JSON names no mirror
    throw e;
  }
}

export class IndexerApi {
  #kind = null;
  constructor(base) {
    this.base = trim(base);
  }
  /** { kind: 'mirror' | 'indexer', mirror? }, asked once per base (again after a failure). */
  kind() {
    this.#kind ??= probe(this.base).catch((e) => {
      this.#kind = null;
      throw e;
    });
    return this.#kind;
  }
  /** For a mirror, its mirror.json read again (its tip, and when it was built); null for a live indexer. */
  async mirrorInfo() {
    const k = await this.kind();
    if (k.kind !== 'mirror') return null;
    const m = await getJson(`${this.base}/mirror.json`, { cache: 'no-cache' });
    if (m?.format === MIRROR_FORMAT) k.mirror = m;
    return k.mirror;
  }
  /**
   * The answer to a route of docs/API.md (a path with its query). A mirror's files are each asked for
   * with revalidation (cache: 'no-cache'), so a file the browser kept from an older build is not
   * read with a newer one; mirror.json is read again, for its tip and its time.
   */
  async get(route) {
    const k = await this.kind();
    if (k.kind === 'indexer') return getJson(this.base + route);
    return mirrorGet(route, async (name) => {
      const j = await getJson(`${this.base}/${name}`, { cache: 'no-cache' });
      if (name === 'mirror.json' && j?.format === MIRROR_FORMAT) k.mirror = j;
      return j;
    });
  }
  async status() {
    return this.get('/status');
  }
  /** The note tree's root after block `height` (hex), or null when the indexer does not report it. */
  async rootAt(height) {
    if (!Number.isInteger(height) || height < 0) throw new Error('bad height');
    const j = list(await this.get(`/roots?from=${height}`), 'roots');
    const r = j.find((x) => x?.height === height);
    if (!r) return null;
    if (!/^[0-9a-f]{64}$/i.test(String(r.root))) throw new Error(`${this.base}: a malformed /roots answer`);
    return String(r.root).toLowerCase();
  }
  /** The state digest after block `height`, or null when the indexer is not there yet (404). */
  async digest(height) {
    if (!Number.isInteger(height) || height < 0) throw new Error('bad height');
    try {
      const j = await this.get(`/digest/${height}`);
      if (j?.height !== height || !/^[0-9a-f]{64}$/i.test(String(j.digest))) throw new Error(`${this.base}: a malformed /digest answer`);
      return String(j.digest).toLowerCase();
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }
  async tokens() {
    return list(await this.get(`/tokens`), 'tokens').map(normToken);
  }
  /** One listing (docs/API.md /listing/:txid), or null if the indexer does not know it. */
  async listing(listTxid) {
    if (!/^[0-9a-f]{64}$/.test(listTxid)) throw new Error('bad listing id');
    try {
      return normListing(await this.get(`/listing/${listTxid}`));
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }
  /** Every listing, optionally in one state (ACTIVE, SOLD, CANCELLED, CLOSED, CLAIMED). */
  async listings(state) {
    return list(await this.get(`/listings${state ? `?state=${state}` : ''}`), 'listings').map(normListing);
  }
  async token(ticker) {
    if (!/^[A-Z0-9]{4}$/.test(ticker)) throw new Error('bad ticker');
    const j = await this.get(`/token/${ticker}`);
    return normToken(j.token ?? j);
  }
  /**
   * Every tree leaf from position `from`, page by page. The vault downloads
   * them all and matches its notes locally, so the indexer never learns which
   * notes are the user's.
   */
  async notes(from = 0) {
    const out = [];
    for (;;) {
      const j = await this.get(`/notes?from=${from}&limit=${NOTE_PAGE}`);
      const page = list(j, 'notes');
      out.push(...page.map(normNote));
      from += page.length;
      if (page.length === 0 || (typeof j.total === 'number' && from >= j.total) || Array.isArray(j)) return out;
    }
  }

  /**
   * Every nullifier spent from block `from` on, in one list (docs/API.md
   * /nullifiers). Returns null when the indexer does not serve the route yet;
   * the vault then reports spends as unknown and never falls back to asking
   * /nullifier/:hex for its own notes.
   */
  async nullifiers(from = 0) {
    let j;
    try {
      j = await this.get(`/nullifiers?from=${from}`);
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
    return list(j, 'nullifiers').map((n) => {
      if (!/^[0-9a-f]{64}$/.test(n?.nullifier) || !Number.isInteger(n.height)) throw new Error('bad nullifier entry from the indexer');
      return { nullifier: n.nullifier, height: n.height };
    });
  }
}

export class Esplora {
  constructor(base) {
    this.base = trim(base);
  }
  async tipHeight() {
    const r = await fetch(`${this.base}/blocks/tip/height`);
    if (!r.ok) throw new Error(`tip height: HTTP ${r.status}`);
    return Number(await r.text());
  }
  async utxos(address) {
    const j = await getJson(`${this.base}/address/${encodeURIComponent(address)}/utxo`);
    return j.map((u) => ({ txid: u.txid, vout: u.vout, value: BigInt(u.value), confirmed: !!u.status?.confirmed }));
  }
  /**
   * Suggested sat/vB for confirmation within ~2 blocks, clamped to
   * [1, MAX_FEE_RATE] so a dishonest server cannot suggest a ruinous fee.
   */
  async feeRate() {
    return (await this.feeEstimate()) ?? 1;
  }
  /** The same estimate, or null when the server gives none (no answer, no number): the page then proposes no rate on mainnet. */
  async feeEstimate() {
    try {
      const j = await getJson(`${this.base}/fee-estimates`);
      const r = Number(j['2'] ?? j['3'] ?? j['6']);
      return Number.isFinite(r) && r > 0 ? Math.min(MAX_FEE_RATE, Math.max(1, Math.ceil(r * 10) / 10)) : null;
    } catch {
      return null;
    }
  }
  async broadcast(hex) {
    const r = await fetch(`${this.base}/tx`, { method: 'POST', body: hex });
    const text = await r.text();
    if (!r.ok) throw new Error(`broadcast refused: ${text}`);
    return text.trim();
  }
  async txHex(id) {
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('bad txid');
    const r = await fetch(`${this.base}/tx/${id}/hex`);
    if (!r.ok) throw new Error(`tx ${id}: HTTP ${r.status}`);
    return (await r.text()).trim();
  }
  /** Whether output `vout` of `id` is spent, and by which transaction: { spent, txid } (Esplora /outspend). */
  async outspend(id, vout) {
    if (!/^[0-9a-f]{64}$/.test(id) || !Number.isInteger(vout)) throw new Error('bad outpoint');
    const j = await getJson(`${this.base}/tx/${id}/outspend/${vout}`);
    return { spent: j?.spent === true, txid: typeof j?.txid === 'string' && /^[0-9a-f]{64}$/.test(j.txid) ? j.txid : null };
  }
  async txStatus(id) {
    return getJson(`${this.base}/tx/${id}/status`);
  }
}
