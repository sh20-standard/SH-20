// Read-only clients: the SH-20 indexer API (docs/API.md) and an Esplora server.
// Only bulk routes are used for wallet state (/notes, /nullifiers): per-note
// routes (/path/:pos, /nullifier/:hex) would tell the indexer which notes are yours.
// Both URLs are settings; any honest indexer and any Esplora work.
// Everything they return is untrusted input: it is normalised here and only
// ever rendered as text.

const trim = (u) => u.replace(/\/+$/, '');
const NOTE_PAGE = 5000; // the API's maximum page
export const MAX_FEE_RATE = 200; // sat/vB, cap on a server's suggestion

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: 'application/json' } });
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

export class IndexerApi {
  constructor(base) {
    this.base = trim(base);
  }
  async status() {
    return getJson(`${this.base}/status`);
  }
  async tokens() {
    return list(await getJson(`${this.base}/tokens`), 'tokens').map(normToken);
  }
  /** One listing (docs/API.md /listing/:txid), or null if the indexer does not know it. */
  async listing(listTxid) {
    if (!/^[0-9a-f]{64}$/.test(listTxid)) throw new Error('bad listing id');
    try {
      return normListing(await getJson(`${this.base}/listing/${listTxid}`));
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }
  /** Every listing, optionally in one state (ACTIVE, SOLD, CANCELLED, CLOSED, CLAIMED). */
  async listings(state) {
    return list(await getJson(`${this.base}/listings${state ? `?state=${state}` : ''}`), 'listings').map(normListing);
  }
  async token(ticker) {
    if (!/^[A-Z0-9]{4}$/.test(ticker)) throw new Error('bad ticker');
    const j = await getJson(`${this.base}/token/${ticker}`);
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
      const j = await getJson(`${this.base}/notes?from=${from}&limit=${NOTE_PAGE}`);
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
      j = await getJson(`${this.base}/nullifiers?from=${from}`);
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
    try {
      const j = await getJson(`${this.base}/fee-estimates`);
      const r = Number(j['2'] ?? j['3'] ?? j['6'] ?? 1);
      return Number.isFinite(r) ? Math.min(MAX_FEE_RATE, Math.max(1, Math.ceil(r * 10) / 10)) : 1;
    } catch {
      return 1;
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
  async txStatus(id) {
    return getJson(`${this.base}/tx/${id}/status`);
  }
}
