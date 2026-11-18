// Read-only clients: the SH-20 indexer API (docs/API.md) and an Esplora server.
// Both URLs are settings; any honest indexer and any Esplora work.
// Everything they return is untrusted input: it is normalised here and only
// ever rendered as text.

const trim = (u) => u.replace(/\/+$/, '');
const NOTE_PAGE = 5000; // the API's maximum page
export const MAX_FEE_RATE = 200; // sat/vB, cap on a server's suggestion

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
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
    tokenNum: num(t.tokenNum),
    ticker: String(t.ticker),
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
  };
}

/** A tree leaf: MINT / TEAM / TAKE / CLAIM carry a public opening (t, v, npk, rho); OUT does not. */
export function normNote(n) {
  const t = n.t ?? n.tokenNum;
  return {
    pos: n.pos ?? null,
    kind: n.kind ?? null,
    tokenNum: t === undefined ? null : num(t),
    v: n.v === undefined ? null : big(n.v),
    npk: frOf(n.npk),
    rho: frOf(n.rho),
    leaf: frOf(n.leaf),
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
