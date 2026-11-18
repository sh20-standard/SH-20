// Follows a live chain and feeds the indexer, handling reorgs.
//
// Two block sources, both read-only and both optional to trust only for chain
// selection (the indexer re-checks every envelope itself):
//   - BitcoindSource: your own Bitcoin Core node over JSON-RPC (recommended)
//   - EsploraSource:  any Esplora REST API (mempool.space, blockstream.info, self-hosted)
// Both return blocks as { height, hash, prev, txs } in the indexer's format.

import { fromBitcoindBlock } from './adapters/bitcoind.js';

const hexBufs = (list) => (list || []).map((h) => Buffer.from(h, 'hex'));

export class EsploraSource {
  constructor(baseUrl, { fetch = globalThis.fetch, pageSize = 25 } = {}) {
    this.base = baseUrl.replace(/\/+$/, '');
    this.fetch = fetch;
    this.pageSize = pageSize;
  }

  async _get(path, json = true) {
    const res = await this.fetch(this.base + path);
    if (!res.ok) throw new Error(`esplora ${path}: HTTP ${res.status}`);
    return json ? res.json() : (await res.text()).trim();
  }

  async tipHeight() {
    return Number(await this._get('/blocks/tip/height', false));
  }

  async blockHash(height) {
    return this._get(`/block-height/${height}`, false);
  }

  async block(hash) {
    const head = await this._get(`/block/${hash}`);
    const txs = [];
    for (let start = 0; start < head.tx_count; start += this.pageSize) {
      const page = await this._get(`/block/${hash}/txs/${start}`);
      for (const t of page) {
        txs.push({
          txid: t.txid,
          vin: t.vin.map((i) => (i.is_coinbase ? { coinbase: true } : { txid: i.txid, vout: i.vout, witness: hexBufs(i.witness) })),
          vout: t.vout.map((o) => ({ value: BigInt(o.value), script: Buffer.from(o.scriptpubkey, 'hex') })),
        });
      }
    }
    return { height: head.height, hash: head.id, prev: head.previousblockhash ?? null, txs };
  }
}

export class BitcoindSource {
  constructor(url, { user = '', pass = '', fetch = globalThis.fetch } = {}) {
    this.url = url;
    this.auth = user || pass ? 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') : null;
    this.fetch = fetch;
    this.id = 0;
  }

  async rpc(method, params = []) {
    const headers = { 'content-type': 'application/json' };
    if (this.auth) headers.authorization = this.auth;
    const res = await this.fetch(this.url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ jsonrpc: '1.0', id: ++this.id, method, params }),
    });
    const body = await res.json();
    if (body.error) throw new Error(`bitcoind ${method}: ${body.error.message}`);
    return body.result;
  }

  async tipHeight() {
    return this.rpc('getblockcount');
  }

  async blockHash(height) {
    return this.rpc('getblockhash', [height]);
  }

  async block(hash) {
    const json = await this.rpc('getblock', [hash, 2]);
    return { ...fromBitcoindBlock(json), prev: json.previousblockhash ?? null };
  }
}

export class Follower {
  /**
   * @param {object} o
   * @param {import('./indexer.js').Indexer} o.indexer
   * @param {{ tipHeight(): Promise<number>, blockHash(h: number): Promise<string>, block(hash: string): Promise<object> }} o.source
   * @param {number} o.startHeight first block to read (the activation height)
   * @param {number} [o.confirmations] blocks to wait before applying (0 = follow the tip)
   * @param {number} [o.keepDepth] undo history kept for reorgs, in blocks
   */
  constructor({ indexer, source, startHeight, confirmations = 0, keepDepth = 288, log = () => {} }) {
    this.indexer = indexer;
    this.source = source;
    this.startHeight = startHeight;
    this.confirmations = confirmations;
    this.keepDepth = keepDepth;
    this.log = log;
    this.hashes = new Map(); // height -> hash of the applied block
  }

  /** Applies every block up to the tip. Returns how many blocks were applied. */
  async step() {
    const tip = (await this.source.tipHeight()) - this.confirmations;
    let applied = 0;
    for (;;) {
      const next = this.indexer.height === null ? this.startHeight : this.indexer.height + 1;
      if (next > tip) return applied;
      const block = await this.source.block(await this.source.blockHash(next));
      if (block.height !== next) throw new Error(`source returned block ${block.height} for height ${next}`);
      const known = this.hashes.get(next - 1);
      if (next > this.startHeight && known !== undefined && block.prev !== known) {
        await this._reorg(next - 1);
        continue;
      }
      const r = this.indexer.applyBlock(block);
      this.hashes.set(next, block.hash);
      this.hashes.delete(next - this.keepDepth - 1);
      this.indexer.pruneFrames(this.keepDepth);
      this.log(r);
      applied++;
    }
  }

  async _reorg(height) {
    let h = height;
    while (h >= this.startHeight && (await this.source.blockHash(h)) !== this.hashes.get(h)) h--;
    const target = Math.max(h, this.startHeight - 1);
    this.log({ reorg: true, from: this.indexer.height, to: target });
    this.indexer.rollback(target);
    for (const k of [...this.hashes.keys()]) if (k > target) this.hashes.delete(k);
  }

  /** Polls the source until `signal` aborts. */
  async run({ intervalMs = 15000, signal } = {}) {
    while (!signal?.aborted) {
      try {
        await this.step();
      } catch (e) {
        this.log({ error: e.message });
      }
      await new Promise((resolve) => {
        const t = setTimeout(resolve, intervalMs);
        signal?.addEventListener('abort', () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
  }
}
