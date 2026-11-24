// Follows a live chain and feeds the indexer, handling reorgs.
//
// Two block sources, both read-only and both optional to trust only for chain
// selection (the indexer re-checks every envelope itself):
//   - BitcoindSource: your own Bitcoin Core node over JSON-RPC (recommended)
//   - EsploraSource:  any Esplora REST API (mempool.space, blockstream.info, self-hosted)
// Both return blocks as { height, hash, prev, txs } in the indexer's format.

import { fromBitcoindBlock } from './adapters/bitcoind.js';
import { parseRawBlock } from './adapters/rawblock.js';
import { extractEnvelope } from './carrier.js';
import { MAGIC, TYPE } from './constants.js';

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

  /**
   * The block's transactions from its raw bytes, in one request; null if the server does not serve them. Bytes that
   * are not the block asked for are refused, never replaced by the pages: the follower tries again at its next step.
   */
  async _raw(hash, head) {
    const path = `/block/${hash}/raw`;
    const res = await this.fetch(this.base + path).catch(() => null);
    if (!res?.ok) return null;
    let block;
    try {
      block = parseRawBlock(Buffer.from(await res.arrayBuffer()));
    } catch (e) {
      throw new Error(`esplora ${path}: ${e.message}`);
    }
    if (block.hash !== hash) throw new Error(`esplora ${path}: the bytes are those of block ${block.hash}`);
    // the block's own header against what /block/:hash said of it
    const prev = head.previousblockhash ?? '0'.repeat(64);
    if (block.prev !== prev) throw new Error(`esplora ${path}: the block before is ${block.prev}, not ${prev}`);
    if (block.txs.length !== head.tx_count) throw new Error(`esplora ${path}: ${block.txs.length} transactions for a tx_count of ${head.tx_count}`);
    return block.txs;
  }

  async block(hash) {
    const head = await this._get(`/block/${hash}`);
    // More than one page: the raw block, one request where pages of 25 take one per page (a mainnet block holds
    // thousands of transactions, and a public server limits its callers). Pages if the server has no /raw.
    const raw = head.tx_count > this.pageSize ? await this._raw(hash, head) : null;
    const txs = raw ?? [];
    for (let start = 0; !raw && start < head.tx_count; start += this.pageSize) {
      const page = await this._get(`/block/${hash}/txs/${start}`);
      for (const t of page) {
        txs.push({
          txid: t.txid,
          vin: t.vin.map((i) => (i.is_coinbase ? { coinbase: true } : { txid: i.txid, vout: i.vout, witness: hexBufs(i.witness) })),
          vout: t.vout.map((o) => ({ value: BigInt(o.value), script: Buffer.from(o.scriptpubkey, 'hex') })),
        });
      }
    }
    // A DEPLOY needs the height that confirmed the output its input 0 spends (SPEC-WIRE §5): Esplora gives it per
    // transaction, so it is fetched for witness DEPLOYs only.
    for (const tx of txs) {
      const found = extractEnvelope(tx);
      if (found.carrier === 'witness' && found.bytes.length > MAGIC.length + 1 && found.bytes[MAGIC.length + 1] === TYPE.DEPLOY) {
        const status = await this._get(`/tx/${tx.vin[0].txid}/status`);
        if (Number.isInteger(status.block_height)) tx.vin[0].prevHeight = status.block_height;
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
    const json = await this.rpc('getblock', [hash, 3]); // 3: with each input's spent output and its height
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
   * @param {import('./blockfile.js').BlockFile} [o.file] keeps every block applied, and every rollback (--data)
   */
  constructor({ indexer, source, startHeight, confirmations = 0, keepDepth = 288, log = () => {}, file = null }) {
    this.indexer = indexer;
    this.source = source;
    this.startHeight = startHeight;
    this.confirmations = confirmations;
    this.keepDepth = keepDepth;
    this.log = log;
    this.file = file;
    this.hashes = new Map(); // height -> hash of the applied block
  }

  /**
   * Applies the blocks of the block file before the first step, without asking the source for them: a restart
   * goes on from there. The next step checks the last of them against the source, as it checks every tip, so
   * blocks a reorg replaced while the follower was stopped are undone then. Returns how many were applied.
   */
  restore(blocks) {
    if (this.indexer.height !== null) throw new Error('restore() comes before the first block');
    for (const block of blocks) this._apply(block, { keep: false });
    return blocks.length;
  }

  _apply(block, { keep = true } = {}) {
    const r = this.indexer.applyBlock(block);
    this.hashes.set(block.height, block.hash);
    this.hashes.delete(block.height - this.keepDepth - 1);
    this.indexer.pruneFrames(this.keepDepth);
    if (keep) this.file?.append(block);
    return r;
  }

  /** Applies every block up to the tip. Returns how many blocks were applied. */
  async step() {
    const tip = (await this.source.tipHeight()) - this.confirmations;
    // A reorg that does not lengthen the chain (a fork of the same height, or a shorter one) shows only at our own
    // tip: the next block, which the check below compares, may never come. Found by bin/api-diff.js --reorg 2,0.
    const ours = this.indexer.height;
    if (ours !== null && ours >= this.startHeight) {
      const h = Math.min(ours, tip);
      if (h < ours || (await this.source.blockHash(h)) !== this.hashes.get(h)) await this._reorg(h);
    }
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
      this.log(this._apply(block));
      applied++;
    }
  }

  async _reorg(height) {
    let h = height;
    while (h >= this.startHeight && (await this.source.blockHash(h)) !== this.hashes.get(h)) h--;
    const target = Math.max(h, this.startHeight - 1);
    this.log({ reorg: true, from: this.indexer.height, to: target });
    this.indexer.rollback(target);
    this.file?.rollback(target + 1);
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
