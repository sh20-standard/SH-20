// The relayer (docs/RELAYER.md): takes proved TRANSFERs that pay it, checks each one as its indexer
// would before it spends a satoshi on it, and publishes them in batches from its own coins.
//
//   submit(hex)   §2: the checks, then the queue; answers { code, body } for the HTTP route
//   tick()        §3: publishes the queue when it is due (full, old enough, or a deadline near)
//   status(nf)    a transfer by either of its nullifiers
//   info()        what a sender needs: the address its fee is sealed to, the fees, the limits
//
// It trusts one indexer, its own: for the tip, the roots, the nullifiers spent and the profile's
// W and K_min. Esplora gives its coins, the fee rate, and takes the two transactions.

import { Refusal, decodeTransfer, checkAnchor, feeOf, verifierArgs, fromHexBody } from './check.js';
import { buildBatch } from './batch.js';
import { oneTimeSecret } from '../../vault/src/taproot.js';
import { toHex } from '../../vault/src/bytes.js';

export const DEFAULTS = Object.freeze({ maxBatch: 10, maxWaitSeconds: 600, minBlocksLeft: 12, maxFeeRate: 50 });
const BATCH_LIMIT = 100; // envelopes per reveal: far below a standard transaction's 400,000 weight units
const VIEW_TTL_MS = 2000; // how long a read of the indexer serves the checks that follow it

export class Relayer {
  /**
   * keys      relayerKeys(): { notes, btc }
   * fees      Map ticker → the fee (bigint, in that ticker)
   * indexer   an IndexerApi (vault/src/api.js) of the relayer's own indexer
   * esplora   an Esplora (vault/src/api.js)
   * verifier  { verifySpend(args) → boolean }: indexer/src/adapters/plonk.js
   */
  constructor({ keys, fees, indexer, esplora, verifier, maxBatch = DEFAULTS.maxBatch, maxWaitSeconds = DEFAULTS.maxWaitSeconds, minBlocksLeft = DEFAULTS.minBlocksLeft, maxFeeRate = DEFAULTS.maxFeeRate, now = Date.now, log = () => {} }) {
    if (!(maxBatch >= 1 && maxBatch <= BATCH_LIMIT)) throw new Error(`maxBatch must be 1 to ${BATCH_LIMIT}`);
    if (!(minBlocksLeft >= 1)) throw new Error('minBlocksLeft must be at least 1');
    for (const [t, v] of fees) if (!/^[A-Z0-9]{4}$/.test(t) || typeof v !== 'bigint' || v <= 0n) throw new Error(`bad fee ${t}=${v}`);
    Object.assign(this, { keys, fees, indexer, esplora, verifier, maxBatch, maxWaitSeconds, minBlocksLeft, maxFeeRate, now, log });
    this.transfers = []; // every record, in arrival order
    this.byNf = new Map(); // nullifier hex → record (queued or published)
    this.held = new Set(); // nullifiers of submissions being checked: two at once cannot both pass
    this.coins = { spent: new Set(), own: [] }; // outpoints spent, outputs of ours not yet seen by Esplora
    this.view = null;
    this.publishing = Promise.resolve();
  }

  /** The indexer's tip, profile and nullifiers, read again when older than VIEW_TTL_MS (or when `fresh`). */
  async chain({ fresh = false } = {}) {
    if (!fresh && this.view && this.now() - this.view.at < VIEW_TTL_MS) return this.view;
    let status, list, tip;
    try {
      [status, list, tip] = await Promise.all([this.indexer.status(), this.indexer.nullifiers(), this.esplora.tipHeight()]);
    } catch (e) {
      throw new Refusal(503, `the relayer cannot read its indexer or Esplora now (${e.message})`);
    }
    if (!Number.isInteger(status?.height)) throw new Refusal(503, 'the indexer has no height yet');
    if (list === null) throw new Refusal(503, 'the indexer serves no /nullifiers: the relayer cannot tell a spent note');
    if (tip > status.height + 1) throw new Refusal(503, `the indexer is at block ${status.height}, the chain at ${tip}: it is behind`);
    this.view = {
      at: this.now(), height: status.height, next: status.height + 1, network: status.network,
      W: status.anchorWindow, kMin: status.anchorMinDepth, spent: new Set(list.map((n) => n.nullifier)),
    };
    return this.view;
  }

  async info() {
    let height = null;
    try {
      height = (await this.chain()).height;
    } catch {}
    return {
      version: 'v0.3', network: this.view?.network ?? null, address: this.keys.notes.addressString,
      fees: Object.fromEntries([...this.fees].map(([t, v]) => [t, v.toString()])),
      maxBatch: this.maxBatch, maxWaitSeconds: this.maxWaitSeconds, minBlocksLeft: this.minBlocksLeft,
      height, queued: this.queue().length,
    };
  }

  queue() {
    return this.transfers.filter((r) => r.state === 'queued');
  }

  status(nf) {
    const r = this.byNf.get(String(nf).toLowerCase()) ?? this.transfers.findLast((x) => x.nullifiers.includes(String(nf).toLowerCase()));
    return r ? view(r) : null;
  }

  /** docs/RELAYER.md §2. Returns { code, body } and never throws for what a sender sent. */
  async submit(hex) {
    let t;
    try {
      t = decodeTransfer(fromHexBody(hex));
    } catch (e) {
      return refused(e);
    }
    const known = t.nullifiers.map((nf) => this.byNf.get(nf)).find(Boolean);
    if (known) {
      if (toHex(known.bytes) === toHex(t.bytes)) return { code: 200, body: view(known) };
      return refused(new Refusal(409, `a nullifier of this transfer is in another one this relayer has ${known.state}`));
    }
    if (t.nullifiers.some((nf) => this.held.has(nf))) return refused(new Refusal(409, 'a transfer with the same nullifier is being checked'));
    t.nullifiers.forEach((nf) => this.held.add(nf));
    try {
      const c = await this.chain();
      const deadline = checkAnchor(t.anchorHeight, { next: c.next, W: c.W, kMin: c.kMin, minBlocksLeft: this.minBlocksLeft });
      if (t.nullifiers.some((nf) => c.spent.has(nf))) throw new Refusal(409, 'a nullifier of this transfer is already spent: its note was spent before');
      const fee = await feeOf(this.keys.notes, t.env, this.fees);
      const root = await this.indexer.rootAt(t.anchorHeight).catch((e) => {
        throw new Refusal(503, `the relayer cannot read the root at ${t.anchorHeight} (${e.message})`);
      });
      if (root === null) throw new Refusal(422, `the indexer has no root at block ${t.anchorHeight}`);
      if (!this.verifier.verifySpend(verifierArgs(t, BigInt('0x' + root)))) throw new Refusal(422, 'the proof does not verify against its public inputs');
      const r = { ...t, fee, deadline, at: this.now(), state: 'queued', txid: null, reason: null };
      this.transfers.push(r);
      t.nullifiers.forEach((nf) => this.byNf.set(nf, r));
      this.log(`queued ${t.nullifiers[0].slice(0, 16)}… paying ${fee.v} ${fee.ticker}, deadline ${deadline} (${this.queue().length} queued)`);
      return { code: 202, body: view(r) };
    } catch (e) {
      return refused(e);
    } finally {
      t.nullifiers.forEach((nf) => this.held.delete(nf));
    }
  }

  /** docs/RELAYER.md §3: publishes the queue if it is due. One run at a time. Returns what it published, or null. */
  tick() {
    const run = this.publishing.catch(() => {}).then(() => this.#tick());
    this.publishing = run;
    return run;
  }

  async #tick() {
    if (this.unsent) {
      // a reveal whose commit went out without it: sent again before anything else
      const u = this.unsent;
      await this.esplora.broadcast(u.reveal.hex);
      this.unsent = null;
      return this.#published(u);
    }
    if (!this.queue().length) return null;
    const c = await this.chain({ fresh: true });
    for (const r of this.queue()) {
      if (r.deadline < c.next) this.#drop(r, `its anchor ran out at block ${r.deadline} before a batch took it`);
      else if (r.nullifiers.some((nf) => c.spent.has(nf))) this.#drop(r, 'a nullifier of it was spent by another transaction');
    }
    const q = this.queue();
    if (!q.length) return null;
    const due = q.length >= this.maxBatch || this.now() - q[0].at >= this.maxWaitSeconds * 1000 || q.some((r) => r.deadline - c.next < this.minBlocksLeft);
    return due ? this.#publish(q.slice(0, this.maxBatch), c) : null;
  }

  #drop(r, reason) {
    r.state = 'dropped';
    r.reason = reason;
    r.nullifiers.forEach((nf) => this.byNf.delete(nf));
    this.log(`dropped ${r.nullifiers[0].slice(0, 16)}…: ${reason}`);
  }

  async #publish(batch, c) {
    const feeRate = Math.min(await this.esplora.feeRate(), this.maxFeeRate);
    const key = (u) => `${u.txid}:${u.vout}`;
    const seen = await this.esplora.utxos(this.keys.btc.address);
    const utxos = [...seen, ...this.coins.own.filter((o) => !seen.some((u) => key(u) === key(o)))].filter((u) => !this.coins.spent.has(key(u)));
    const b = buildBatch({ envelopes: batch.map((r) => r.bytes), secret: oneTimeSecret(), btc: this.keys.btc, utxos, feeRate, tipHeight: c.height });
    await this.esplora.broadcast(b.commit.hex); // a refusal leaves the batch queued for the next tick
    for (const u of b.commit.spent) this.coins.spent.add(key(u));
    this.coins.own.push(...this.#ours(b.commit.tx, b.commit.txid));
    const done = { ...b, batch, feeRate };
    try {
      await this.esplora.broadcast(b.reveal.hex);
    } catch (e) {
      // the commit is out, and only this reveal gets its output back: kept, and sent again at the next tick
      this.unsent = done;
      throw e;
    }
    return this.#published(done);
  }

  #ours(tx, id) {
    const mine = toHex(this.keys.btc.script);
    return tx.vout.map((o, vout) => ({ txid: id, vout, value: o.value, script: o.script })).filter((o) => toHex(o.script) === mine);
  }

  #published({ commit, reveal, batch, feeRate }) {
    this.coins.spent.add(`${commit.txid}:0`);
    this.coins.own.push(...this.#ours(reveal.tx, reveal.txid));
    for (const r of batch) Object.assign(r, { state: 'published', txid: reveal.txid });
    const out = { txid: reveal.txid, commitTxid: commit.txid, transfers: batch.length, revealVsize: reveal.vsize, commitVsize: commit.vsize, fees: commit.fee + reveal.fee, feeRate };
    this.log(`published ${batch.length} transfer(s) in ${out.txid}: reveal ${out.revealVsize} vB, commit ${out.commitVsize} vB, ${out.fees} sats at ${feeRate} sat/vB`);
    return out;
  }
}

const view = (r) => ({
  state: r.state, nullifiers: r.nullifiers, fee: { ticker: r.fee.ticker, v: r.fee.v.toString() }, deadline: r.deadline,
  ...(r.txid ? { txid: r.txid } : {}), ...(r.reason ? { reason: r.reason } : {}),
});

function refused(e) {
  if (!(e instanceof Refusal)) return { code: 500, body: { error: `the relayer failed: ${e.message}` } };
  return { code: e.status, body: { error: e.message } };
}
