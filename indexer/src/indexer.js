// SH-20 reference indexer (draft v0.3).
//
// Replays blocks in order and keeps the whole SH-20 state: tickers, mints,
// the shared note tree and its per-block roots, nullifiers, listings and the
// running digest. Every rule here is a rule of the standard; two honest
// indexers fed the same blocks reach the same digest.
//
// Proof verification is pluggable. The default verifier rejects every spend,
// so nothing that needs a proof is accepted until a pinned verifier is given.

import { createHash } from 'node:crypto';
import { DEFAULT_PROFILE, DOMAIN, FR, MIN_LOCK_SATS, PAY_MODE, N_OUT } from './constants.js';
import { extractEnvelope } from './carrier.js';
import { parseEnvelope, CodecError } from './codec.js';
import { NoteTree } from './tree.js';
import { noteLeaf, frToBytes, tickerT, PUBLIC_RHO } from './notes.js';
import { verify as schnorrVerify } from './schnorr.js';
import { encodeEvents } from './events.js';

export class Reject extends Error {}

export const rejectAllVerifier = Object.freeze({ name: 'reject-all', verifySpend: () => false });

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

const hexFr = (x) => x.toString(16).padStart(64, '0');

const isOpReturn = (script) => script.length > 0 && script[0] === 0x6a;
const isP2TR = (script) => script.length === 34 && script[0] === 0x51 && script[1] === 0x20;

export class Indexer {
  constructor({ profile = {}, verifier = rejectAllVerifier } = {}) {
    this.profile = { ...DEFAULT_PROFILE, ...profile };
    this.verifier = verifier;
    this.tree = new NoteTree();
    this.emptyRoot = this.tree.root;
    this.tokens = new Map(); // ticker -> token record, in DEPLOY order
    this.meta = new Map(); // 'genesis' -> ticker of the genesis token (from the profile)
    this.nullifiers = new Set(); // hex
    this.roots = new Map(); // height -> root after that block
    this.listings = new Map(); // LIST txid -> listing
    this.locks = new Map(); // "txid:vout" -> LIST txid
    this.teamQueue = new Map(); // unlock height -> [{ ticker, v, npk }]
    this.height = null;
    this.digest = sha256(Buffer.from(DOMAIN.DIGEST, 'utf8'));
    this.frames = [];
    this._ops = null;
    // One entry per tree leaf, in tree order: what a wallet needs to find its notes.
    // Not part of the digest; it is derived from the same accepted envelopes.
    this.notes = [];
    this._ctx = { height: null, txid: null };
    // Per-block history for explorers: accepted events and rejected envelopes, and
    // the block of every SH-20 transaction. Undone on reorgs; not part of the digest.
    this.history = new Map(); // height -> { height, hash, digest, root, events, rejected }
    this.txIndex = new Map(); // txid -> height
    this.digests = new Map(); // height -> digest hex, every block: lets anyone compare indexers at one height
  }

  /** Appends a leaf to the tree and records its metadata for wallets. */
  _append(leaf, meta) {
    const pos = this.tree.append(leaf);
    this.notes.push({ pos, height: this._ctx.height, txid: this._ctx.txid, leaf: hexFr(leaf), ...meta });
    return pos;
  }

  // ---- undo log -----------------------------------------------------------

  _set(map, key, value) {
    this._ops.push({ kind: 'map', map, key, had: map.has(key), prev: map.get(key) });
    map.set(key, value);
  }

  _add(set, key) {
    this._ops.push({ kind: 'set', set, key });
    set.add(key);
  }

  // ---- blocks -------------------------------------------------------------

  /**
   * Applies one block. Block format: { height, hash, txs: [{ txid, vin: [{ txid, vout, witness: Buffer[] } | { coinbase: true }], vout: [{ value: bigint, script: Buffer }] }] }
   */
  applyBlock(block) {
    if (this.height !== null && block.height !== this.height + 1) {
      throw new Error(`expected block ${this.height + 1}, got ${block.height}`);
    }
    this._ops = [];
    const frame = { height: block.height, ops: this._ops, tree: this.tree.snapshot(), digest: this.digest };
    const events = [];
    const rejected = [];

    this._ctx = { height: block.height, txid: null };
    if (block.height >= this.profile.activationHeight) {
      if (!this.meta.has('genesis')) events.push(this._installGenesis(block.height));
      const unlocks = (this.teamQueue.get(block.height) || []).slice().sort((a, b) => (a.ticker < b.ticker ? -1 : a.ticker > b.ticker ? 1 : 0));
      for (const u of unlocks) {
        const pos = this._append(noteLeaf(tickerT(u.ticker), u.v, u.npk, PUBLIC_RHO), { kind: 'TEAM', ticker: u.ticker, v: u.v, npk: hexFr(u.npk) });
        this._intoPool(u.ticker, u.v);
        events.push({ type: 'TEAM_UNLOCK', ticker: u.ticker, v: u.v, pos });
      }
      for (const tx of block.txs) this._applyTx(tx, block.height, events, rejected);
    }

    this._set(this.roots, block.height, this.tree.root);
    const delta = sha256(encodeEvents(events));
    const h = Buffer.alloc(4);
    h.writeUInt32LE(block.height);
    this.digest = sha256(this.digest, h, frToBytes(this.tree.root), delta);

    this._set(this.digests, block.height, this.digest.toString('hex'));
    if (events.length || rejected.length) {
      this._set(this.history, block.height, {
        height: block.height, hash: block.hash ?? null, digest: this.digest.toString('hex'),
        root: hexFr(this.tree.root), leaves: this.tree.size, events, rejected,
      });
      for (const e of [...events, ...rejected]) if (e.txid && !this.txIndex.has(e.txid)) this._set(this.txIndex, e.txid, block.height);
    }

    this.frames.push(frame);
    this._ops = null;
    this.height = block.height;
    return { height: block.height, root: this.tree.root, digest: this.digest.toString('hex'), events, rejected };
  }

  /** Forgets undo data older than `depth` blocks; deeper reorgs then throw. */
  pruneFrames(depth) {
    const keepFrom = this.frames.length - depth;
    if (keepFrom > 0) this.frames.splice(0, keepFrom);
  }

  /** Lowest height `rollback` can reach (one below the oldest kept frame). */
  get rollbackFloor() {
    return this.frames.length ? this.frames[0].height - 1 : this.height;
  }

  /** Undoes every block above `height` (reorg). */
  rollback(height) {
    if (this.height !== null && height < this.rollbackFloor) {
      throw new Error(`reorg below ${this.rollbackFloor} is deeper than the kept undo history`);
    }
    while (this.frames.length && this.frames[this.frames.length - 1].height > height) {
      const f = this.frames.pop();
      for (let i = f.ops.length - 1; i >= 0; i--) {
        const op = f.ops[i];
        if (op.kind === 'map') {
          if (op.had) op.map.set(op.key, op.prev);
          else op.map.delete(op.key);
        } else {
          op.set.delete(op.key);
        }
      }
      this.tree.restore(f.tree);
      this.notes.length = this.tree.size;
      this.digest = f.digest;
      this.height = f.height - 1;
    }
  }

  // ---- transactions -------------------------------------------------------

  _applyTx(tx, H, events, rejected) {
    this._ctx = { height: H, txid: tx.txid };
    const spentLocks = [];
    for (const input of tx.vin) {
      if (input.coinbase) continue;
      const id = this.locks.get(`${input.txid}:${input.vout}`);
      if (id && this.listings.get(id).state === 'ACTIVE') spentLocks.push(id);
    }

    const found = extractEnvelope(tx);
    if (found.error) rejected.push({ txid: tx.txid, reason: found.error });
    if (found.bytes) {
      try {
        const { env, body } = parseEnvelope(found.bytes);
        const event = this._apply(env, body, tx, H, spentLocks);
        events.push({ txid: tx.txid, ...event });
      } catch (e) {
        if (!(e instanceof Reject) && !(e instanceof CodecError)) throw e;
        rejected.push({ txid: tx.txid, reason: e.message });
      }
    }

    for (const id of spentLocks) {
      const l = this.listings.get(id);
      if (l.state === 'ACTIVE') {
        this._set(this.listings, id, { ...l, state: 'CLOSED', closedBy: tx.txid });
        events.push({ txid: tx.txid, type: 'CLOSED', listTxid: id });
      }
    }
  }

  _apply(env, body, tx, H, spentLocks) {
    switch (env.type) {
      case 'DEPLOY':
        return this._deploy(env, body, tx, H);
      case 'MINT':
        return this._mint(env, tx, H);
      case 'TRANSFER': {
        const s = this._checkSpend(env.spend, body, 0n, 0n, H);
        return { type: 'TRANSFER', ...this._commitSpend(s) };
      }
      case 'BURN':
        return this._burn(env, body, H);
      case 'LIST':
        return this._list(env, body, tx, H);
      case 'TAKE':
        return this._take(env, tx, spentLocks);
      case 'CLAIM':
        return this._claim(env);
      default:
        throw new Reject('unknown type');
    }
  }

  _token(ticker) {
    const t = this.tokens.get(ticker);
    if (!t) throw new Reject('unknown ticker');
    return t;
  }

  /** Ticker of the genesis token (fixed by the profile), or undefined before activation. */
  get genesis() {
    return this.meta.get('genesis');
  }

  _paid(tx, payMode, price, payScript) {
    if (payMode === PAY_MODE.NONE) return true;
    let sum = 0n;
    for (const out of tx.vout) {
      if (payMode === PAY_MODE.BURN ? isOpReturn(out.script) : out.script.equals(payScript)) sum += out.value;
    }
    return sum >= price;
  }

  _roomFor(k) {
    if (this.tree.size + k > this.tree.capacity) throw new Reject('note tree is full');
  }

  _checkSpend(spend, body, vPub, tPub, H) {
    const { anchorWindow: W, anchorMinDepth: K, activationHeight } = this.profile;
    const a = spend.anchorHeight;
    if (a < H - W || a > H - K) throw new Reject('anchor outside the window');
    const root = a < activationHeight ? this.emptyRoot : this.roots.get(a);
    if (root === undefined) throw new Reject('unknown anchor');
    const [n0, n1] = spend.nf;
    if (n0 === 0n || n1 === 0n) throw new Reject('zero nullifier');
    if (n0 === n1) throw new Reject('duplicate nullifier');
    if (this.nullifiers.has(hexFr(n0)) || this.nullifiers.has(hexFr(n1))) throw new Reject('nullifier already spent');
    const outLeaves = spend.outs.map((o) => o.leaf);
    if (outLeaves.some((x) => x === 0n)) throw new Reject('zero output leaf');
    this._roomFor(N_OUT);
    const bodyHash = BigInt('0x' + sha256(Buffer.from(DOMAIN.BODY, 'utf8'), body).toString('hex')) % FR;
    const ok = this.verifier.verifySpend({
      root, nullifiers: [n0, n1], outLeaves, bodyHash, vPub, tPub, proof: spend.proof,
    });
    if (!ok) throw new Reject('invalid proof');
    return { nf: [n0, n1], outs: spend.outs };
  }

  _commitSpend({ nf, outs }) {
    for (const x of nf) this._add(this.nullifiers, hexFr(x));
    const positions = outs.map((o, j) =>
      this._append(o.leaf, { kind: 'OUT', j, pkEph: o.pkEph.toString('hex'), ct: o.ct.toString('hex') }),
    );
    return { nullifiers: nf.map(hexFr), positions };
  }

  /** Creates the genesis token from the profile, in the first block read (the activation block). */
  _installGenesis(H) {
    const g = this.profile.genesis;
    this._set(this.meta, 'genesis', g.ticker);
    this._set(this.tokens, g.ticker, {
      ticker: g.ticker, t: tickerT(g.ticker), max: g.max, lim: g.lim, pre: 0n, start: H, end: 0, unlock: H, price: 0n,
      payMode: PAY_MODE.NONE, payScript: '', mints: 0n, burned: 0n, pool: 0n, deployTxid: null, deployHeight: H, genesis: true,
    });
    // The record commits to the profile's rules, so indexers run with different
    // profiles part at the activation block, not at the first spend it touches.
    const { deployBurn, anchorWindow, anchorMinDepth } = this.profile;
    return { type: 'GENESIS', ticker: g.ticker, max: g.max, lim: g.lim, deployBurn, anchorWindow, anchorMinDepth };
  }

  // ---- the turnstile ------------------------------------------------------
  // pool[t] = what entered the shielded pool in public (mints, team unlocks, TAKE, CLAIM) minus
  // what left it in public (BURN, LIST, the DEPLOY burn). All of these amounts are public already.
  // A spend may not take out more of a ticker than the pool holds: a soundness bug in the circuit
  // could forge hidden notes, but never bring more than the honest supply back into the open.

  _intoPool(ticker, v) {
    const t = this.tokens.get(ticker);
    this._set(this.tokens, ticker, { ...t, pool: t.pool + v });
  }

  _outOfPool(ticker, v, apply = true) {
    const t = this.tokens.get(ticker);
    if (v > t.pool) throw new Reject('more than the pool holds of this ticker');
    if (apply) this._set(this.tokens, ticker, { ...t, pool: t.pool - v });
  }

  _deploy(env, body, tx, H) {
    if (this.tokens.has(env.ticker)) throw new Reject('ticker already deployed');
    const { max, lim, pre, start, end, unlock, price, payMode } = env;
    if (max <= 0n || lim <= 0n) throw new Reject('max and lim must be positive');
    if (pre >= max) throw new Reject('pre must leave a public mint (pre < max)');
    if ((max - pre) % lim !== 0n) throw new Reject('(max - pre) must be a multiple of lim');
    if (start <= H) throw new Reject('start must be after the DEPLOY block');
    if (end !== 0 && end < start) throw new Reject('end before start');
    if (unlock < start) throw new Reject('unlock before start');
    if (payMode === PAY_MODE.NONE && price !== 0n) throw new Reject('payMode 0 needs price 0');
    if (payMode !== PAY_MODE.NONE && price <= 0n) throw new Reject('price must be positive');

    const D = this.profile.deployBurn;
    let spent = null;
    if (D > 0n) {
      if (!env.spend) throw new Reject('DEPLOY must burn genesis units');
      this._outOfPool(this.genesis, D, false);
      spent = this._checkSpend(env.spend, body, D, tickerT(this.genesis), H);
    } else if (env.spend) {
      throw new Reject('DEPLOY carries no burn when D = 0');
    }

    const commit = spent ? this._commitSpend(spent) : null;
    if (spent) {
      this._outOfPool(this.genesis, D);
      const g = this.tokens.get(this.genesis);
      this._set(this.tokens, g.ticker, { ...g, burned: g.burned + D });
    }
    this._set(this.tokens, env.ticker, {
      ticker: env.ticker, t: tickerT(env.ticker), max, lim, pre, start, end, unlock, price, payMode,
      payScript: env.payScript.toString('hex'), mints: 0n, burned: 0n, pool: 0n, deployTxid: tx.txid, deployHeight: H,
    });
    if (pre > 0n) {
      const queue = (this.teamQueue.get(unlock) || []).concat([{ ticker: env.ticker, v: pre, npk: env.team.npk }]);
      this._set(this.teamQueue, unlock, queue);
    }
    return { type: 'DEPLOY', ticker: env.ticker, ...(commit ? { burn: commit } : {}) };
  }

  _mint(env, tx, H) {
    const t = this._token(env.ticker);
    if (H < t.start) throw new Reject('mint not open yet');
    if (t.end !== 0 && H > t.end) throw new Reject('mint closed');
    const left = (t.max - t.pre) / t.lim - t.mints;
    if (left <= 0n) throw new Reject('sold out');
    // A batch near the end gets what is left, and pays only for that.
    const k = BigInt(env.k ?? 1) < left ? BigInt(env.k ?? 1) : left;
    if (!this._paid(tx, t.payMode, t.price * k, Buffer.from(t.payScript, 'hex'))) throw new Reject('mint not paid');
    this._roomFor(1);
    const v = t.lim * k;
    const pos = this._append(noteLeaf(t.t, v, env.npk, PUBLIC_RHO), { kind: 'MINT', ticker: t.ticker, v, npk: hexFr(env.npk) });
    this._set(this.tokens, t.ticker, { ...t, mints: t.mints + k, pool: t.pool + v });
    return { type: 'MINT', ticker: t.ticker, v, pos };
  }

  _burn(env, body, H) {
    const t = this._token(env.ticker);
    if (env.vPub <= 0n) throw new Reject('burn amount must be positive');
    this._outOfPool(t.ticker, env.vPub, false);
    const s = this._checkSpend(env.spend, body, env.vPub, t.t, H);
    const commit = this._commitSpend(s);
    this._set(this.tokens, t.ticker, { ...t, burned: t.burned + env.vPub, pool: t.pool - env.vPub });
    return { type: 'BURN', ticker: t.ticker, v: env.vPub, ...commit };
  }

  _list(env, body, tx, H) {
    const t = this._token(env.ticker);
    if (env.amount <= 0n || env.price <= 0n) throw new Reject('amount and price must be positive');
    const lock = tx.vout[env.lockVout];
    if (!lock) throw new Reject('no lock output');
    if (!isP2TR(lock.script) || !lock.script.subarray(2).equals(env.lockKey)) throw new Reject('lock output must be P2TR to lockKey');
    if (lock.value < MIN_LOCK_SATS) throw new Reject('lock output below 330 sats');
    this._outOfPool(t.ticker, env.amount, false);
    const s = this._checkSpend(env.spend, body, env.amount, t.t, H);
    const commit = this._commitSpend(s);
    this._outOfPool(t.ticker, env.amount);
    const listing = {
      listTxid: tx.txid, ticker: t.ticker, amount: env.amount, price: env.price,
      payScript: env.payScript.toString('hex'), lock: `${tx.txid}:${env.lockVout}`,
      lockKey: env.lockKey.toString('hex'), state: 'ACTIVE', height: H,
    };
    this._set(this.listings, tx.txid, listing);
    this._set(this.locks, listing.lock, tx.txid);
    return { type: 'LIST', listTxid: tx.txid, ticker: t.ticker, amount: env.amount, price: env.price, ...commit };
  }

  _take(env, tx, spentLocks) {
    const id = spentLocks.find((x) => this.listings.get(x).state === 'ACTIVE');
    if (!id) throw new Reject('TAKE must spend an active listing lock');
    const l = this.listings.get(id);
    this._roomFor(1);
    const sold = this._paid(tx, PAY_MODE.PAY, l.price, Buffer.from(l.payScript, 'hex'));
    const pos = this._append(noteLeaf(tickerT(l.ticker), l.amount, env.npk, PUBLIC_RHO), { kind: 'TAKE', ticker: l.ticker, v: l.amount, npk: hexFr(env.npk) });
    this._intoPool(l.ticker, l.amount);
    this._set(this.listings, id, { ...l, state: sold ? 'SOLD' : 'CANCELLED', takeTxid: tx.txid });
    return { type: 'TAKE', listTxid: id, outcome: sold ? 'SOLD' : 'CANCELLED', pos };
  }

  _claim(env) {
    const l = this.listings.get(env.listTxid);
    if (!l) throw new Reject('unknown listing');
    if (l.state !== 'CLOSED') throw new Reject('listing is not CLOSED');
    const msg = Indexer.claimMessage(env.listTxid, env.npk);
    if (!schnorrVerify(Buffer.from(l.lockKey, 'hex'), msg, env.sig)) throw new Reject('bad CLAIM signature');
    this._roomFor(1);
    const pos = this._append(noteLeaf(tickerT(l.ticker), l.amount, env.npk, PUBLIC_RHO), { kind: 'CLAIM', ticker: l.ticker, v: l.amount, npk: hexFr(env.npk) });
    this._intoPool(l.ticker, l.amount);
    this._set(this.listings, l.listTxid, { ...l, state: 'CLAIMED' });
    return { type: 'CLAIM', listTxid: l.listTxid, pos };
  }

  // ---- read side ----------------------------------------------------------

  token(ticker) {
    return this.tokens.get(ticker) ?? null;
  }

  /** Message a seller signs with the lock key to CLAIM a CLOSED listing. */
  static claimMessage(listTxid, npk) {
    return sha256(Buffer.from(DOMAIN.CLAIM, 'utf8'), Buffer.from(listTxid, 'hex'), frToBytes(npk));
  }
}
