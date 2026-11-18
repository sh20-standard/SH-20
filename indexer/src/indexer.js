// SH-20 reference indexer (draft v0.1).
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
import { noteLeaf, frToBytes } from './notes.js';
import { verify as schnorrVerify } from './schnorr.js';

export class Reject extends Error {}

export const rejectAllVerifier = Object.freeze({ name: 'reject-all', verifySpend: () => false });

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

const hexFr = (x) => x.toString(16).padStart(64, '0');

const canonical = (value) =>
  JSON.stringify(value, (_, v) => {
    if (typeof v === 'bigint') return v.toString();
    if (v && v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data).toString('hex');
    return v;
  });

const isOpReturn = (script) => script.length > 0 && script[0] === 0x6a;
const isP2TR = (script) => script.length === 34 && script[0] === 0x51 && script[1] === 0x20;

export class Indexer {
  constructor({ profile = {}, verifier = rejectAllVerifier } = {}) {
    this.profile = { ...DEFAULT_PROFILE, ...profile };
    this.verifier = verifier;
    this.tree = new NoteTree();
    this.emptyRoot = this.tree.root;
    this.tickers = new Map(); // ticker -> tokenNum
    this.tokens = new Map(); // tokenNum -> token record
    this.nullifiers = new Set(); // hex
    this.roots = new Map(); // height -> root after that block
    this.listings = new Map(); // LIST txid -> listing
    this.locks = new Map(); // "txid:vout" -> LIST txid
    this.teamQueue = new Map(); // unlock height -> [{ tokenNum, v, npk, rho }]
    this.height = null;
    this.digest = sha256(Buffer.from(DOMAIN.DIGEST, 'utf8'));
    this.frames = [];
    this._ops = null;
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

    if (block.height >= this.profile.activationHeight) {
      const unlocks = (this.teamQueue.get(block.height) || []).slice().sort((a, b) => a.tokenNum - b.tokenNum);
      for (const u of unlocks) {
        const pos = this.tree.append(noteLeaf(u.tokenNum, u.v, u.npk, u.rho));
        events.push({ type: 'TEAM_UNLOCK', tokenNum: u.tokenNum, v: u.v, pos });
      }
      for (const tx of block.txs) this._applyTx(tx, block.height, events, rejected);
    }

    this._set(this.roots, block.height, this.tree.root);
    const delta = sha256(Buffer.from(canonical(events), 'utf8'));
    const h = Buffer.alloc(4);
    h.writeUInt32LE(block.height);
    this.digest = sha256(this.digest, h, frToBytes(this.tree.root), delta);

    this.frames.push(frame);
    this._ops = null;
    this.height = block.height;
    return { height: block.height, root: this.tree.root, digest: this.digest.toString('hex'), events, rejected };
  }

  /** Undoes every block above `height` (reorg). */
  rollback(height) {
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
      this.digest = f.digest;
      this.height = f.height - 1;
    }
    if (this.frames.length === 0 && this.height !== null && this.height > height) this.height = null;
  }

  // ---- transactions -------------------------------------------------------

  _applyTx(tx, H, events, rejected) {
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

  _token(tokenNum) {
    const t = this.tokens.get(tokenNum);
    if (!t) throw new Reject('unknown tokenNum');
    return t;
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
    return { nf: [n0, n1], outLeaves };
  }

  _commitSpend({ nf, outLeaves }) {
    for (const x of nf) this._add(this.nullifiers, hexFr(x));
    const positions = outLeaves.map((leaf) => this.tree.append(leaf));
    return { nullifiers: nf.map(hexFr), positions };
  }

  _deploy(env, body, tx, H) {
    if (this.tickers.has(env.ticker)) throw new Reject('ticker already deployed');
    const { max, lim, pre, start, end, unlock, price, payMode } = env;
    if (max <= 0n || lim <= 0n) throw new Reject('max and lim must be positive');
    if (pre >= max) throw new Reject('pre must leave a public mint (pre < max)');
    if ((max - pre) % lim !== 0n) throw new Reject('(max - pre) must be a multiple of lim');
    if (start <= H) throw new Reject('start must be after the DEPLOY block');
    if (end !== 0 && end < start) throw new Reject('end before start');
    if (unlock < start) throw new Reject('unlock before start');
    if (payMode === PAY_MODE.NONE && price !== 0n) throw new Reject('payMode 0 needs price 0');
    if (payMode !== PAY_MODE.NONE && price <= 0n) throw new Reject('price must be positive');

    const genesis = this.tokens.size === 0;
    let spent = null;
    if (genesis) {
      if (env.spend) throw new Reject('genesis DEPLOY carries no burn');
    } else {
      if (!env.spend) throw new Reject('DEPLOY must burn genesis units');
      spent = this._checkSpend(env.spend, body, this.profile.deployBurn, BigInt(this.profile.genesisTokenNum), H);
    }

    const tokenNum = this.tokens.size + 1;
    const commit = spent ? this._commitSpend(spent) : null;
    if (spent) {
      const g = this.tokens.get(this.profile.genesisTokenNum);
      this._set(this.tokens, g.tokenNum, { ...g, burned: g.burned + this.profile.deployBurn });
    }
    this._set(this.tickers, env.ticker, tokenNum);
    this._set(this.tokens, tokenNum, {
      tokenNum, ticker: env.ticker, max, lim, pre, start, end, unlock, price, payMode,
      payScript: env.payScript.toString('hex'), mints: 0n, burned: 0n, deployTxid: tx.txid, deployHeight: H,
    });
    if (pre > 0n) {
      const queue = (this.teamQueue.get(unlock) || []).concat([{ tokenNum, v: pre, npk: env.team.npk, rho: env.team.rho }]);
      this._set(this.teamQueue, unlock, queue);
    }
    return { type: 'DEPLOY', ticker: env.ticker, tokenNum, ...(commit ? { burn: commit } : {}) };
  }

  _mint(env, tx, H) {
    const t = this._token(env.tokenNum);
    if (H < t.start) throw new Reject('mint not open yet');
    if (t.end !== 0 && H > t.end) throw new Reject('mint closed');
    if (t.mints >= (t.max - t.pre) / t.lim) throw new Reject('sold out');
    if (!this._paid(tx, t.payMode, t.price, Buffer.from(t.payScript, 'hex'))) throw new Reject('mint not paid');
    this._roomFor(1);
    const pos = this.tree.append(noteLeaf(t.tokenNum, t.lim, env.npk, env.rho));
    this._set(this.tokens, t.tokenNum, { ...t, mints: t.mints + 1n });
    return { type: 'MINT', tokenNum: t.tokenNum, v: t.lim, pos };
  }

  _burn(env, body, H) {
    const t = this._token(env.tokenNum);
    if (env.vPub <= 0n) throw new Reject('burn amount must be positive');
    const s = this._checkSpend(env.spend, body, env.vPub, BigInt(t.tokenNum), H);
    const commit = this._commitSpend(s);
    this._set(this.tokens, t.tokenNum, { ...t, burned: t.burned + env.vPub });
    return { type: 'BURN', tokenNum: t.tokenNum, v: env.vPub, ...commit };
  }

  _list(env, body, tx, H) {
    const t = this._token(env.tokenNum);
    if (env.amount <= 0n || env.price <= 0n) throw new Reject('amount and price must be positive');
    const lock = tx.vout[env.lockVout];
    if (!lock) throw new Reject('no lock output');
    if (!isP2TR(lock.script)) throw new Reject('lock output must be P2TR');
    if (lock.value < MIN_LOCK_SATS) throw new Reject('lock output below 330 sats');
    const s = this._checkSpend(env.spend, body, env.amount, BigInt(t.tokenNum), H);
    const commit = this._commitSpend(s);
    const listing = {
      listTxid: tx.txid, tokenNum: t.tokenNum, amount: env.amount, price: env.price,
      payScript: env.payScript.toString('hex'), lock: `${tx.txid}:${env.lockVout}`,
      lockKey: lock.script.subarray(2).toString('hex'), state: 'ACTIVE', height: H,
    };
    this._set(this.listings, tx.txid, listing);
    this._set(this.locks, listing.lock, tx.txid);
    return { type: 'LIST', listTxid: tx.txid, tokenNum: t.tokenNum, amount: env.amount, price: env.price, ...commit };
  }

  _take(env, tx, spentLocks) {
    const id = spentLocks.find((x) => this.listings.get(x).state === 'ACTIVE');
    if (!id) throw new Reject('TAKE must spend an active listing lock');
    const l = this.listings.get(id);
    this._roomFor(1);
    const sold = this._paid(tx, PAY_MODE.PAY, l.price, Buffer.from(l.payScript, 'hex'));
    const pos = this.tree.append(noteLeaf(l.tokenNum, l.amount, env.npk, env.rho));
    this._set(this.listings, id, { ...l, state: sold ? 'SOLD' : 'CANCELLED', takeTxid: tx.txid });
    return { type: 'TAKE', listTxid: id, outcome: sold ? 'SOLD' : 'CANCELLED', pos };
  }

  _claim(env) {
    const l = this.listings.get(env.listTxid);
    if (!l) throw new Reject('unknown listing');
    if (l.state !== 'CLOSED') throw new Reject('listing is not CLOSED');
    const msg = sha256(Buffer.from(DOMAIN.CLAIM, 'utf8'), Buffer.from(env.listTxid, 'hex'), frToBytes(env.npk), frToBytes(env.rho));
    if (!schnorrVerify(Buffer.from(l.lockKey, 'hex'), msg, env.sig)) throw new Reject('bad CLAIM signature');
    this._roomFor(1);
    const pos = this.tree.append(noteLeaf(l.tokenNum, l.amount, env.npk, env.rho));
    this._set(this.listings, l.listTxid, { ...l, state: 'CLAIMED' });
    return { type: 'CLAIM', listTxid: l.listTxid, pos };
  }

  // ---- read side ----------------------------------------------------------

  token(ticker) {
    const num = this.tickers.get(ticker);
    return num === undefined ? null : this.tokens.get(num);
  }

  /** Message a seller signs with the lock key to CLAIM a CLOSED listing. */
  static claimMessage(listTxid, npk, rho) {
    return sha256(Buffer.from(DOMAIN.CLAIM, 'utf8'), Buffer.from(listTxid, 'hex'), frToBytes(npk), frToBytes(rho));
  }
}
