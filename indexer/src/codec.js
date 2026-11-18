// SH-20 envelope codec (draft v0.2). Strict: any deviation from the canonical
// layout throws, and parse(serialize(x)) must give back the same bytes.
//
// Integers are little-endian. Field elements are 32-byte little-endian
// integers below the BN254 scalar field. Layouts are in docs/SPEC-WIRE.md.

import {
  FR, MAGIC, VERSION, TYPE, TYPE_NAME, N_IN, N_OUT, PROOF_BYTES, PAYSCRIPT_MAX, PAY_MODE,
} from './constants.js';

export class CodecError extends Error {}

const TICKER_RE = /^[A-Z0-9]{4}$/;

function readTicker(r) {
  const ticker = r.bytes(4).toString('latin1');
  if (!TICKER_RE.test(ticker)) throw new CodecError('bad ticker');
  return ticker;
}

function writeTicker(w, ticker) {
  if (typeof ticker !== 'string' || !TICKER_RE.test(ticker)) throw new CodecError('bad ticker');
  w.bytes(Buffer.from(ticker, 'latin1'));
}

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  need(k) {
    if (this.pos + k > this.buf.length) throw new CodecError('truncated');
  }
  bytes(k) {
    this.need(k);
    const out = this.buf.subarray(this.pos, this.pos + k);
    this.pos += k;
    return Buffer.from(out);
  }
  u8() {
    this.need(1);
    return this.buf[this.pos++];
  }
  u16() {
    this.need(2);
    const v = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return v;
  }
  u32() {
    this.need(4);
    const v = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  u64() {
    this.need(8);
    const v = this.buf.readBigUInt64LE(this.pos);
    this.pos += 8;
    return v;
  }
  fr() {
    const b = this.bytes(32);
    const v = BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
    if (v >= FR) throw new CodecError('non-canonical field element');
    return v;
  }
  remaining() {
    return this.buf.length - this.pos;
  }
}

class Writer {
  constructor() {
    this.parts = [];
  }
  bytes(b) {
    this.parts.push(Buffer.from(b));
  }
  u8(v) {
    this.parts.push(Buffer.from([v]));
  }
  u16(v) {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v);
    this.parts.push(b);
  }
  u32(v) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    this.parts.push(b);
  }
  u64(v) {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(v));
    this.parts.push(b);
  }
  fr(v) {
    if (v < 0n || v >= FR) throw new CodecError('field element out of range');
    this.parts.push(Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse());
  }
  out() {
    return Buffer.concat(this.parts);
  }
}

// A public opening is the note key alone (v0.3): public notes use rho = 0, since a fresh npk
// already makes each of them unique and nothing about them is hidden.
function readOpening(r) {
  return { npk: r.fr() };
}
function writeOpening(w, o) {
  w.fr(o.npk);
}

function readPayScript(r, payMode) {
  const len = r.u8();
  if (len > PAYSCRIPT_MAX) throw new CodecError('payScript too long');
  const script = r.bytes(len);
  if (payMode !== undefined) {
    if (payMode === PAY_MODE.PAY && len === 0) throw new CodecError('payMode 2 needs a payScript');
    if (payMode !== PAY_MODE.PAY && len !== 0) throw new CodecError('payScript only allowed with payMode 2');
  } else if (len === 0) {
    throw new CodecError('empty payScript');
  }
  return script;
}

// Spend section. Returns the spend and the reader position where the proof starts (v0.3:
// pk_eph is a 32-byte X25519 key, and the proof has a fixed size, with no length field).
function readSpend(r) {
  const anchorHeight = r.u32();
  const nf = [];
  for (let i = 0; i < N_IN; i++) nf.push(r.fr());
  const outs = [];
  for (let j = 0; j < N_OUT; j++) {
    const leaf = r.fr();
    const pkEph = r.bytes(32);
    const ct = r.bytes(28);
    outs.push({ leaf, pkEph, ct });
  }
  const bodyEnd = r.pos;
  const proof = r.bytes(PROOF_BYTES);
  return { spend: { anchorHeight, nf, outs, proof }, bodyEnd };
}

function writeSpend(w, s) {
  w.u32(s.anchorHeight);
  if (s.nf.length !== N_IN || s.outs.length !== N_OUT) throw new CodecError('bad arity');
  for (const x of s.nf) w.fr(x);
  for (const o of s.outs) {
    w.fr(o.leaf);
    if (o.pkEph.length !== 32) throw new CodecError('pk_eph must be 32 bytes');
    w.bytes(o.pkEph);
    if (o.ct.length !== 28) throw new CodecError('ct must be 28 bytes');
    w.bytes(o.ct);
  }
  if (s.proof.length !== PROOF_BYTES) throw new CodecError(`proof must be ${PROOF_BYTES} bytes`);
  w.bytes(s.proof);
}

/**
 * Parse an envelope. Returns { env, body } where `body` is the bytes covered
 * by the proof's body hash (everything before the proof), or null when the
 * type carries no proof.
 */
export function parseEnvelope(buf) {
  const r = new Reader(buf);
  if (!r.bytes(4).equals(MAGIC)) throw new CodecError('bad magic');
  const version = r.u8();
  if (version !== VERSION) throw new CodecError('unknown version');
  const type = r.u8();
  const name = TYPE_NAME[type];
  if (!name) throw new CodecError('unknown type');
  let env;
  let bodyEnd = null;

  switch (type) {
    case TYPE.DEPLOY: {
      const ticker = readTicker(r);
      const max = r.u64();
      const lim = r.u64();
      const pre = r.u64();
      const start = r.u32();
      const end = r.u32();
      const unlock = r.u32();
      const price = r.u64();
      const payMode = r.u8();
      if (payMode > PAY_MODE.PAY) throw new CodecError('bad payMode');
      const payScript = readPayScript(r, payMode);
      const team = pre > 0n ? readOpening(r) : null;
      let spend = null;
      if (r.remaining() > 0) {
        const res = readSpend(r);
        spend = res.spend;
        bodyEnd = res.bodyEnd;
      }
      env = { type: name, ticker, max, lim, pre, start, end, unlock, price, payMode, payScript, team, spend };
      break;
    }
    case TYPE.MINT:
      env = { type: name, ticker: readTicker(r), ...readOpening(r) };
      break;
    case TYPE.TRANSFER: {
      const res = readSpend(r);
      env = { type: name, spend: res.spend };
      bodyEnd = res.bodyEnd;
      break;
    }
    case TYPE.BURN: {
      const ticker = readTicker(r);
      const vPub = r.u64();
      const res = readSpend(r);
      env = { type: name, ticker, vPub, spend: res.spend };
      bodyEnd = res.bodyEnd;
      break;
    }
    case TYPE.LIST: {
      const ticker = readTicker(r);
      const amount = r.u64();
      const price = r.u64();
      const lockVout = r.u8();
      const payScript = readPayScript(r);
      const res = readSpend(r);
      env = { type: name, ticker, amount, price, lockVout, payScript, spend: res.spend };
      bodyEnd = res.bodyEnd;
      break;
    }
    case TYPE.TAKE:
      env = { type: name, ...readOpening(r) };
      break;
    case TYPE.CLAIM:
      env = { type: name, listTxid: r.bytes(32).toString('hex'), ...readOpening(r), sig: r.bytes(64) };
      break;
  }
  if (r.remaining() !== 0) throw new CodecError('trailing bytes');
  const again = serializeEnvelope(env);
  if (!again.equals(buf)) throw new CodecError('non-canonical encoding');
  return { env, body: bodyEnd === null ? null : Buffer.from(buf.subarray(0, bodyEnd)) };
}

export function serializeEnvelope(env) {
  const w = new Writer();
  w.bytes(MAGIC);
  w.u8(VERSION);
  const type = TYPE[env.type];
  if (type === undefined) throw new CodecError('unknown type');
  w.u8(type);
  switch (type) {
    case TYPE.DEPLOY:
      writeTicker(w, env.ticker);
      w.u64(env.max);
      w.u64(env.lim);
      w.u64(env.pre);
      w.u32(env.start);
      w.u32(env.end);
      w.u32(env.unlock);
      w.u64(env.price);
      w.u8(env.payMode);
      w.u8(env.payScript.length);
      w.bytes(env.payScript);
      if (BigInt(env.pre) > 0n) writeOpening(w, env.team);
      if (env.spend) writeSpend(w, env.spend);
      break;
    case TYPE.MINT:
      writeTicker(w, env.ticker);
      writeOpening(w, env);
      break;
    case TYPE.TRANSFER:
      writeSpend(w, env.spend);
      break;
    case TYPE.BURN:
      writeTicker(w, env.ticker);
      w.u64(env.vPub);
      writeSpend(w, env.spend);
      break;
    case TYPE.LIST:
      writeTicker(w, env.ticker);
      w.u64(env.amount);
      w.u64(env.price);
      w.u8(env.lockVout);
      w.u8(env.payScript.length);
      w.bytes(env.payScript);
      writeSpend(w, env.spend);
      break;
    case TYPE.TAKE:
      writeOpening(w, env);
      break;
    case TYPE.CLAIM: {
      const txid = Buffer.from(env.listTxid, 'hex');
      if (txid.length !== 32) throw new CodecError('listTxid must be 32 bytes');
      w.bytes(txid);
      writeOpening(w, env);
      if (env.sig.length !== 64) throw new CodecError('sig must be 64 bytes');
      w.bytes(env.sig);
      break;
    }
  }
  return w.out();
}
