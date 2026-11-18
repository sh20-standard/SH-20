// Just enough Bitcoin for the vault: addresses → scripts, transactions, PSBT v0
// (build, parse, finalize, extract) and size estimates. The wallet extension
// signs; the vault never holds a Bitcoin private key.

import { sha256d, hash160 } from './hash.js';
import { concat, toHex, fromHex, equal, u32le, u64le } from './bytes.js';

export const NETWORKS = Object.freeze({
  signet: { name: 'signet', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 },
});

// ---- addresses --------------------------------------------------------------

const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32 = 1;
const BECH32M = 0x2bc830a3;

function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i];
  }
  return chk >>> 0;
}

const hrpExpand = (hrp) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return out;
}

function decodeSegwit(addr, hrp) {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return null;
  const a = addr.toLowerCase();
  const sep = a.lastIndexOf('1');
  if (sep < 1 || sep + 7 > a.length || a.length > 90 || a.slice(0, sep) !== hrp) return null;
  const data = [...a.slice(sep + 1)].map((c) => BECH.indexOf(c));
  if (data.includes(-1)) return null;
  const c = polymod([...hrpExpand(hrp), ...data]);
  const version = data[0];
  if (version > 16) return null;
  if (c !== (version === 0 ? BECH32 : BECH32M)) return null;
  const program = convertBits(data.slice(1, -6), 5, 8, false);
  if (!program || program.length < 2 || program.length > 40) return null;
  if (version === 0 && program.length !== 20 && program.length !== 32) return null;
  return { version, program: new Uint8Array(program) };
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeBase58Check(s) {
  let x = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) return null;
    x = x * 58n + BigInt(i);
  }
  let hex = x.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)[0].length;
  const bytes = concat(new Uint8Array(lead), x === 0n ? new Uint8Array(0) : fromHex(hex));
  if (bytes.length < 5) return null;
  const body = bytes.subarray(0, -4);
  if (!equal(sha256d(body).subarray(0, 4), bytes.subarray(-4))) return null;
  return body;
}

/** Address → scriptPubKey for `net`; throws on anything else (including other networks). */
export function addressToScript(addr, net = NETWORKS.signet) {
  const sw = decodeSegwit(addr, net.hrp);
  if (sw) {
    const op = sw.version === 0 ? 0x00 : 0x50 + sw.version;
    return concat(new Uint8Array([op, sw.program.length]), sw.program);
  }
  const b = decodeBase58Check(addr);
  if (b && b.length === 21 && b[0] === net.p2sh) return concat(new Uint8Array([0xa9, 0x14]), b.subarray(1), new Uint8Array([0x87]));
  if (b && b.length === 21 && b[0] === net.p2pkh) {
    return concat(new Uint8Array([0x76, 0xa9, 0x14]), b.subarray(1), new Uint8Array([0x88, 0xac]));
  }
  throw new Error(`not a ${net.name} address: ${addr}`);
}

export function scriptType(s) {
  if (s.length === 22 && s[0] === 0x00 && s[1] === 0x14) return 'p2wpkh';
  if (s.length === 34 && s[0] === 0x00 && s[1] === 0x20) return 'p2wsh';
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20) return 'p2tr';
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) return 'p2sh';
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9) return 'p2pkh';
  if (s.length > 0 && s[0] === 0x6a) return 'opreturn';
  return 'unknown';
}

/** Bitcoin Core's dust limit at the default 3 sat/vB dust relay fee. */
export function dustLimit(script) {
  switch (scriptType(script)) {
    case 'opreturn':
      return 0n;
    case 'p2wpkh':
      return 294n;
    case 'p2tr':
    case 'p2wsh':
      return 330n;
    case 'p2sh':
      return 540n;
    default:
      return 546n;
  }
}

// ---- scripts ---------------------------------------------------------------

export function pushData(data) {
  const n = data.length;
  if (n <= 75) return concat(new Uint8Array([n]), data);
  if (n <= 255) return concat(new Uint8Array([0x4c, n]), data);
  if (n <= 520) return concat(new Uint8Array([0x4d, n & 0xff, n >> 8]), data);
  throw new Error('push too large');
}

/** `OP_RETURN <one minimal push>`: the SH-20 OP_RETURN carrier. */
export const opReturnScript = (data) => concat(new Uint8Array([0x6a]), pushData(data));

/** P2SH-P2WPKH redeem script for a compressed public key. */
export const p2shP2wpkhRedeem = (pubkey33) => concat(new Uint8Array([0x00, 0x14]), hash160(pubkey33));

// ---- transactions ------------------------------------------------------------

export function compactSize(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8]);
  return concat(new Uint8Array([0xfe]), u32le(n));
}

class Reader {
  constructor(b) {
    this.b = b;
    this.p = 0;
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  bytes(n) {
    if (this.p + n > this.b.length) throw new Error('truncated');
    const out = this.b.slice(this.p, this.p + n);
    this.p += n;
    return out;
  }
  u8() {
    return this.bytes(1)[0];
  }
  u32() {
    this.bytes(4);
    return this.dv.getUint32(this.p - 4, true);
  }
  u64() {
    this.bytes(8);
    return this.dv.getBigUint64(this.p - 8, true);
  }
  cs() {
    const f = this.u8();
    if (f < 0xfd) return f;
    if (f === 0xfd) {
      this.bytes(2);
      return this.dv.getUint16(this.p - 2, true);
    }
    if (f === 0xfe) return this.u32();
    throw new Error('compact size too large');
  }
  varBytes() {
    return this.bytes(this.cs());
  }
  get done() {
    return this.p === this.b.length;
  }
}

const txidBytes = (hex) => fromHex(hex).reverse();
const witnessBytes = (items) => concat(compactSize(items.length), ...items.map((w) => concat(compactSize(w.length), w)));

/**
 * tx = { version, locktime, vin: [{ txid (display hex), vout, sequence, scriptSig?, witness? }],
 *        vout: [{ value: bigint, script }] }
 */
export function serializeTx(tx, withWitness = true) {
  const segwit = withWitness && tx.vin.some((i) => i.witness && i.witness.length);
  const parts = [u32le(tx.version)];
  if (segwit) parts.push(new Uint8Array([0x00, 0x01]));
  parts.push(compactSize(tx.vin.length));
  for (const i of tx.vin) {
    const ss = i.scriptSig || new Uint8Array(0);
    parts.push(txidBytes(i.txid), u32le(i.vout), compactSize(ss.length), ss, u32le(i.sequence));
  }
  parts.push(compactSize(tx.vout.length));
  for (const o of tx.vout) parts.push(u64le(o.value), compactSize(o.script.length), o.script);
  if (segwit) for (const i of tx.vin) parts.push(witnessBytes(i.witness || []));
  parts.push(u32le(tx.locktime));
  return concat(...parts);
}

export function parseTx(bytes) {
  const r = new Reader(bytes);
  const version = r.u32();
  let segwit = false;
  if (bytes[r.p] === 0x00 && bytes[r.p + 1] === 0x01) {
    segwit = true;
    r.bytes(2);
  }
  const vin = [];
  for (let n = r.cs(), k = 0; k < n; k++) {
    vin.push({ txid: toHex(r.bytes(32).reverse()), vout: r.u32(), scriptSig: r.varBytes(), sequence: r.u32(), witness: [] });
  }
  const vout = [];
  for (let n = r.cs(), k = 0; k < n; k++) vout.push({ value: r.u64(), script: r.varBytes() });
  if (segwit) for (const i of vin) for (let n = r.cs(), k = 0; k < n; k++) i.witness.push(r.varBytes());
  const locktime = r.u32();
  if (!r.done) throw new Error('trailing bytes in transaction');
  return { version, locktime, vin, vout };
}

export const txid = (tx) => toHex(sha256d(serializeTx(tx, false)).reverse());

export function weight(tx) {
  return serializeTx(tx, false).length * 3 + serializeTx(tx, true).length;
}

export const vsize = (tx) => Math.ceil(weight(tx) / 4);

// ---- size estimates ----------------------------------------------------------

// Input weight with the largest signature each type can carry (72-byte DER +
// sighash for ECDSA, 64 + 1 for Schnorr), so a fee computed from it is never short.
const INPUT_WEIGHT = {
  p2wpkh: 41 * 4 + (1 + 1 + 72 + 1 + 33),
  p2tr: 41 * 4 + (1 + 1 + 65),
  p2sh: (41 + 23) * 4 + (1 + 1 + 72 + 1 + 33), // P2SH-P2WPKH
};

export const SUPPORTED_INPUTS = Object.keys(INPUT_WEIGHT);

const outputWeight = (script) => (8 + compactSize(script.length).length + script.length) * 4;

export function estimateVsize(inputTypes, outputScripts) {
  let w = (4 + 4 + compactSize(inputTypes.length).length + compactSize(outputScripts.length).length) * 4 + 2;
  for (const t of inputTypes) {
    if (!INPUT_WEIGHT[t]) throw new Error(`unsupported input type ${t}`);
    w += INPUT_WEIGHT[t];
  }
  for (const s of outputScripts) w += outputWeight(s);
  return Math.ceil(w / 4);
}

// ---- PSBT (BIP174, version 0) -----------------------------------------------

const MAGIC = fromHex('70736274ff');
const stripped = (t) => ({ ...t, vin: t.vin.map((i) => ({ ...i, scriptSig: new Uint8Array(0), witness: [] })) });
const kv = (key, value) => concat(compactSize(key.length), key, compactSize(value.length), value);

/**
 * meta[i] = { witnessUtxo: { value, script }, redeemScript?, tapInternalKey? }
 */
export function createPsbt(tx, meta) {
  const parts = [MAGIC, kv(new Uint8Array([0x00]), serializeTx(stripped(tx), false)), new Uint8Array([0])];
  meta.forEach((m) => {
    const wu = concat(u64le(m.witnessUtxo.value), compactSize(m.witnessUtxo.script.length), m.witnessUtxo.script);
    parts.push(kv(new Uint8Array([0x01]), wu));
    if (m.redeemScript) parts.push(kv(new Uint8Array([0x04]), m.redeemScript));
    if (m.tapInternalKey) parts.push(kv(new Uint8Array([0x17]), m.tapInternalKey));
    parts.push(new Uint8Array([0]));
  });
  tx.vout.forEach(() => parts.push(new Uint8Array([0])));
  return concat(...parts);
}

function readMap(r) {
  const out = [];
  for (;;) {
    const key = r.varBytes();
    if (key.length === 0) return out;
    out.push({ key, value: r.varBytes() });
  }
}

export function parsePsbt(bytes) {
  const r = new Reader(bytes);
  if (!equal(r.bytes(5), MAGIC)) throw new Error('not a PSBT');
  const global = readMap(r);
  const g = global.find((e) => e.key.length === 1 && e.key[0] === 0x00);
  if (!g) throw new Error('PSBT without unsigned transaction');
  const tx = parseTx(g.value);
  const inputs = tx.vin.map(() => readMap(r));
  const outputs = tx.vout.map(() => readMap(r));
  return { tx, global, inputs, outputs };
}

function parseWitness(b) {
  const r = new Reader(b);
  const items = [];
  for (let n = r.cs(), k = 0; k < n; k++) items.push(r.varBytes());
  return items;
}

/**
 * Finalizes every input (if the wallet did not) and returns the network
 * transaction. Supports what the vault builds: P2WPKH, P2SH-P2WPKH, P2TR key path.
 */
export function finalizePsbt(bytes) {
  const { tx, inputs } = parsePsbt(bytes);
  tx.vin.forEach((input, i) => {
    const m = inputs[i];
    const one = (type) => m.filter((e) => e.key[0] === type);
    const finalWit = one(0x08)[0];
    const finalSig = one(0x07)[0];
    if (finalWit || finalSig) {
      input.witness = finalWit ? parseWitness(finalWit.value) : [];
      input.scriptSig = finalSig ? finalSig.value : new Uint8Array(0);
      return;
    }
    const tapSig = one(0x13)[0];
    if (tapSig) {
      input.witness = [tapSig.value];
      return;
    }
    const partial = one(0x02);
    if (partial.length === 1) {
      input.witness = [partial[0].value, partial[0].key.subarray(1)];
      const redeem = one(0x04)[0];
      input.scriptSig = redeem ? pushData(redeem.value) : new Uint8Array(0);
      return;
    }
    throw new Error(`input ${i} is not signed`);
  });
  const raw = serializeTx(tx, true);
  return { tx, hex: toHex(raw), txid: txid(tx), vsize: vsize(tx) };
}

/** True when two transactions are identical apart from signatures. */
export const sameUnsignedTx = (a, b) => equal(serializeTx(stripped(a), false), serializeTx(stripped(b), false));
