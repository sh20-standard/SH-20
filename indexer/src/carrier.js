// Finds the SH-20 envelope in a transaction (SPEC-WIRE §3).
//
// Two carriers:
//  - OP_RETURN: an output that is exactly `OP_RETURN <one minimal push>`, whose data starts with "SH20".
//    Cheapest for small envelopes (MINT, TAKE, CLAIM, a DEPLOY without a spend): one transaction.
//  - Witness: in the tapscript of input 0, `OP_0 OP_IF <push "SH20"> <minimal pushes of ≤ 520 bytes> OP_ENDIF`.
//    For envelopes with a proof, paid at the witness rate.
// Anything that does not match a carrier exactly carries no envelope. An envelope whose version byte is not 0x00
// belongs to another version: it is not counted. Two or more counted envelopes, all TRANSFERs in the witness, are a
// batch, each applied alone; any other transaction with two or more counted envelopes is refused.

import { MAGIC, MAX_PUSH, TYPE, VERSION } from './constants.js';

const OP_0 = 0x00;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_1NEGATE = 0x4f;
const OP_1 = 0x51;
const OP_16 = 0x60;
const OP_IF = 0x63;
const OP_ENDIF = 0x68;
const OP_RETURN = 0x6a;

/** Splits a script into opcodes; a push keeps its data. Throws when a push runs past the end. */
export function parseScript(script) {
  const ops = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    let len = -1;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === OP_PUSHDATA1) {
      if (i + 1 > script.length) throw new Error('bad push');
      len = script[i];
      i += 1;
    } else if (op === OP_PUSHDATA2) {
      if (i + 2 > script.length) throw new Error('bad push');
      len = script.readUInt16LE(i);
      i += 2;
    } else if (op === OP_PUSHDATA4) {
      if (i + 4 > script.length) throw new Error('bad push');
      len = script.readUInt32LE(i);
      i += 4;
    }
    if (len >= 0) {
      if (i + len > script.length) throw new Error('bad push');
      ops.push({ op, data: script.subarray(i, i + len) });
      i += len;
    } else {
      ops.push({ op });
    }
  }
  return ops;
}

/**
 * The data an opcode pushes when it is a minimal push in Bitcoin's sense (CheckMinimalPush), else null.
 * OP_0 pushes nothing, OP_1..OP_16 push the byte 1..16, OP_1NEGATE pushes 0x81; any other data uses the
 * shortest length prefix.
 */
export function minimalPushData({ op, data }) {
  if (op === OP_0) return Buffer.alloc(0);
  if (op >= OP_1 && op <= OP_16) return Buffer.from([op - 0x50]);
  if (op === OP_1NEGATE) return Buffer.from([0x81]);
  if (!data) return null;
  const n = data.length;
  if (n === 0) return null; // must be OP_0
  if (n === 1 && ((data[0] >= 1 && data[0] <= 16) || data[0] === 0x81)) return null; // must be OP_1..OP_16 or OP_1NEGATE
  if (n <= 75) return op === n ? data : null;
  if (n <= 255) return op === OP_PUSHDATA1 ? data : null;
  if (n <= 65535) return op === OP_PUSHDATA2 ? data : null;
  return op === OP_PUSHDATA4 ? data : null;
}

const startsWithMagic = (d) => d.length >= MAGIC.length && d.subarray(0, MAGIC.length).equals(MAGIC);

function fromOpReturn(tx) {
  const found = [];
  tx.vout.forEach((out, index) => {
    if (out.script.length === 0 || out.script[0] !== OP_RETURN) return;
    let ops;
    try {
      ops = parseScript(out.script.subarray(1));
    } catch {
      return; // does not split into opcodes: no envelope
    }
    if (ops.length !== 1) return;
    const data = minimalPushData(ops[0]);
    if (data && startsWithMagic(data)) found.push({ bytes: Buffer.from(data), index });
  });
  return found;
}

/** The tapscript of a script-path spend, recognised from the witness alone; null otherwise. */
export function tapscriptOf(witness) {
  if (!witness || witness.length < 2) return null;
  let items = witness;
  const last = items[items.length - 1];
  if (last.length > 0 && last[0] === 0x50) items = items.slice(0, -1); // annex
  if (items.length < 2) return null;
  const control = items[items.length - 1];
  const m = (control.length - 33) / 32;
  if (control.length < 33 || !Number.isInteger(m) || m > 128 || (control[0] & 0xfe) !== 0xc0) return null;
  return items[items.length - 2];
}

function fromWitness(tx) {
  const vin0 = tx.vin[0];
  if (!vin0 || vin0.coinbase) return [];
  const script = tapscriptOf(vin0.witness);
  if (!script) return [];
  let ops;
  try {
    ops = parseScript(script);
  } catch {
    return []; // does not split into opcodes: no envelope
  }
  const found = [];
  let i = 0;
  while (i + 2 < ops.length) {
    const tag = ops[i + 2];
    const opens = ops[i].op === OP_0 && ops[i + 1].op === OP_IF && tag.op === MAGIC.length && tag.data.equals(MAGIC);
    if (!opens) {
      i += 1;
      continue;
    }
    const chunks = [MAGIC];
    let j = i + 3;
    let closed = false;
    for (; j < ops.length; j++) {
      if (ops[j].op === OP_ENDIF) {
        closed = true;
        break;
      }
      const data = minimalPushData(ops[j]);
      if (!data || data.length > MAX_PUSH) break;
      chunks.push(data);
    }
    if (closed) {
      found.push({ bytes: Buffer.concat(chunks) });
      i = j + 1; // after OP_ENDIF
    } else {
      i += 1; // no envelope at this OP_0: look again from the next opcode
    }
  }
  return found;
}

// An envelope of another version is not counted (SPEC-WIRE §3); one too short to have a version byte is v0.
const counted = (x) => x.bytes.length <= MAGIC.length || x.bytes[MAGIC.length] === VERSION;

const isTransfer = (x) => x.bytes.length > MAGIC.length + 1 && x.bytes[MAGIC.length + 1] === TYPE.TRANSFER;

/**
 * @returns {{none: true} | {error: string} | {bytes: Buffer, carrier: 'opreturn'|'witness'} |
 *   {batch: {bytes: Buffer, carrier: 'witness'}[]}}
 */
export function extractEnvelope(tx) {
  const all = [
    ...fromOpReturn(tx).map((x) => ({ ...x, carrier: 'opreturn' })),
    ...fromWitness(tx).map((x) => ({ ...x, carrier: 'witness' })),
  ].filter(counted);
  if (all.length === 0) return { none: true };
  if (all.length === 1) return all[0];
  // A batch (SPEC-WIRE §3): TRANSFERs in the witness only, so a relayer can publish several people's transfers at once.
  if (all.every((x) => x.carrier === 'witness' && isTransfer(x))) return { batch: all };
  return { error: 'more than one SH-20 envelope in the transaction' };
}
