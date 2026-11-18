// Finds the SH-20 envelope in a transaction.
//
// Two carriers are allowed:
//  - OP_RETURN: an output `OP_RETURN <one minimal push>` whose data starts with "SH20".
//    Cheapest for small envelopes (MINT, TAKE, CLAIM, genesis DEPLOY): one transaction.
//  - Witness: a tapscript on input 0 holding `OP_0 OP_IF "SH20" <pushes...> OP_ENDIF`.
//    Needed for envelopes with a proof (about 2.4 KB), paid at the witness rate.
// A transaction carries at most one envelope; two of any kind reject it.

import { MAGIC, MAX_PUSH } from './constants.js';

const OP_0 = 0x00;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_IF = 0x63;
const OP_ENDIF = 0x68;
const OP_RETURN = 0x6a;

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

function isMinimalPush({ op, data }) {
  const n = data.length;
  if (n <= 75) return op === n;
  if (n <= 255) return op === OP_PUSHDATA1;
  if (n <= 65535) return op === OP_PUSHDATA2;
  return false;
}

const startsWithMagic = (d) => d && d.length >= MAGIC.length && d.subarray(0, MAGIC.length).equals(MAGIC);

function fromOpReturn(tx) {
  const found = [];
  tx.vout.forEach((out, index) => {
    if (out.script.length === 0 || out.script[0] !== OP_RETURN) return;
    let ops;
    try {
      ops = parseScript(out.script.subarray(1));
    } catch {
      return; // malformed OP_RETURN that cannot hold an envelope
    }
    const tagged = ops.some((o) => startsWithMagic(o.data));
    if (!tagged) return;
    if (ops.length !== 1 || !isMinimalPush(ops[0])) {
      found.push({ error: 'OP_RETURN envelope must be one minimal push', index });
    } else {
      found.push({ bytes: Buffer.from(ops[0].data), index });
    }
  });
  return found;
}

function tapscriptOf(witness) {
  if (!witness || witness.length < 2) return null;
  let items = witness;
  const last = items[items.length - 1];
  if (items.length >= 3 && last.length > 0 && last[0] === 0x50) items = items.slice(0, -1); // annex
  if (items.length < 2) return null;
  const control = items[items.length - 1];
  if (control.length < 33 || (control.length - 33) % 32 !== 0 || (control[0] & 0xfe) !== 0xc0) return null;
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
    return [];
  }
  const found = [];
  for (let i = 0; i + 2 < ops.length; i++) {
    if (ops[i].op !== OP_0 || ops[i + 1].op !== OP_IF) continue;
    const tag = ops[i + 2].data;
    if (!tag || !tag.equals(MAGIC)) continue;
    const chunks = [MAGIC];
    let j = i + 3;
    let closed = false;
    let bad = false;
    for (; j < ops.length; j++) {
      if (ops[j].op === OP_ENDIF) {
        closed = true;
        break;
      }
      if (!ops[j].data || ops[j].data.length > MAX_PUSH || !isMinimalPush(ops[j])) {
        bad = true;
        break;
      }
      chunks.push(ops[j].data);
    }
    if (!closed || bad) found.push({ error: 'malformed witness envelope' });
    else found.push({ bytes: Buffer.concat(chunks) });
    i = j;
  }
  return found;
}

/**
 * @returns {{none: true} | {error: string} | {bytes: Buffer, carrier: 'opreturn'|'witness', index?: number}}
 */
export function extractEnvelope(tx) {
  const a = fromOpReturn(tx);
  const b = fromWitness(tx);
  const all = [...a.map((x) => ({ ...x, carrier: 'opreturn' })), ...b.map((x) => ({ ...x, carrier: 'witness' }))];
  if (all.length === 0) return { none: true };
  if (all.length > 1) return { error: 'more than one SH-20 envelope in the transaction' };
  if (all[0].error) return { error: all[0].error };
  return all[0];
}
