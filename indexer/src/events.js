// Binary encoding of accepted events (SPEC-WIRE §6). The block digest hashes the
// concatenation of these records, so a second implementation in any language
// reaches the same digest without reproducing a JSON serializer.
//
// record = code(1) ‖ txid(32, display order; zeros for block events) ‖ payload
// Every payload has a fixed size for its code (DEPLOY: for its flag byte), so a
// concatenation of records parses one way only.

import { frToBytes } from './notes.js';

export const EVENT_CODE = Object.freeze({
  DEPLOY: 0x01, MINT: 0x02, TRANSFER: 0x03, BURN: 0x04, LIST: 0x05, TAKE: 0x06, CLAIM: 0x07,
  GENESIS: 0x80, TEAM_UNLOCK: 0x81, CLOSED: 0x82,
});
export const TAKE_OUTCOME = Object.freeze({ SOLD: 1, CANCELLED: 2 });

const BLOCK_EVENTS = new Set(['GENESIS', 'TEAM_UNLOCK']);
const ZERO_TXID = Buffer.alloc(32);

const u8 = (n) => Buffer.from([n]);
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const u64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return b;
};
const ticker = (s) => {
  const b = Buffer.from(s, 'ascii');
  if (b.length !== 4) throw new Error(`event ticker must be 4 bytes: ${s}`);
  return b;
};
const txid = (hex) => {
  const b = Buffer.from(hex, 'hex');
  if (b.length !== 32) throw new Error(`event txid must be 32 bytes: ${hex}`);
  return b;
};
// Nullifiers are kept as big-endian hex; on the wire and here they are 32 bytes little-endian.
const fr = (hex) => frToBytes(BigInt('0x' + hex));
const spent = ({ nullifiers, pos }) => {
  if (nullifiers.length !== 2 || pos.length !== 3) throw new Error('a spend has 2 nullifiers and 3 positions');
  return [...nullifiers.map(fr), ...pos.map(u32)];
};

const payload = (e) => {
  switch (e.type) {
    case 'GENESIS':
      return [ticker(e.ticker), u64(e.max), u64(e.lim), u64(e.deployBurn), u32(e.anchorWindow), u32(e.anchorMinDepth), u32(e.deployMaturity)];
    case 'TEAM_UNLOCK':
      return [ticker(e.ticker), u64(e.pre), u32(e.pos)];
    case 'DEPLOY':
      return e.nullifiers ? [ticker(e.ticker), u8(1), ...spent(e)] : [ticker(e.ticker), u8(0)];
    case 'MINT':
      return [ticker(e.ticker), u64(e.v), u32(e.pos)];
    case 'TRANSFER':
      return spent(e);
    case 'BURN':
      return [ticker(e.ticker), u64(e.vPub), ...spent(e)];
    case 'LIST':
      return [ticker(e.ticker), u64(e.amount), u64(e.price), ...spent(e)];
    case 'TAKE':
      return [txid(e.listTxid), u8(TAKE_OUTCOME[e.outcome]), u32(e.pos)];
    case 'CLOSED':
      return [txid(e.listTxid)];
    case 'CLAIM':
      return [txid(e.listTxid), u32(e.pos)];
    default:
      throw new Error(`unknown event type ${e.type}`);
  }
};

/** One event as its record bytes. */
export function encodeEvent(e) {
  const code = EVENT_CODE[e.type];
  if (code === undefined) throw new Error(`unknown event type ${e.type}`);
  const id = BLOCK_EVENTS.has(e.type) ? ZERO_TXID : txid(e.txid);
  return Buffer.concat([u8(code), id, ...payload(e)]);
}

/** events_H: the records of a block's accepted events, in order (empty for a block without events). */
export function encodeEvents(events) {
  return Buffer.concat(events.map(encodeEvent));
}
