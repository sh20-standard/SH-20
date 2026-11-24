// A block as Bitcoin serializes it (Esplora's GET /block/:hash/raw) → the transactions in the indexer's format:
// { txid, vin: [{ coinbase: true } | { txid, vout, witness: [Buffer] }], vout: [{ value: BigInt, script: Buffer }] }.
// One request per block instead of one per page of 25 transactions: a mainnet block holds thousands.

import { createHash } from 'node:crypto';

const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();

export function parseRawBlock(raw) {
  const b = Buffer.from(raw);
  let p = 80; // the header
  const need = (n) => {
    if (p + n > b.length) throw new Error(`raw block: cut short at byte ${p}`);
  };
  const varint = () => {
    need(1);
    const x = b[p++];
    if (x < 0xfd) return x;
    const n = x === 0xfd ? 2 : x === 0xfe ? 4 : 8;
    need(n);
    const v = n === 8 ? Number(b.readBigUInt64LE(p)) : b.readUIntLE(p, n);
    p += n;
    return v;
  };
  const bytes = (n) => {
    need(n);
    const out = b.subarray(p, p + n);
    p += n;
    return out;
  };
  const count = varint();
  const txs = [];
  for (let i = 0; i < count; i++) {
    const start = p;
    bytes(4); // version
    const segwit = b[p] === 0x00 && b[p + 1] === 0x01;
    if (segwit) p += 2;
    const afterFlag = p;
    const vin = [];
    for (let n = varint(), k = 0; k < n; k++) {
      const prev = bytes(32);
      const vout = bytes(4).readUInt32LE(0);
      bytes(varint()); // scriptSig
      bytes(4); // sequence
      vin.push(vout === 0xffffffff && prev.every((x) => x === 0) ? { coinbase: true } : { txid: Buffer.from(prev).reverse().toString('hex'), vout });
    }
    const vout = [];
    for (let n = varint(), k = 0; k < n; k++) {
      const value = bytes(8).readBigUInt64LE(0);
      vout.push({ value, script: Buffer.from(bytes(varint())) });
    }
    const outputsEnd = p;
    for (const input of vin) {
      const witness = [];
      if (segwit) for (let n = varint(), k = 0; k < n; k++) witness.push(Buffer.from(bytes(varint())));
      if (!input.coinbase) input.witness = witness;
    }
    const locktime = bytes(4);
    // the txid hashes the transaction without its marker, flag and witnesses
    const stripped = segwit ? Buffer.concat([b.subarray(start, start + 4), b.subarray(afterFlag, outputsEnd), locktime]) : b.subarray(start, p);
    txs.push({ txid: Buffer.from(sha256d(stripped)).reverse().toString('hex'), vin, vout });
  }
  if (p !== b.length) throw new Error(`raw block: ${b.length - p} bytes after the last transaction`);
  return txs;
}
