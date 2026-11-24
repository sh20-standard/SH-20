// A block as Bitcoin serializes it (Esplora's GET /block/:hash/raw) → { hash, prev, txs }, the transactions in the
// indexer's format: { txid, vin: [{ coinbase: true } | { txid, vout, witness: [Buffer] }], vout: [{ value: BigInt, script: Buffer }] }.
// One request per block instead of one per page of 25 transactions: a mainnet block holds thousands.
//
// What the bytes say about themselves is checked, as indexer-rs does (src/raw.rs): a coinbase first and nowhere else,
// the txids against the header's merkle root, the witnesses against the coinbase's commitment (BIP141). The caller
// compares `hash` and `prev` with the block it asked for. So a block read this way is that block, or it is refused;
// a page of JSON says nothing of the kind.

import { createHash } from 'node:crypto';

const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const reversedHex = (b) => Buffer.from(b).reverse().toString('hex');

// The output of a coinbase that commits to the witnesses starts with OP_RETURN, a push of 36 bytes, the tag aa21a9ed.
const COMMITMENT_HEAD = Buffer.from('6a24aa21a9ed', 'hex');

/** Bitcoin's merkle tree over hashes in their internal byte order: pairs level by level, the last with itself where a level is odd. */
function merkleRoot(leaves) {
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]])));
    level = next;
  }
  return level[0];
}

export function parseRawBlock(raw) {
  const b = Buffer.from(raw);
  if (b.length < 80) throw new Error(`raw block: ${b.length} bytes are not a block header`);
  const header = b.subarray(0, 80);
  let p = 80;
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
  if (count === 0) throw new Error('raw block: no transaction');
  const txs = [];
  const txids = []; // internal byte order, as the merkle tree takes them
  const wtxids = [];
  let anyWitness = false;
  let reserved = null; // the coinbase's witness
  for (let i = 0; i < count; i++) {
    const start = p;
    bytes(4); // version
    // BIP144: a marker 0x00 where the input count would be (never zero in a block), then the flag 0x01
    const segwit = b[p] === 0x00;
    if (segwit) {
      const flag = bytes(2)[1];
      if (flag !== 0x01) throw new Error(`raw block: the transaction at byte ${start} has the witness marker and the flag ${flag}`);
    }
    const afterFlag = p;
    const vin = [];
    const inputs = varint();
    if (inputs === 0) throw new Error(`raw block: the transaction at byte ${start} has no input`);
    for (let k = 0; k < inputs; k++) {
      const prev = bytes(32);
      const vout = bytes(4).readUInt32LE(0);
      bytes(varint()); // scriptSig
      bytes(4); // sequence
      vin.push(vout === 0xffffffff && prev.every((x) => x === 0) ? { coinbase: true } : { txid: reversedHex(prev), vout });
    }
    const vout = [];
    for (let n = varint(), k = 0; k < n; k++) {
      const value = bytes(8).readBigUInt64LE(0);
      vout.push({ value, script: Buffer.from(bytes(varint())) });
    }
    const outputsEnd = p;
    const witnesses = vin.map(() => {
      const witness = [];
      if (segwit) for (let n = varint(), k = 0; k < n; k++) witness.push(Buffer.from(bytes(varint())));
      return witness;
    });
    // a node refuses the witness form around no witness at all: the plain form says the same
    if (segwit && witnesses.every((w) => w.length === 0)) throw new Error(`raw block: the transaction at byte ${start} is in the witness form and has no witness`);
    vin.forEach((input, k) => {
      if (!input.coinbase) input.witness = witnesses[k];
    });
    if (i === 0) reserved = witnesses[0];
    const locktime = bytes(4);
    // the txid hashes the transaction without its marker, flag and witnesses; the wtxid hashes all of it
    const txid = sha256d(segwit ? Buffer.concat([b.subarray(start, start + 4), b.subarray(afterFlag, outputsEnd), locktime]) : b.subarray(start, p));
    txids.push(txid);
    wtxids.push(segwit ? sha256d(b.subarray(start, p)) : txid);
    anyWitness ||= segwit;
    txs.push({ txid: reversedHex(txid), vin, vout });
  }
  if (p !== b.length) throw new Error(`raw block: ${b.length - p} bytes after the last transaction`);

  const first = txs[0].vin;
  if (!(first.length === 1 && first[0].coinbase) || txs.slice(1).some((t) => t.vin.some((input) => input.coinbase))) {
    throw new Error('raw block: the coinbase is not the first transaction and that one alone');
  }
  if (!merkleRoot(txids).equals(header.subarray(36, 68))) {
    throw new Error('raw block: the transactions are not the ones the header commits to (merkle root)');
  }
  // BIP141: where a transaction has a witness, the coinbase's last output that starts with COMMITMENT_HEAD holds
  // sha256d(witness root ‖ reserved value): the reserved value is the one witness item, of 32 bytes, of the coinbase's
  // input, and the witness root the merkle root of the wtxids with zeros for the coinbase's.
  const commitment = txs[0].vout.findLast((o) => o.script.length >= 38 && o.script.subarray(0, 6).equals(COMMITMENT_HEAD));
  if (!commitment) {
    if (anyWitness) throw new Error('raw block: a transaction has a witness and the coinbase commits to none');
  } else {
    if (reserved.length !== 1 || reserved[0].length !== 32) throw new Error('raw block: the coinbase commits to the witnesses without the reserved value in its own');
    const root = merkleRoot([Buffer.alloc(32), ...wtxids.slice(1)]);
    if (!sha256d(Buffer.concat([root, reserved[0]])).equals(commitment.script.subarray(6, 38))) {
      throw new Error('raw block: the witnesses are not the ones the coinbase commits to');
    }
  }
  return { hash: reversedHex(sha256d(header)), prev: reversedHex(header.subarray(4, 36)), txs };
}
