// Esplora's raw block (GET /block/:hash/raw), read in one request when a block holds more than a page of transactions:
// the parser against Bitcoin's genesis block, and the follower's source giving the same block either way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseRawBlock } from '../src/adapters/rawblock.js';
import { EsploraSource } from '../src/follower.js';

const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();

// Bitcoin's block 0, as every node serves it
const GENESIS = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c'
  + '0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';

test("the genesis block: one coinbase, Bitcoin's own txid and hash", () => {
  const raw = Buffer.from(GENESIS, 'hex');
  const { hash, prev, txs: [tx, ...rest] } = parseRawBlock(raw);
  assert.equal(hash, '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  assert.equal(prev, '0'.repeat(64));
  assert.equal(rest.length, 0);
  assert.equal(tx.txid, '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b');
  assert.deepEqual(tx.vin, [{ coinbase: true }]);
  assert.equal(tx.vout[0].value, 5000000000n);
  assert.equal(tx.vout[0].script.length, 67);
  assert.throws(() => parseRawBlock(raw.subarray(0, raw.length - 1)), /cut short/);
  assert.throws(() => parseRawBlock(Buffer.concat([raw, Buffer.from([0])])), /after the last transaction/);
  assert.throws(() => parseRawBlock(raw.subarray(0, 79)), /not a block header/);
});

// A block of our own: a segwit coinbase, a legacy transaction, segwit ones with empty and long witness items, a
// script past 252 bytes (a 3-byte length) and an OP_RETURN; serialized here as Bitcoin does, with a header that
// commits to its transactions and a coinbase that commits to their witnesses (BIP141).
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.from([0xfd, n & 0xff, n >> 8]));
const withLen = (b) => Buffer.concat([varint(b.length), b]);
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
function serialize(t, witness) {
  const ins = Buffer.concat([varint(t.vin.length), ...t.vin.map((i) => Buffer.concat([
    i.coinbase ? Buffer.alloc(32) : Buffer.from(i.txid, 'hex').reverse(), u32(i.coinbase ? 0xffffffff : i.vout), withLen(i.scriptSig ?? Buffer.alloc(0)), u32(0xfffffffd),
  ]))]);
  const outs = Buffer.concat([varint(t.vout.length), ...t.vout.map((o) => Buffer.concat([u64(o.value), withLen(o.script)]))]);
  const wit = Buffer.concat(t.vin.map((i) => Buffer.concat([varint((i.witness ?? []).length), ...(i.witness ?? []).map(withLen)])));
  return witness ? Buffer.concat([u32(2), Buffer.from([0, 1]), ins, outs, wit, u32(0)]) : Buffer.concat([u32(2), ins, outs, u32(0)]);
}
const h = (s) => createHash('sha256').update(s).digest('hex');
const hex = (b) => Buffer.from(b).reverse().toString('hex');
const segwit = (t) => t.vin.some((i) => i.witness);
const txidOf = (t) => sha256d(serialize(t, false));
const wtxidOf = (t) => sha256d(serialize(t, segwit(t)));
// the merkle tree, written again here rather than taken from the parser
const merkle = (level) => (level.length === 1 ? level[0] : merkle(Array.from({ length: Math.ceil(level.length / 2) }, (_, k) => sha256d(Buffer.concat([level[2 * k], level[2 * k + 1] ?? level[2 * k]])))));
const OTHERS = [
  { vin: [{ txid: h('a'), vout: 1, scriptSig: Buffer.alloc(107, 1) }], vout: [{ value: 1000n, script: Buffer.from('76a914' + h('b').slice(0, 40) + '88ac', 'hex') }] },
  { vin: [{ txid: h('c'), vout: 0, witness: [Buffer.alloc(0), Buffer.alloc(300, 7), Buffer.from('c0' + h('d'), 'hex')] }, { txid: h('e'), vout: 3, witness: [Buffer.alloc(64, 2)] }],
    vout: [{ value: 0n, script: Buffer.concat([Buffer.from('6a', 'hex'), Buffer.from('SH20')]) }, { value: 330n, script: Buffer.alloc(260, 0x51) }] },
  ...Array.from({ length: 4 }, (_, k) => ({ vin: [{ txid: h(`f${k}`), vout: k, witness: [Buffer.alloc(64, k)] }], vout: [{ value: BigInt(546 + k), script: Buffer.from('5120' + h(`g${k}`), 'hex') }] })),
];
const RESERVED = Buffer.alloc(32, 0x5a);
// a coinbase: its witness holds the reserved value (null: no witness), its last output the commitment (unless commit is false)
function coinbase(others, { commit = true, reserved = [RESERVED] } = {}) {
  const root = merkle([Buffer.alloc(32), ...others.map(wtxidOf)]);
  const commitment = Buffer.concat([Buffer.from('6a24aa21a9ed', 'hex'), sha256d(Buffer.concat([root, RESERVED]))]);
  return {
    vin: [{ coinbase: true, scriptSig: Buffer.from('03a0bb0d', 'hex'), ...(reserved ? { witness: reserved } : {}) }],
    vout: [{ value: 312500000n, script: Buffer.from('0014' + h('cb').slice(0, 40), 'hex') }, ...(commit ? [{ value: 0n, script: commitment }] : [])],
  };
}
const PREV = Buffer.from(h('the block before'), 'hex');
function block(txs, { nonce = 42 } = {}) {
  const header = Buffer.concat([u32(0x20000000), PREV, merkle(txs.map(txidOf)), u32(1700000000), u32(0x1d00ffff), u32(nonce)]);
  return Buffer.concat([header, varint(txs.length), ...txs.map((t) => serialize(t, segwit(t)))]);
}
const TXS = [coinbase(OTHERS), ...OTHERS];
const BLOCK = block(TXS);
const HASH = hex(sha256d(BLOCK.subarray(0, 80)));
const EXPECTED = TXS.map((t) => ({
  txid: hex(txidOf(t)),
  vin: t.vin.map((i) => (i.coinbase ? { coinbase: true } : { txid: i.txid, vout: i.vout, witness: i.witness ?? [] })),
  vout: t.vout.map((o) => ({ value: o.value, script: o.script })),
}));

test('our block: the txid is the hash without the witnesses, and every input, witness and output is read', () => {
  const { hash, prev, txs } = parseRawBlock(BLOCK);
  assert.equal(hash, HASH);
  assert.equal(prev, hex(PREV));
  assert.deepEqual(txs, EXPECTED);
  assert.notEqual(hex(wtxidOf(TXS[2])), txs[2].txid, 'the wtxid is not the txid');
  // with no witness anywhere, the coinbase need not commit to any
  assert.equal(parseRawBlock(block([coinbase([], { commit: false, reserved: null }), OTHERS[0]])).txs.length, 2);
});

test('bytes that are not the block their header names are refused', () => {
  const flip = (bytes, at) => { const b = Buffer.from(bytes); b[at] ^= 1; return b; };
  // one bit in an output: the txids no longer give the header's merkle root
  assert.throws(() => parseRawBlock(flip(BLOCK, BLOCK.indexOf(OTHERS[0].vout[0].script) + 5)), /merkle root/);
  // one bit in a witness: the txids stay, the coinbase's commitment no longer holds
  assert.throws(() => parseRawBlock(flip(BLOCK, BLOCK.indexOf(Buffer.alloc(300, 7)) + 150)), /witnesses are not the ones the coinbase commits to/);
  assert.throws(() => parseRawBlock(block([coinbase(OTHERS, { commit: false }), ...OTHERS])), /commits to none/);
  assert.throws(() => parseRawBlock(block([coinbase(OTHERS, { reserved: null }), ...OTHERS])), /without the reserved value/);
  assert.throws(() => parseRawBlock(block([coinbase(OTHERS, { reserved: [Buffer.alloc(31)] }), ...OTHERS])), /without the reserved value/);
  assert.throws(() => parseRawBlock(block([OTHERS[0], coinbase(OTHERS.slice(1)), ...OTHERS.slice(1)])), /coinbase is not the first/);
  assert.throws(() => parseRawBlock(block([coinbase(OTHERS), coinbase(OTHERS), ...OTHERS])), /coinbase is not the first/);
  // the witness marker with a flag other than 1
  const flag = BLOCK.indexOf(serialize(OTHERS[1], true)) + 5;
  assert.equal(BLOCK[flag], 1);
  assert.throws(() => parseRawBlock(Buffer.concat([BLOCK.subarray(0, flag), Buffer.from([2]), BLOCK.subarray(flag + 1)])), /witness marker and the flag 2/);
  // the witness form around no witness at all
  const bare = { vin: [{ txid: h('w'), vout: 0, witness: [] }], vout: [{ value: 1n, script: Buffer.alloc(1) }] };
  assert.throws(() => parseRawBlock(block([coinbase([bare]), bare])), /witness form and has no witness/);
  assert.throws(() => parseRawBlock(Buffer.concat([BLOCK.subarray(0, 80), varint(0)])), /no transaction/);
});

// An Esplora server over that block: /block/:hash, its pages of transactions, and /raw unless told otherwise.
function esplora({ raw = true, page = 3, bytes = BLOCK, prev = hex(PREV), count = TXS.length } = {}) {
  const asked = [];
  const json = (v) => ({ ok: true, json: async () => v, text: async () => JSON.stringify(v) });
  const fetch = async (url) => {
    const path = new URL(url).pathname;
    asked.push(path);
    if (path === `/block/${HASH}`) return json({ id: HASH, height: 7, previousblockhash: prev, tx_count: count });
    if (path === `/block/${HASH}/raw`) return raw ? { ok: true, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) } : { ok: false, status: 404 };
    const m = new RegExp(`^/block/${HASH}/txs/(\\d+)$`).exec(path);
    if (m) {
      return json(TXS.slice(Number(m[1]), Number(m[1]) + page).map((t, k) => ({
        txid: EXPECTED[Number(m[1]) + k].txid,
        vin: t.vin.map((i) => (i.coinbase ? { is_coinbase: true } : { txid: i.txid, vout: i.vout, witness: (i.witness ?? []).map((w) => w.toString('hex')) })),
        vout: t.vout.map((o) => ({ value: Number(o.value), scriptpubkey: o.script.toString('hex') })),
      })));
    }
    return { ok: false, status: 404 };
  };
  return { fetch, asked };
}
const source = (server, pageSize = 3) => new EsploraSource('http://esplora.invalid', { fetch: server.fetch, pageSize });

test('the follower reads a block of more than one page in one request, and the same block from its pages when /raw is missing', async () => {
  const one = esplora();
  const byRaw = await source(one).block(HASH);
  assert.deepEqual(one.asked, [`/block/${HASH}`, `/block/${HASH}/raw`]);
  const two = esplora({ raw: false });
  const byPages = await source(two).block(HASH);
  assert.deepEqual(two.asked, [`/block/${HASH}`, `/block/${HASH}/raw`, ...[0, 3, 6].map((k) => `/block/${HASH}/txs/${k}`)]);
  assert.deepEqual(byRaw, byPages);
  assert.deepEqual(byRaw, { height: 7, hash: HASH, prev: hex(PREV), txs: EXPECTED });
  // one page or less: the pages, as before
  const small = esplora({ page: 25 });
  const byOnePage = await source(small, 25).block(HASH);
  assert.deepEqual(small.asked, [`/block/${HASH}`, `/block/${HASH}/txs/0`]);
  assert.deepEqual(byOnePage, byRaw);
});

test('the follower refuses raw bytes that are not the block it asked for, and does not take the pages instead', async () => {
  const refused = async (server, why) => {
    await assert.rejects(source(server).block(HASH), why);
    assert.deepEqual(server.asked, [`/block/${HASH}`, `/block/${HASH}/raw`]);
  };
  await refused(esplora({ bytes: block(TXS, { nonce: 43 }) }), new RegExp(`/block/${HASH}/raw: the bytes are those of block [0-9a-f]{64}`));
  await refused(esplora({ prev: h('another block before') }), /the block before is/);
  await refused(esplora({ count: 8 }), /7 transactions for a tx_count of 8/);
  const cut = Buffer.from(BLOCK);
  cut[BLOCK.indexOf(Buffer.alloc(300, 7))] ^= 1;
  await refused(esplora({ bytes: cut }), new RegExp(`/block/${HASH}/raw: raw block: the witnesses are not the ones`));
});
