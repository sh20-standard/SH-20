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

test("the genesis block: one coinbase, Bitcoin's own txid", () => {
  const raw = Buffer.from(GENESIS, 'hex');
  assert.equal(Buffer.from(sha256d(raw.subarray(0, 80))).reverse().toString('hex'), '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  const [tx, ...rest] = parseRawBlock(raw);
  assert.equal(rest.length, 0);
  assert.equal(tx.txid, '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b');
  assert.deepEqual(tx.vin, [{ coinbase: true }]);
  assert.equal(tx.vout[0].value, 5000000000n);
  assert.equal(tx.vout[0].script.length, 67);
  assert.throws(() => parseRawBlock(raw.subarray(0, raw.length - 1)), /cut short/);
  assert.throws(() => parseRawBlock(Buffer.concat([raw, Buffer.from([0])])), /after the last transaction/);
});

// A block of our own: a segwit coinbase, a legacy transaction, segwit ones with empty and long witness items, a
// script past 252 bytes (a 3-byte length) and an OP_RETURN; serialized here as Bitcoin does.
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
const TXS = [
  { vin: [{ coinbase: true, scriptSig: Buffer.from('03a0bb0d', 'hex'), witness: [Buffer.alloc(32)] }], vout: [{ value: 312500000n, script: Buffer.from('0014' + h('cb').slice(0, 40), 'hex') }] },
  { vin: [{ txid: h('a'), vout: 1, scriptSig: Buffer.alloc(107, 1) }], vout: [{ value: 1000n, script: Buffer.from('76a914' + h('b').slice(0, 40) + '88ac', 'hex') }] },
  { vin: [{ txid: h('c'), vout: 0, witness: [Buffer.alloc(0), Buffer.alloc(300, 7), Buffer.from('c0' + h('d'), 'hex')] }, { txid: h('e'), vout: 3, witness: [Buffer.alloc(64, 2)] }],
    vout: [{ value: 0n, script: Buffer.concat([Buffer.from('6a', 'hex'), Buffer.from('SH20')]) }, { value: 330n, script: Buffer.alloc(260, 0x51) }] },
  ...Array.from({ length: 4 }, (_, k) => ({ vin: [{ txid: h(`f${k}`), vout: k, witness: [Buffer.alloc(64, k)] }], vout: [{ value: BigInt(546 + k), script: Buffer.from('5120' + h(`g${k}`), 'hex') }] })),
];
const segwit = (t) => t.vin.some((i) => i.witness);
const BLOCK = Buffer.concat([Buffer.alloc(80, 9), varint(TXS.length), ...TXS.map((t) => serialize(t, segwit(t)))]);
const TXIDS = TXS.map((t) => Buffer.from(sha256d(serialize(t, false))).reverse().toString('hex'));
const EXPECTED = TXS.map((t, k) => ({
  txid: TXIDS[k],
  vin: t.vin.map((i) => (i.coinbase ? { coinbase: true } : { txid: i.txid, vout: i.vout, witness: i.witness ?? [] })),
  vout: t.vout.map((o) => ({ value: o.value, script: o.script })),
}));

test('our block: the txid is the hash without the witnesses, and every input, witness and output is read', () => {
  const txs = parseRawBlock(BLOCK);
  assert.deepEqual(txs, EXPECTED);
  assert.notEqual(Buffer.from(sha256d(serialize(TXS[2], true))).reverse().toString('hex'), txs[2].txid, 'the wtxid is not the txid');
});

// An Esplora server over that block: /block/:hash, its pages of transactions, and /raw unless told otherwise.
function esplora({ raw = true, page = 3 } = {}) {
  const asked = [];
  const json = (v) => ({ ok: true, json: async () => v, text: async () => JSON.stringify(v) });
  const fetch = async (url) => {
    const path = new URL(url).pathname;
    asked.push(path);
    if (path === '/block/bb') return json({ id: 'bb', height: 7, previousblockhash: 'aa', tx_count: TXS.length });
    if (path === '/block/bb/raw') return raw ? { ok: true, arrayBuffer: async () => BLOCK.buffer.slice(BLOCK.byteOffset, BLOCK.byteOffset + BLOCK.length) } : { ok: false, status: 404 };
    const m = /^\/block\/bb\/txs\/(\d+)$/.exec(path);
    if (m) {
      return json(TXS.slice(Number(m[1]), Number(m[1]) + page).map((t, k) => ({
        txid: TXIDS[Number(m[1]) + k],
        vin: t.vin.map((i) => (i.coinbase ? { is_coinbase: true } : { txid: i.txid, vout: i.vout, witness: (i.witness ?? []).map((w) => w.toString('hex')) })),
        vout: t.vout.map((o) => ({ value: Number(o.value), scriptpubkey: o.script.toString('hex') })),
      })));
    }
    return { ok: false, status: 404 };
  };
  return { fetch, asked };
}

test('the follower reads a block of more than one page in one request, and the same block from its pages when /raw is missing', async () => {
  const one = esplora();
  const byRaw = await new EsploraSource('http://esplora.invalid', { fetch: one.fetch, pageSize: 3 }).block('bb');
  assert.deepEqual(one.asked, ['/block/bb', '/block/bb/raw']);
  const two = esplora({ raw: false });
  const byPages = await new EsploraSource('http://esplora.invalid', { fetch: two.fetch, pageSize: 3 }).block('bb');
  assert.deepEqual(two.asked, ['/block/bb', '/block/bb/raw', '/block/bb/txs/0', '/block/bb/txs/3', '/block/bb/txs/6']);
  assert.deepEqual(byRaw, byPages);
  assert.deepEqual(byRaw, { height: 7, hash: 'bb', prev: 'aa', txs: EXPECTED });
  // one page or less: the pages, as before
  const small = esplora({ page: 25 });
  const byOnePage = await new EsploraSource('http://esplora.invalid', { fetch: small.fetch, pageSize: 25 }).block('bb');
  assert.deepEqual(small.asked, ['/block/bb', '/block/bb/txs/0']);
  assert.deepEqual(byOnePage, byRaw);
});
