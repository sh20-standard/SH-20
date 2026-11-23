// The relayer of docs/RELAYER.md against a real indexer (indexer/src/indexer.js and its API) with
// the mock verifier of the indexer's tests: what it refuses before it spends anything (§2), and a
// batch it publishes (§3), read back by the indexer from the reveal's own bytes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { chain, mockVerifier, spend, tx as helperTx } from '../../indexer/test/helpers.js';
import { IndexerApi } from '../../vault/src/api.js';
import { serializeEnvelope, seal, decodeAddress, HRP } from '../../vault/src/sh20.js';
import { scanOutput } from '../../vault/src/notekeys.js';
import { envelopeScript } from '../../vault/src/taproot.js';
import { parseTx, txid } from '../../vault/src/btc.js';
import { sha256 } from '../../vault/src/hash.js';
import { utf8 } from '../../vault/src/bytes.js';
import { relayerKeys } from '../src/keys.js';
import { Relayer } from '../src/relayer.js';
import { batchScript } from '../src/batch.js';
import { relayerHandler } from '../src/http.js';
import { createServer } from 'node:http';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const keys = await relayerKeys({ words: WORDS, btcSecret: sha256(utf8('sh20 relayer test key: public, never for real coins')) });
const relayerAddress = await decodeAddress(HRP.test, keys.notes.addressString);
const other = await relayerKeys({ words: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong', btcSecret: sha256(utf8('other')) });

/** A TRANSFER anchored at `anchorHeight` whose output `k` pays `fee` of `ticker` to `to` (the relayer by default). */
async function transfer(anchorHeight, { fee = 10n, ticker = 'SH20', k = 1, to = relayerAddress, proof } = {}) {
  const s = spend(anchorHeight, proof);
  const o = await seal(to, ticker, fee, crypto.getRandomValues(new Uint8Array(32)));
  s.outs[k] = { leaf: o.leaf, pkEph: o.pkEph, ct: o.ct };
  return { s, bytes: serializeEnvelope({ type: 'TRANSFER', spend: s }) };
}
const hex = (b) => Buffer.from(b).toString('hex');
const nfHex = (x) => x.toString(16).padStart(64, '0');

/** An indexer on a chain of `blocks` empty blocks, its API, an Esplora that mines what it is given, and a relayer. */
async function setup({ blocks = 5, ...opts } = {}) {
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(idx);
  for (let i = 0; i < blocks; i++) c.block();
  const server = await listen(idx, { port: 0 });
  const broadcasts = [];
  const results = [];
  const esplora = {
    tipHeight: async () => idx.height,
    feeRate: async () => 2,
    utxos: async () => [{ txid: 'aa'.repeat(32), vout: 0, value: 100000n }].filter(() => broadcasts.length === 0),
    async broadcast(h) {
      broadcasts.push(h);
      const t = parseTx(Buffer.from(h, 'hex'));
      // each transaction in a block of its own, as the indexer reads it (the witness as Bitcoin carries it)
      results.push(c.block({ txid: txid(t), vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })), vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })) }));
      return txid(t);
    },
  };
  let clock = 1_000_000;
  const relayer = new Relayer({ keys, fees: new Map([['SH20', 10n]]), indexer: new IndexerApi(`http://127.0.0.1:${server.address().port}`), esplora, verifier: mockVerifier(), now: () => clock, ...opts });
  return { idx, c, server, relayer, broadcasts, results, wait: (s) => { clock += s * 1000; } };
}

test('one envelope: the batch script is the vault\'s own', async () => {
  const { bytes } = await transfer(3);
  const e = new Uint8Array(32).fill(7);
  assert.deepEqual(batchScript(e, [bytes]), envelopeScript(e, bytes));
});

test('docs/RELAYER.md §2: what the relayer refuses before it spends anything', async () => {
  const { c, server, relayer, broadcasts } = await setup({ blocks: 120, maxBatch: 10 });
  try {
    const at = c.next - 1; // the tip: anchored at once
    const expect = async (body, code, re) => {
      const r = await relayer.submit(body);
      assert.equal(r.code, code, JSON.stringify(r.body));
      if (re) assert.match(r.body.error, re);
      return r;
    };
    await expect('zz', 400, /in hex/);
    await expect(hex(new Uint8Array(42)), 400, /830 bytes/);
    const mint = serializeEnvelope({ type: 'BURN', ticker: 'SH20', vPub: 5n, spend: spend(at) });
    await expect(hex(mint.subarray(0, 830)), 400, /not an SH-20 envelope|not a TRANSFER/);
    await expect(hex((await transfer(at, { to: await decodeAddress(HRP.test, other.notes.addressString) })).bytes), 402, /no output pays this relayer/);
    await expect(hex((await transfer(at, { fee: 9n })).bytes), 402, /asks 10/);
    await expect(hex((await transfer(at, { ticker: 'ABCD' })).bytes), 402, /no fee in ABCD/);
    await expect(hex((await transfer(at - 100 + 5)).bytes), 422, /leaves 4 block\(s\)/); // an anchor about to run out
    await expect(hex((await transfer(at + 1)).bytes), 422, /K_min/);
    await expect(hex((await transfer(at, { proof: 'wrong' })).bytes), 422, /proof does not verify/);
    const ok = await transfer(at);
    const first = await expect(hex(ok.bytes), 202);
    assert.equal(first.body.state, 'queued');
    assert.deepEqual(first.body.fee, { ticker: 'SH20', v: '10' });
    assert.equal((await expect(hex(ok.bytes), 200)).body.state, 'queued', 'the same transfer again: its status');
    const twin = await transfer(at);
    twin.s.nf[1] = ok.s.nf[1];
    await expect(hex(serializeEnvelope({ type: 'TRANSFER', spend: twin.s })), 409, /another one this relayer has queued/);
    // a nullifier already on chain: a plain TRANSFER spends it in a block
    const spentBefore = await transfer(at);
    const r = c.block(helperTx({ env: { type: 'TRANSFER', spend: { ...spend(at), nf: [spentBefore.s.nf[0], 77n] } }, carrier: 'witness' }));
    assert.equal(r.events[0]?.type, 'TRANSFER', JSON.stringify(r.rejected));
    relayer.view = null;
    await expect(hex(spentBefore.bytes), 409, /already spent/);
    assert.equal(broadcasts.length, 0, 'nothing published: one transfer queued, the batch not due');
  } finally {
    server.close();
  }
});

test('docs/RELAYER.md §3: a batch the indexer reads as a batch, each transfer accepted, the fees the relayer\'s', async () => {
  const { c, server, relayer, broadcasts, results } = await setup({ maxBatch: 3 });
  try {
    const at = c.next - 1;
    const ts = [await transfer(at, { k: 0 }), await transfer(at, { k: 2, fee: 25n }), await transfer(at - 2)];
    for (const t of ts.slice(0, 2)) assert.equal((await relayer.submit(hex(t.bytes))).code, 202);
    assert.equal(await relayer.tick(), null, 'two of three: not due yet');
    assert.equal((await relayer.submit(hex(ts[2].bytes))).code, 202);
    const out = await relayer.tick();
    assert.equal(out.transfers, 3);
    assert.equal(broadcasts.length, 2, 'the commit, then the reveal');
    assert.equal(out.revealVsize, Math.ceil((515 + 840 * 3) / 4), 'the size of circuit/bench/batch-vsize.mjs');
    const [commitBlock, revealBlock] = results;
    assert.deepEqual(commitBlock.events, [], 'the commit carries nothing');
    assert.deepEqual(revealBlock.rejected, []);
    assert.deepEqual(revealBlock.events.map((e) => e.type), ['TRANSFER', 'TRANSFER', 'TRANSFER'], 'one batch, in the order they came');
    assert.ok(revealBlock.events.every((e) => e.txid === out.txid));
    for (const t of ts) {
      const s = relayer.status(nfHex(t.s.nf[0]));
      assert.equal(s.state, 'published');
      assert.equal(s.txid, out.txid);
    }
    // the relayer's fee notes open with its keys (and so in a vault restored from its words)
    let earned = 0n;
    for (const t of ts) for (const o of t.s.outs) earned += (await scanOutput(keys.notes, o))?.v ?? 0n;
    assert.equal(earned, 45n);
    assert.equal(relayer.queue().length, 0);
  } finally {
    server.close();
  }
});

test('docs/RELAYER.md §3: when a batch is due, and what is dropped before it', async () => {
  const { c, server, relayer, broadcasts, wait } = await setup({ maxBatch: 10, maxWaitSeconds: 600, minBlocksLeft: 12 });
  try {
    const at = c.next - 1;
    const a = await transfer(at);
    const b = await transfer(at);
    assert.equal((await relayer.submit(hex(a.bytes))).code, 202);
    assert.equal((await relayer.submit(hex(b.bytes))).code, 202);
    // b's note is spent by someone else before the batch
    c.block(helperTx({ env: { type: 'TRANSFER', spend: { ...spend(at), nf: [b.s.nf[1], 99n] } }, carrier: 'witness' }));
    wait(599);
    assert.equal(await relayer.tick(), null, 'one second short of the wait');
    const sb = relayer.status(nfHex(b.s.nf[0]));
    assert.equal(sb.state, 'dropped');
    assert.match(sb.reason, /spent by another transaction/);
    wait(1);
    const out = await relayer.tick();
    assert.equal(out?.transfers, 1, 'the oldest has waited ten minutes');
    assert.equal(broadcasts.length, 2);
    // a deadline that comes near makes a batch due at once, and one that has passed drops it
    const d = await transfer(c.next - 1);
    relayer.view = null; // two blocks were mined by the batch: the indexer is read again (the clock here does not move)
    assert.equal((await relayer.submit(hex(d.bytes))).code, 202);
    for (let i = 0; i < 100 - 12; i++) c.block();
    relayer.view = null;
    const near = await relayer.tick();
    assert.equal(near?.transfers, 1, 'fewer than 12 blocks left: published without waiting');
  } finally {
    server.close();
  }
});

test('the HTTP routes: /info, POST /transfer, /transfer/:nf', async () => {
  const { c, server, relayer } = await setup();
  const http = createServer(relayerHandler(relayer));
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${http.address().port}`;
  try {
    const info = await (await fetch(`${base}/info`)).json();
    assert.equal(info.address, keys.notes.addressString);
    assert.deepEqual(info.fees, { SH20: '10' });
    assert.equal(info.height, c.next - 1);
    const t = await transfer(c.next - 1);
    const r = await fetch(`${base}/transfer`, { method: 'POST', body: hex(t.bytes) });
    assert.equal(r.status, 202);
    assert.equal(r.headers.get('access-control-allow-origin'), '*');
    const nf = (await r.json()).nullifiers[1];
    assert.equal((await (await fetch(`${base}/transfer/${nf}`)).json()).state, 'queued');
    assert.equal((await fetch(`${base}/transfer/${'0'.repeat(64)}`)).status, 404);
    assert.equal((await fetch(`${base}/transfer`, { method: 'POST', body: 'ab'.repeat(5000) })).status, 413);
  } finally {
    http.close();
    server.close();
  }
});

test('the relayer\'s keys are the vault\'s for the same words', async () => {
  const { Vault } = await import('../../vault/src/keys.js');
  const m = new Map();
  const v = await Vault.fromWords({ getItem: (k) => m.get(k) ?? null, setItem: (k, x) => m.set(k, x), removeItem: (k) => m.delete(k) }, WORDS, 'pass');
  assert.equal(v.address, keys.notes.addressString, 'the vault restored from the relayer\'s words spends its fees');
});
