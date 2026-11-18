import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEnvelope, serializeEnvelope, CodecError } from '../src/codec.js';
import { extractEnvelope } from '../src/carrier.js';
import { deployEnv, spend, opening, fr, opReturn, witnessFor, p2wpkh, tx } from './helpers.js';

const all = () => [
  deployEnv(),
  deployEnv({ ticker: 'AB12', pre: 1000n, team: opening(), payMode: 2, payScript: p2wpkh(), spend: spend(5) }),
  { type: 'MINT', ticker: 'GENE', ...opening() },
  { type: 'TRANSFER', spend: spend(7) },
  { type: 'BURN', ticker: 'GENE', vPub: 500n, spend: spend(7) },
  { type: 'LIST', ticker: 'GENE', amount: 2000n, price: 50000n, lockVout: 1, payScript: p2wpkh(), spend: spend(7) },
  { type: 'TAKE', ...opening() },
  { type: 'CLAIM', listTxid: 'ab'.repeat(32), ...opening(), sig: Buffer.alloc(64, 3) },
];

test('every type round-trips byte for byte', () => {
  for (const env of all()) {
    const bytes = serializeEnvelope(env);
    const { env: back } = parseEnvelope(bytes);
    assert.deepEqual(serializeEnvelope(back), bytes, env.type);
  }
});

test('sizes of the proof-less envelopes', () => {
  assert.equal(serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening() }).length, 42);
  assert.equal(serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening(), k: 1 }).length, 42);
  const batch = serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening(), k: 10 });
  assert.equal(batch.length, 43);
  assert.equal(parseEnvelope(batch).env.k, 10);
  for (const k of [0, 11, 2.5]) assert.throws(() => serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening(), k }), /mint count must be 1 to 10/);
  assert.equal(serializeEnvelope({ type: 'TAKE', ...opening() }).length, 38);
  assert.equal(serializeEnvelope({ type: 'CLAIM', listTxid: '00'.repeat(32), ...opening(), sig: Buffer.alloc(64) }).length, 134);
  assert.equal(serializeEnvelope(deployEnv()).length, 6 + 4 + 8 * 3 + 4 * 3 + 8 + 1 + 1);
});

test('a TRANSFER is 830 bytes (480-byte proof, no length field) and rides the witness in 520-byte chunks', () => {
  const env = { type: 'TRANSFER', spend: spend(7, 'x') };
  const bytes = serializeEnvelope(env);
  assert.equal(bytes.length, 6 + 4 + 2 * 32 + 3 * 92 + 480); // 830
  const found = extractEnvelope({ txid: 'a', vin: [{ txid: 'b', vout: 0, witness: witnessFor(bytes) }], vout: [] });
  assert.equal(found.carrier, 'witness');
  assert.ok(found.bytes.equals(bytes));
});

test('the body hash covers everything before the proof; proofs and keys have fixed sizes', () => {
  const env = { type: 'BURN', ticker: 'GENE', vPub: 500n, spend: spend(7) };
  const bytes = serializeEnvelope(env);
  const { body } = parseEnvelope(bytes);
  assert.equal(body.length, bytes.length - 480);
  assert.ok(body.equals(bytes.subarray(0, bytes.length - 480)));
  assert.throws(() => serializeEnvelope({ ...env, spend: { ...env.spend, proof: Buffer.alloc(479) } }), /proof must be 480 bytes/);
  const s = spend(7);
  s.outs[1].pkEph = Buffer.alloc(33, 2);
  assert.throws(() => serializeEnvelope({ type: 'TRANSFER', spend: s }), /pk_eph must be 32 bytes/);
  assert.throws(() => parseEnvelope(bytes.subarray(0, bytes.length - 1)), /truncated/);
});

test('strict parsing rejects malformed envelopes', () => {
  const good = serializeEnvelope(deployEnv());
  const cases = {
    'bad magic': Buffer.concat([Buffer.from('SH21'), good.subarray(4)]),
    'unknown version': Buffer.concat([good.subarray(0, 4), Buffer.from([1]), good.subarray(5)]),
    'unknown type': Buffer.concat([good.subarray(0, 5), Buffer.from([9]), good.subarray(6)]),
    'bad ticker': Buffer.concat([good.subarray(0, 6), Buffer.from('gene'), good.subarray(10)]),
    // An extra byte after a DEPLOY is read as the start of a burn section.
    truncated: Buffer.concat([good, Buffer.from([0])]),
  };
  const mintBytes = serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening() });
  cases['bad ticker in MINT'] = Buffer.concat([mintBytes.subarray(0, 6), Buffer.from('GEN\0'), mintBytes.subarray(10)]);
  assert.throws(() => serializeEnvelope({ type: 'MINT', ticker: 'gene', ...opening() }), /bad ticker/);
  assert.throws(() => serializeEnvelope({ type: 'MINT', tokenNum: 1, ...opening() }), /bad ticker/);
  // A batch MINT ends with its count, 2 to 10; one mint is written without the byte, and nothing follows the count.
  for (const k of [0, 1, 11, 255]) assert.throws(() => parseEnvelope(Buffer.concat([mintBytes, Buffer.from([k])])), /mint count must be 2 to 10/, `k = ${k}`);
  assert.throws(() => parseEnvelope(Buffer.concat([mintBytes, Buffer.from([2, 0])])), /trailing bytes/);
  assert.throws(() => parseEnvelope(mintBytes.subarray(0, mintBytes.length - 1)), /truncated/);
  for (const [reason, buf] of Object.entries(cases)) {
    assert.throws(() => parseEnvelope(buf), (e) => e instanceof CodecError && e.message.includes(reason.replace(' in MINT', '')), reason);
  }
  // A field element at or above the BN254 modulus is non-canonical.
  const mint = serializeEnvelope({ type: 'MINT', ticker: 'GENE', npk: fr() });
  const big = Buffer.from(mint);
  big.fill(0xff, 10, 42);
  assert.throws(() => parseEnvelope(big), /non-canonical field element/);
  // payScript is only allowed with payMode 2.
  assert.throws(() => serializeEnvelope(deployEnv({ payMode: 1, payScript: p2wpkh() })) && parseEnvelope(serializeEnvelope(deployEnv({ payMode: 1, payScript: p2wpkh() }))), /payScript only allowed/);
});

test('carrier rules: one envelope per transaction', () => {
  const bytes = serializeEnvelope({ type: 'MINT', ticker: 'GENE', ...opening() });
  const one = tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() } });
  assert.ok(extractEnvelope(one).bytes);
  const twoOpReturns = { txid: 'a', vin: [{ txid: 'b', vout: 0, witness: [] }], vout: [{ value: 0n, script: opReturn(bytes) }, { value: 0n, script: opReturn(bytes) }] };
  assert.match(extractEnvelope(twoOpReturns).error, /more than one/);
  const both = { txid: 'a', vin: [{ txid: 'b', vout: 0, witness: witnessFor(bytes) }], vout: [{ value: 0n, script: opReturn(bytes) }] };
  assert.match(extractEnvelope(both).error, /more than one/);
  const nonMinimal = Buffer.concat([Buffer.from([0x6a, 0x4c, bytes.length]), bytes]); // PUSHDATA1 for a 42-byte push
  assert.match(extractEnvelope({ txid: 'a', vin: [], vout: [{ value: 0n, script: nonMinimal }] }).error, /minimal push/);
  assert.ok(extractEnvelope({ txid: 'a', vin: [], vout: [{ value: 0n, script: opReturn(Buffer.from('hello')) }] }).none);
});
