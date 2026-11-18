import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  addressToScript, scriptType, serializeTx, parseTx, createPsbt, parsePsbt, finalizePsbt, estimateVsize, vsize,
  sameUnsignedTx, txid, p2shP2wpkhRedeem,
} from '../src/btc.js';
import { toHex, fromHex } from '../src/bytes.js';

test('signet segwit addresses (BIP173 / BIP350 vectors)', () => {
  assert.equal(toHex(addressToScript('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')),
    '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262');
  assert.equal(toHex(addressToScript('tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c')),
    '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433');
  assert.equal(toHex(addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
  for (const bad of [
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', // mainnet
    'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsX', // mixed case
    'tb1pw508d6qejxtdg4y5r3zarqfsj6c3', // v1 with bech32 checksum
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', // v0 with bech32m checksum
  ]) assert.throws(() => addressToScript(bad), /not a signet address/, bad);
});

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58check(payload) {
  const sum = createHash('sha256').update(createHash('sha256').update(payload).digest()).digest().subarray(0, 4);
  const b = Buffer.concat([payload, sum]);
  let x = BigInt('0x' + b.toString('hex'));
  let s = '';
  while (x > 0n) { s = B58[Number(x % 58n)] + s; x /= 58n; }
  for (const c of b) { if (c !== 0) break; s = '1' + s; }
  return s;
}

test('signet base58 addresses', () => {
  const h = Buffer.alloc(20, 0xab);
  assert.equal(toHex(addressToScript(b58check(Buffer.concat([Buffer.from([0xc4]), h])))), 'a914' + h.toString('hex') + '87');
  assert.equal(scriptType(addressToScript(b58check(Buffer.concat([Buffer.from([0x6f]), h])))), 'p2pkh');
  assert.throws(() => addressToScript(b58check(Buffer.concat([Buffer.from([0x05]), h]))), /not a signet/);
});

const sampleTx = () => ({
  version: 2,
  locktime: 123,
  vin: [{ txid: 'aa'.repeat(32), vout: 1, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [] }],
  vout: [{ value: 1000n, script: fromHex('6a0401020304') }, { value: 5000n, script: fromHex('0014' + '11'.repeat(20)) }],
});

test('transaction round trip and txid byte order', () => {
  const tx = sampleTx();
  const raw = serializeTx(tx);
  assert.equal(toHex(serializeTx(parseTx(raw))), toHex(raw));
  const expected = Buffer.from(createHash('sha256').update(createHash('sha256').update(raw).digest()).digest()).reverse().toString('hex');
  assert.equal(txid(tx), expected);
  tx.vin[0].witness = [new Uint8Array(64)];
  assert.equal(txid(tx), expected, 'witness does not change the txid');
  assert.equal(toHex(serializeTx(parseTx(serializeTx(tx)))), toHex(serializeTx(tx)));
});

test('PSBT build, parse, finalize for P2WPKH, P2SH-P2WPKH and P2TR', () => {
  const pub = fromHex('02' + '33'.repeat(32));
  const cases = [
    { type: 'p2wpkh', script: fromHex('0014' + '22'.repeat(20)), sign: (psbt) => withKv(psbt, 0x02, concatB([0x02], pub.subarray(1)), new Uint8Array(71)) },
    { type: 'p2tr', script: fromHex('5120' + '44'.repeat(32)), meta: { tapInternalKey: pub.subarray(1) }, sign: (psbt) => withKv(psbt, 0x13, new Uint8Array(0), new Uint8Array(64)) },
    { type: 'p2sh', script: fromHex('a914' + '55'.repeat(20) + '87'), meta: { redeemScript: p2shP2wpkhRedeem(pub) }, sign: (psbt) => withKv(psbt, 0x02, concatB([], pub), new Uint8Array(71)) },
  ];
  for (const c of cases) {
    const tx = sampleTx();
    const psbt = createPsbt(tx, [{ witnessUtxo: { value: 10000n, script: c.script }, ...(c.meta || {}) }]);
    const p = parsePsbt(psbt);
    assert.ok(sameUnsignedTx(p.tx, tx));
    assert.throws(() => finalizePsbt(psbt), /not signed/);
    const done = finalizePsbt(c.sign(psbt));
    assert.ok(sameUnsignedTx(done.tx, tx), c.type);
    // a nested segwit scriptSig is part of the txid; native segwit and taproot keep the unsigned txid
    if (c.type !== 'p2sh') assert.equal(done.txid, txid(tx));
    const est = estimateVsize([c.type], tx.vout.map((o) => o.script));
    assert.ok(done.vsize <= est && done.vsize >= est - 1, `${c.type}: real ${done.vsize} vs estimate ${est}`);
    if (c.type === 'p2sh') assert.equal(toHex(done.tx.vin[0].scriptSig), '16' + toHex(p2shP2wpkhRedeem(pub)));
  }
});

// Adds one key-value pair to input 0 of a single-input, two-output PSBT (test only).
function concatB(prefix, rest) { return Uint8Array.from([...prefix, ...rest]); }
function withKv(psbt, type, keyRest, value) {
  const key = Uint8Array.from([type, ...keyRest]);
  const pair = Uint8Array.from([key.length, ...key, value.length, ...value]);
  // input map ends at the separator before the two empty output maps (last 3 bytes: 00 00 00)
  const cut = psbt.length - 3;
  return Uint8Array.from([...psbt.subarray(0, cut), ...pair, ...psbt.subarray(cut)]);
}

test('vsize estimate uses Bitcoin weights', () => {
  // reference from CLAUDE.md: P2TR, 1 input, 2 P2TR outputs ≈ 154 vB with a 64-byte signature;
  // the estimate allows a sighash byte (65), so it says 155 (one quarter vB more, rounded up)
  const p2tr = fromHex('5120' + '00'.repeat(32));
  assert.equal(estimateVsize(['p2tr'], [p2tr, p2tr]), 155);
  const tx = sampleTx();
  tx.vin[0].witness = [new Uint8Array(64)];
  assert.equal(vsize(tx), Math.ceil((serializeTx(tx, false).length * 3 + serializeTx(tx).length) / 4));
});
