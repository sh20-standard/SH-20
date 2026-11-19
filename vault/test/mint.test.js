// End to end against the reference indexer: the vault builds the MINT, the
// indexer reads it from a block and must accept it with the leaf the vault expects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { deployEnv, tx as helperTx, chain } from '../../indexer/test/helpers.js';
import { buildMint, mintProblems, selectCoins } from '../src/mint.js';
import { normToken } from '../src/api.js';
import { noteOpening } from '../src/keys.js';
import { parsePsbt, addressToScript, scriptType, estimateVsize, txid, vsize } from '../src/btc.js';
import { noteLeaf, parseEnvelope, tickerT } from '../src/sh20.js';

const TR = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c';
const WPKH = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const PUB = '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const utxo = (value, i = 0) => ({ txid: (i + 1).toString(16).padStart(64, '0'), vout: i, value });

const toIndexerTx = (t) => ({
  txid: txid(t),
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

// Fakes the wallet signature so the size is the real one (indexers do not check BTC signatures).
function fakeSign(psbt, type) {
  const p = parsePsbt(psbt);
  return p.tx.vin.map(() => (type === 'p2tr' ? [new Uint8Array(64)] : [new Uint8Array(71), new Uint8Array(33)]));
}

function setup(over) {
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n } });
  const c = chain(idx);
  const r = c.block(helperTx({ env: deployEnv(over) }));
  assert.equal(r.events.at(-1)?.type, 'DEPLOY', JSON.stringify(r.rejected));
  return { idx, c };
}

const seed = new Uint8Array(32).fill(9);
const OPEN0 = await noteOpening(seed, 0); // the vault's public note 0 (WebCrypto: asynchronous)

for (const [label, over, payer] of [
  ['payMode 1 (burn), taproot payer', { payMode: 1, price: 1000n }, { address: TR, publicKey: PUB }],
  ['payMode 2 (pay to script), native segwit payer', { payMode: 2, price: 5000n, payScript: Buffer.from('0014' + '66'.repeat(20), 'hex') }, { address: WPKH }],
  ['payMode 2 below dust is raised to dust and still accepted', { payMode: 2, price: 100n, payScript: Buffer.from('0014' + '66'.repeat(20), 'hex') }, { address: WPKH }],
  ['payMode 0 (free)', { payMode: 0, price: 0n }, { address: TR, publicKey: PUB }],
]) {
  test(`MINT accepted by the indexer: ${label}`, async () => {
    const { idx, c } = setup(over);
    const token = normToken(idx.token('GENE'));
    const opening = OPEN0;
    const m = buildMint({ token, opening, payer, utxos: [utxo(3000n, 0), utxo(100000n, 1), utxo(20000n, 2)], feeRate: 2, tipHeight: c.next - 1 });

    // the envelope is the 42-byte MINT of wire v0.3 (npk alone) and parses back with the indexer codec
    assert.equal(m.envelope.length, 42);
    assert.equal(parseEnvelope(Buffer.from(m.envelope)).env.npk, opening.npk);
    assert.equal(m.tx.vin.length, 1, 'one input');

    const type = scriptType(addressToScript(payer.address));
    const witnesses = fakeSign(m.psbt, type);
    m.tx.vin.forEach((i, k) => { i.witness = witnesses[k]; });
    const r = c.block(toIndexerTx(m.tx));
    assert.deepEqual(r.rejected, []);
    assert.equal(r.events[0].type, 'MINT');
    assert.equal(parseEnvelope(Buffer.from(m.envelope)).env.ticker, 'GENE', 'the MINT names its token by ticker');
    const leaf = noteLeaf(tickerT('GENE'), token.lim, opening.npk, 0n);
    assert.equal(idx.tree.leaves[r.events[0].pos], leaf);

    const outs = m.tx.vout.reduce((s, o) => s + o.value, 0n);
    const ins = m.tx.vin.reduce((s, i) => s + [3000n, 100000n, 20000n][i.vout], 0n);
    assert.equal(ins - outs, m.fee);
    const real = vsize(m.tx);
    assert.ok(m.fee >= BigInt(Math.ceil(2 * real)), 'fee covers the real size');
    console.log(`  ${label}: ${real} vB (estimate ${m.vsizeEstimate}), ${m.tx.vout.length} outputs, fee ${m.fee} sats`);
  });
}

test('pre-flight refuses mints the indexer would reject (no refund)', async () => {
  const { idx, c } = setup({ start: 5, end: 6, unlock: 5, max: 3000n, lim: 1000n });
  const t = normToken(idx.token('GENE'));
  assert.match(mintProblems(t, 4).join(), /opens at block 5/);
  assert.deepEqual(mintProblems(t, 5), []);
  assert.match(mintProblems(t, 7).join(), /closed/);
  assert.match(mintProblems({ ...t, mints: 3n }, 5).join(), /sold out/);
  assert.throws(() => buildMint({ token: t, opening: OPEN0, payer: { address: WPKH }, utxos: [utxo(1e5)], feeRate: 1, tipHeight: c.next - 1 }), /opens at block 5/);
});

test('coin selection: smallest single input, no change when it would be dust, several inputs if needed', async () => {
  const s = addressToScript(WPKH);
  const fixed = [{ value: 1000n, script: new Uint8Array(76).fill(0x6a) }];
  const one = selectCoins([utxo(50000n, 0), utxo(5000n, 1), utxo(900n, 2)], fixed, 'p2wpkh', s, 1);
  assert.deepEqual(one.picked.map((u) => u.value), [5000n]);
  assert.ok(one.change > 0n);
  const fee0 = BigInt(estimateVsize(['p2wpkh'], [fixed[0].script]));
  const exact = selectCoins([utxo(1000n + fee0 + 100n)], fixed, 'p2wpkh', s, 1);
  assert.equal(exact.change, 0n, 'leftover below dust goes to the fee');
  const many = selectCoins([utxo(700n, 0), utxo(800n, 1), utxo(900n, 2)], fixed, 'p2wpkh', s, 1);
  assert.equal(many.picked.length, 2);
  assert.throws(() => selectCoins([utxo(500n)], fixed, 'p2wpkh', s, 1), /not enough BTC/);
});

test('mainnet or legacy payers are refused', async () => {
  const { idx, c } = setup({});
  const t = normToken(idx.token('GENE'));
  const args = { token: t, opening: OPEN0, utxos: [utxo(1e5)], feeRate: 1, tipHeight: c.next };
  assert.throws(() => buildMint({ ...args, payer: { address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' } }), /not a signet address/);
  assert.throws(() => buildMint({ ...args, payer: { address: 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7' } }), /native segwit, nested segwit or taproot/);
});

test('fee rate above the hard cap is refused', async () => {
  const { idx, c } = setup({});
  const t = normToken(idx.token('GENE'));
  assert.throws(() => buildMint({ token: t, opening: OPEN0, payer: { address: WPKH }, utxos: [utxo(10n ** 8n)], feeRate: 5000, tipHeight: c.next }), /fee rate must be between/);
});

test('batch MINT (wire v0.3): k mints in a 43-byte envelope, paid k × price, one note of k × lim', async () => {
  for (const [over, payer] of [
    [{ payMode: 1, price: 1000n }, { address: TR, publicKey: PUB }],
    [{ payMode: 2, price: 5000n, payScript: Buffer.from('0014' + '66'.repeat(20), 'hex') }, { address: WPKH }],
    [{ payMode: 0, price: 0n }, { address: TR, publicKey: PUB }],
  ]) {
    const { idx, c } = setup(over);
    const token = normToken(idx.token('GENE'));
    const opening = OPEN0;
    const m = buildMint({ token, opening, payer, utxos: [utxo(100000n, 1)], feeRate: 2, tipHeight: c.next - 1, k: 3 });
    assert.equal(m.envelope.length, 43);
    assert.equal(parseEnvelope(Buffer.from(m.envelope)).env.k, 3);
    assert.equal(m.price, over.payMode === 0 ? 0n : 3n * over.price);
    assert.equal(m.v, 3000n);
    const witnesses = fakeSign(m.psbt, scriptType(addressToScript(payer.address)));
    m.tx.vin.forEach((i, j) => { i.witness = witnesses[j]; });
    const r = c.block(toIndexerTx(m.tx));
    assert.deepEqual(r.rejected, [], `payMode ${over.payMode}`);
    assert.equal(r.events[0].v, 3000n);
    assert.equal(idx.tree.leaves[r.events[0].pos], noteLeaf(tickerT('GENE'), 3000n, opening.npk, 0n));
    assert.equal(idx.token('GENE').mints, 3n);
  }
});

test('batch MINT: never more than 10, nor more than what is left (an indexer keeps the overpayment)', async () => {
  const { idx, c } = setup({ max: 5000n, lim: 1000n, payMode: 1, price: 1000n });
  const t = normToken(idx.token('GENE'));
  const args = { token: t, opening: OPEN0, payer: { address: WPKH }, utxos: [utxo(10n ** 6n)], feeRate: 1, tipHeight: c.next - 1 };
  assert.throws(() => buildMint({ ...args, k: 6 }), /only 5 mint\(s\) left/);
  assert.throws(() => buildMint({ ...args, k: 11 }), /1 to 10/);
  assert.throws(() => buildMint({ ...args, k: 0 }), /1 to 10/);
  assert.equal(buildMint({ ...args, k: 5 }).price, 5000n);
  assert.equal(buildMint({ ...args, k: 1 }).envelope.length, 42, 'one mint has no count byte');
});
