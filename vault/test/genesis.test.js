// The genesis token SH20 has no DEPLOY: the vault checks it against its own
// profile constants. End to end with the reference indexer's default profile
// (D = 1000: every DEPLOY burns SH20), where SH20 is the only token at activation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { GENESIS, ACTIVATION_HEIGHT, PROFILE } from '../src/profile.js';
import { genesisMismatches, verifyMintTerms } from '../src/deploy.js';
import { crossCheck } from '../src/consensus.js';
import { buildMint } from '../src/mint.js';
import { normToken, Esplora } from '../src/api.js';
import { noteOpening } from '../src/keys.js';
import { txid } from '../src/btc.js';
import { noteLeaf, tickerT } from '../src/sh20.js';

const json = (x) => JSON.parse(JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
const A = PROFILE.activationHeight; // the vault's own: an indexer activated at another height is on another profile

// blocks from A on (indexer/test/helpers.js chain() starts at 1)
function chainFrom(indexer, start) {
  let h = start;
  return { block: (...txs) => indexer.applyBlock({ height: h++, hash: `h${h}`, txs }), get next() { return h; } };
}

function activated() {
  const idx = new Indexer({ profile: { activationHeight: A } }); // default profile: D = 1000
  const c = chainFrom(idx, A);
  c.block(); // block A installs SH20
  const status = {
    network: 'signet', activationHeight: A, deployBurn: String(idx.profile.deployBurn), deployMaturity: idx.profile.deployMaturity,
    anchorWindow: idx.profile.anchorWindow, genesis: idx.genesis,
  };
  return { idx, c, token: normToken(json(idx.token('SH20'))), status };
}

test('the vault\'s genesis constants are the profile\'s and the vectors\'', async () => {
  const v = JSON.parse(readFileSync(new URL('../../indexer/vectors/v0.3.json', import.meta.url), 'utf8')).genesis;
  assert.equal(GENESIS.ticker, DEFAULT_PROFILE.genesis.ticker);
  assert.equal(GENESIS.max, DEFAULT_PROFILE.genesis.max);
  assert.equal(GENESIS.lim, DEFAULT_PROFILE.genesis.lim);
  for (const k of ['ticker', 'max', 'lim', 'pre', 'price', 'payMode']) assert.equal(String(GENESIS[k]), String(v[k]), k);
  assert.equal(ACTIVATION_HEIGHT, DEFAULT_PROFILE.activationHeight, 'A is the reference profile\'s');
});

test('SH20 from the reference indexer matches the profile; every lie is refused', async () => {
  const { token } = activated();
  assert.equal(token.genesis, true);
  assert.equal(token.deployTxid, null);
  assert.deepEqual(genesisMismatches(token), []);
  for (const [k, v] of [['price', 1n], ['payMode', 2], ['payScript', '0014' + 'ee'.repeat(20)], ['lim', 10000n], ['max', 1n],
    ['pre', 1000n], ['start', A + 1], ['end', 99]]) {
    assert.match(genesisMismatches({ ...token, [k]: v }).join(), new RegExp(`^${k}: profile says`), k);
  }
  assert.match(genesisMismatches({ ...token, start: A + 1 }).join(), new RegExp(`start: profile says ${A}, indexer says ${A + 1}`), 'start is the vault\'s activation height');
  assert.match(genesisMismatches({ ...token, deployTxid: 'ab'.repeat(32) }).join(), /has no DEPLOY/);
  assert.match(genesisMismatches({ ...token, genesis: false }).join(), /does not mark it/);
  assert.match(genesisMismatches({ ...token, t: 7n }).join(), /^t: the ticker gives/);
});

test('only SH20 skips the DEPLOY check: a token called genesis by a liar is refused', async () => {
  const { token } = activated();
  globalThis.fetch = async () => { throw new Error('no network needed for SH20'); };
  const esplora = new Esplora('http://esplora');
  assert.equal(await verifyMintTerms(esplora, token), 'genesis');
  await assert.rejects(verifyMintTerms(esplora, { ...token, ticker: 'FAKE', genesis: true }), /only SH20 is a genesis token/);
  await assert.rejects(verifyMintTerms(esplora, { ...token, price: 5000n, payMode: 1 }), /genesis profile.*price/);
  await assert.rejects(verifyMintTerms(esplora, { ...token, genesis: false, deployTxid: 'ab'.repeat(32) }), /has no DEPLOY/,
    'SH20 shown with a DEPLOY is not sent to the DEPLOY check');
});

test('an indexer on another profile than the vault (activation height, D, N) refuses the mint, and names it', async () => {
  const { token, status } = activated();
  const ix = (base, s) => ({ base, status: async () => ({ height: 9, digest: 'd'.repeat(64), ...s }), token: async () => token });
  let r = await crossCheck([ix('a', status), ix('b', status)], 'SH20');
  assert.deepEqual(r.problems, []);
  assert.equal(r.profile, PROFILE);
  r = await crossCheck([ix('a', status), ix('b', { ...status, activationHeight: A + 4 })], 'SH20');
  assert.deepEqual(r.problems, [`b follows another profile: activationHeight ${A + 4}, the vault has ${A}`]);
  r = await crossCheck([ix('a', status), ix('b', { ...status, deployBurn: '0' })], 'SH20');
  assert.deepEqual(r.problems, ['b follows another profile: deployBurn 0, the vault has 1000']);
  r = await crossCheck([ix('a', { ...status, deployMaturity: 1 }), ix('b', { ...status, deployMaturity: 1 })], 'SH20');
  assert.equal(r.problems.length, 2, 'two indexers that agree with each other on N, not with the vault: both named');
});

test('MINT of SH20 accepted by the indexer: free, 1,000 units, terms from the profile', async () => {
  const { idx, c, token, status } = activated();
  const opening = (await noteOpening(new Uint8Array(32).fill(3), 0));
  const m = buildMint({
    token, opening, payer: { address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' },
    utxos: [{ txid: '11'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: c.next - 1,
  });
  assert.equal(m.price, 0n);
  assert.equal(await verifyMintTerms(null, token), 'genesis');
  const r = c.block({
    txid: txid(m.tx),
    vin: m.tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: [Buffer.alloc(71), Buffer.alloc(33)] })),
    vout: m.tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
  });
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].type, 'MINT');
  assert.equal(idx.tree.leaves[r.events[0].pos], noteLeaf(tickerT('SH20'), 1000n, opening.npk, 0n));
});
