// The genesis token SH20 has no DEPLOY: the vault checks it against its own
// profile constants. End to end with the reference indexer's default profile
// (D = 1000: every DEPLOY burns SH20), where SH20 is the only token at activation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { chain } from '../../indexer/test/helpers.js';
import { GENESIS, ACTIVATION_HEIGHT } from '../src/profile.js';
import { genesisMismatches, verifyMintTerms } from '../src/deploy.js';
import { crossCheck, profileOf } from '../src/consensus.js';
import { buildMint } from '../src/mint.js';
import { normToken, Esplora } from '../src/api.js';
import { noteOpening } from '../src/keys.js';
import { txid } from '../src/btc.js';
import { noteLeaf, tickerT } from '../src/sh20.js';

const json = (x) => JSON.parse(JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
const A = 5;

function activated() {
  const idx = new Indexer({ profile: { activationHeight: A } }); // default profile: D = 1000
  const c = chain(idx);
  for (let h = 1; h <= A; h++) c.block();
  return { idx, c, token: normToken(json(idx.token('SH20'))), status: { activationHeight: A, deployBurn: String(idx.profile.deployBurn), deployMaturity: idx.profile.deployMaturity, genesis: idx.genesis } };
}

test('the vault\'s genesis constants are the profile\'s and the vectors\'', async () => {
  const v = JSON.parse(readFileSync(new URL('../../indexer/vectors/v0.3.json', import.meta.url), 'utf8')).genesis;
  assert.equal(GENESIS.ticker, DEFAULT_PROFILE.genesis.ticker);
  assert.equal(GENESIS.max, DEFAULT_PROFILE.genesis.max);
  assert.equal(GENESIS.lim, DEFAULT_PROFILE.genesis.lim);
  for (const k of ['ticker', 'max', 'lim', 'pre', 'price', 'payMode']) assert.equal(String(GENESIS[k]), String(v[k]), k);
  assert.equal(ACTIVATION_HEIGHT, null, 'A is not fixed yet: update this test when it is');
});

test('SH20 from the reference indexer matches the profile; every lie is refused', async () => {
  const { token } = activated();
  assert.equal(token.genesis, true);
  assert.equal(token.deployTxid, null);
  assert.deepEqual(genesisMismatches(token, A), []);
  for (const [k, v] of [['price', 1n], ['payMode', 2], ['payScript', '0014' + 'ee'.repeat(20)], ['lim', 10000n], ['max', 1n],
    ['pre', 1000n], ['start', A + 1], ['end', 99]]) {
    assert.match(genesisMismatches({ ...token, [k]: v }, A).join(), new RegExp(`^${k}: profile says`), k);
  }
  assert.match(genesisMismatches(token, A + 1).join(), /start: profile says 6, indexer says 5/, 'start is the activation height');
  assert.match(genesisMismatches(token, undefined).join(), /activation height is unknown/);
  assert.match(genesisMismatches({ ...token, deployTxid: 'ab'.repeat(32) }, A).join(), /has no DEPLOY/);
  assert.match(genesisMismatches({ ...token, genesis: false }, A).join(), /does not mark it/);
  assert.match(genesisMismatches({ ...token, t: 7n }, A).join(), /^t: the ticker gives/);
});

test('only SH20 skips the DEPLOY check: a token called genesis by a liar is refused', async () => {
  const { token } = activated();
  globalThis.fetch = async () => { throw new Error('no network needed for SH20'); };
  const esplora = new Esplora('http://esplora');
  assert.equal(await verifyMintTerms(esplora, token, { activationHeight: A }), 'genesis');
  await assert.rejects(verifyMintTerms(esplora, { ...token, ticker: 'FAKE', genesis: true }, { activationHeight: A }), /only SH20 is a genesis token/);
  await assert.rejects(verifyMintTerms(esplora, { ...token, price: 5000n, payMode: 1 }, { activationHeight: A }), /genesis profile.*price/);
  await assert.rejects(verifyMintTerms(esplora, { ...token, genesis: false, deployTxid: 'ab'.repeat(32) }, { activationHeight: A }), /has no DEPLOY/,
    'SH20 shown with a DEPLOY is not sent to the DEPLOY check');
});

test('indexers on different profiles (activation height, D) refuse the mint', async () => {
  const { token, status } = activated();
  const ix = (base, s) => ({ base, status: async () => ({ network: 'signet', height: 9, digest: 'd'.repeat(64), ...s }), token: async () => token });
  let r = await crossCheck([ix('a', status), ix('b', status)], 'SH20');
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.profile, { activationHeight: A, deployBurn: 1000n, deployMaturity: 6, genesis: 'SH20' });
  r = await crossCheck([ix('a', status), ix('b', { ...status, activationHeight: 4 })], 'SH20');
  assert.match(r.problems.join(), /different profiles: activationHeight 4 ≠ 5/);
  r = await crossCheck([ix('a', status), ix('b', { ...status, deployBurn: '0' })], 'SH20');
  assert.match(r.problems.join(), /deployBurn 0 ≠ 1000/);
  r = await crossCheck([ix('a', status), ix('b', { ...status, deployMaturity: 1 })], 'SH20');
  assert.match(r.problems.join(), /deployMaturity 1 ≠ 6/, 'indexers must agree on N, the DEPLOY maturity');
  assert.equal(profileOf({}).deployBurn, null);
  for (const bad of ['abc', '1.5', -1, '1e3', {}, true]) assert.equal(profileOf({ deployBurn: bad }).deployBurn, null, `deployBurn ${JSON.stringify(bad)}`);
  assert.equal(profileOf({ deployBurn: 1000 }).deployBurn, 1000n);
});

test('MINT of SH20 accepted by the indexer: free, 1,000 units, terms from the profile', async () => {
  const { idx, c, token, status } = activated();
  const opening = (await noteOpening(new Uint8Array(32).fill(3), 0));
  const m = buildMint({
    token, opening, payer: { address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' },
    utxos: [{ txid: '11'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: c.next - 1,
  });
  assert.equal(m.price, 0n);
  assert.equal(await verifyMintTerms(null, token, profileOf(status)), 'genesis');
  const r = c.block({
    txid: txid(m.tx),
    vin: m.tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: [Buffer.alloc(71), Buffer.alloc(33)] })),
    vout: m.tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
  });
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].type, 'MINT');
  assert.equal(idx.tree.leaves[r.events[0].pos], noteLeaf(tickerT('SH20'), 1000n, opening.npk, 0n));
});
