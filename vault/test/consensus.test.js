// Several indexers must agree before a mint; one alone only warns.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crossCheck } from '../src/consensus.js';

const GENE = {
  ticker: 'GENE', t: 1195724357n, max: 21000000n, lim: 1000n, pre: 0n, start: 2, end: 0, unlock: 2, price: 1000n,
  payMode: 2, payScript: '0014' + '66'.repeat(20), mints: 5n, burned: 0n, deployTxid: 'aa'.repeat(32), deployHeight: 1,
};
const notFound = () => Object.assign(new Error('HTTP 404'), { status: 404 });

// Fake indexer: `heights` lets the height move between calls.
function ix(base, { token = GENE, height = 10, digest = 'd'.repeat(64), network = 'signet', down = false, heights } = {}) {
  let call = 0;
  return {
    base,
    async status() {
      if (down) throw new Error('connection refused');
      return { network, height: heights ? heights[Math.min(call++, heights.length - 1)] : height, digest };
    },
    async token() {
      if (!token) throw notFound();
      return token;
    },
  };
}
const fast = { sleep: async () => {} };

test('honest indexers agree: no problem, no warning', async () => {
  const r = await crossCheck([ix('a'), ix('b'), ix('c', { token: { ...GENE, mints: 6n } })], 'GENE', fast);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.agreed, 3);
  assert.equal(r.token.t, 1195724357n);
});

test('an indexer lying about payScript or the DEPLOY refuses the mint', async () => {
  let r = await crossCheck([ix('honest'), ix('liar', { token: { ...GENE, payScript: '0014' + 'ee'.repeat(20) } })], 'GENE', fast);
  assert.match(r.problems.join(), /liar and honest disagree on GENE: payScript/);
  assert.equal(r.agreed, 0);
  r = await crossCheck([ix('honest'), ix('liar', { token: { ...GENE, deployTxid: 'bb'.repeat(32) } })], 'GENE', fast);
  assert.match(r.problems.join(), /deployTxid/, 'naming another DEPLOY of the ticker is a disagreement');
  r = await crossCheck([ix('honest'), ix('liar', { token: null })], 'GENE', fast);
  assert.match(r.problems.join(), /liar does not know GENE/);
});

test('same height, different digest refuses the mint', async () => {
  const r = await crossCheck([ix('a'), ix('b', { digest: 'e'.repeat(64) })], 'GENE', fast);
  assert.match(r.problems.join(), /disagree on the state at block 10/);
});

test('indexers a block apart: retried, then digests skipped with a warning', async () => {
  let r = await crossCheck([ix('a', { height: 11 }), ix('b', { heights: [10, 11] })], 'GENE', fast);
  assert.deepEqual(r.warnings, [], 'the slower one caught up on the retry');
  assert.equal(r.agreed, 2);
  r = await crossCheck([ix('a', { height: 12 }), ix('b', { height: 10, digest: 'e'.repeat(64) })], 'GENE', fast);
  assert.deepEqual(r.problems, []);
  assert.match(r.warnings.join(), /different blocks.*not compared/);
});

test('one indexer, or one unreachable: warnings only', async () => {
  let r = await crossCheck([ix('a')], 'GENE', fast);
  assert.deepEqual(r.problems, []);
  assert.match(r.warnings.join(), /only one indexer/);
  assert.equal(r.agreed, 1);
  r = await crossCheck([ix('a'), ix('b', { down: true })], 'GENE', fast);
  assert.match(r.warnings.join(), /unreachable, not compared: b/);
  assert.match(r.warnings.join(), /only one indexer/);
  await assert.rejects(crossCheck([ix('a', { down: true })], 'GENE', fast), /no indexer reachable/);
  await assert.rejects(crossCheck([ix('a', { token: null })], 'GENE', fast), /unknown ticker/);
  r = await crossCheck([ix('a', { network: 'mainnet' })], 'GENE', fast);
  assert.match(r.problems.join(), /follows mainnet/);
});
