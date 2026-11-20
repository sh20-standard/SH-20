// The deploy screen: the vault's DEPLOY rules must be the indexer's, and it must
// show the burn of D SH20 (a spend with a proof) when the profile has D > 0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { deployEnv, tx as helperTx, chain, opening } from '../../indexer/test/helpers.js';
import { deployProblems, deployBytes, burnInputs, planDeploy } from '../src/deploy-plan.js';
import { serializeEnvelope } from '../src/sh20.js';

const P2WPKH = Buffer.from('0014' + '66'.repeat(20), 'hex');
const base = (over = {}) => ({ ...deployEnv({ ticker: 'NEWT', start: 10, unlock: 10, ...over }) });

test('the vault refuses exactly the DEPLOYs the indexer rejects', () => {
  const cases = [
    {}, { payMode: 0, price: 0n }, { payMode: 2, price: 5000n, payScript: P2WPKH }, { end: 20 },
    { pre: 1000n, unlock: 30, team: opening() }, { max: 0n }, { lim: 0n }, { pre: 21000000n, team: opening() },
    { max: 21000500n }, { start: 3 }, { start: 4 }, { end: 9 }, { unlock: 9 }, { payMode: 0, price: 1n }, { payMode: 1, price: 0n },
    { ticker: 'SH20' },
  ];
  for (const over of cases) {
    const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 } }); // the terms are tested here, maturity in deploy-maturity.test.js
    const c = chain(idx);
    c.block(); c.block(); c.block(); // SH20 at block 1; the DEPLOY lands in block 4
    const env = base(over);
    const vault = deployProblems({ ...env, payScript: new Uint8Array(env.payScript) }, { nextHeight: c.next, taken: [...idx.tokens.keys()] });
    const r = c.block(helperTx({ env, prevHeight: c.next - 1 }));
    const accepted = r.events.some((e) => e.type === 'DEPLOY');
    assert.equal(vault.length === 0, accepted, `${JSON.stringify(over, (_, v) => (typeof v === 'bigint' ? String(v) : v))}: vault ${vault.join('; ') || 'ok'}, indexer ${r.rejected[0]?.reason ?? 'accepted'}`);
  }
});

test('envelope bytes (wire v0.3): OP_RETURN without a burn, plus the 824-byte spend with one', () => {
  const env = base();
  const d = { ...env, payScript: new Uint8Array(0) };
  assert.equal(deployBytes(d, { burn: false }), serializeEnvelope(env).length);
  assert.equal(deployBytes(d, { burn: false }), 56);
  assert.equal(deployBytes(d, { burn: true }), 56 + 824, 'SPEC-WIRE §4: + 824 with a spend (32-byte pk_eph, no proofLen)');
  const team = { ...d, pre: 1000n, unlock: 30 };
  assert.equal(deployBytes(team, { burn: false }), 88, 'SPEC-WIRE §4: 88 with a team opening (npk alone)');
});

test('a burn is paid by one or two unspent SH20 notes', () => {
  const n = (v, over = {}) => ({ ticker: 'SH20', v: BigInt(v), status: 'in tree', spent: 'no', ...over });
  assert.deepEqual(burnInputs([n(1000), n(3000)], 1000n).pick.map((x) => x.v), [1000n], 'the smallest note that covers D');
  assert.deepEqual(burnInputs([n(600), n(500), n(100)], 1000n).pick.map((x) => x.v), [600n, 500n]);
  const none = burnInputs([n(400), n(400), n(400)], 1000n);
  assert.equal(none.pick, null, 'three notes are not one spend');
  assert.equal(none.total, 1200n);
  const ignored = burnInputs([n(5000, { spent: 'block 7' }), n(5000, { spent: 'unknown' }), n(5000, { ticker: 'GENE' }), n(5000, { status: 'signed' })], 1000n);
  assert.equal(ignored.count, 0, 'spent, unknown, other tickers and unconfirmed notes do not count');
});

test('the plan shows the burn: D SH20 with a proof in the witness, or no proof when D = 0', () => {
  const d = { ...base(), payScript: new Uint8Array(0) };
  const notes = [{ ticker: 'SH20', v: 1000n, status: 'in tree', spent: 'no' }];
  const p = planDeploy(d, { nextHeight: 4, taken: ['SH20'], deployBurn: 1000n, notes });
  assert.deepEqual(p.problems, []);
  assert.equal(p.burn, 1000n);
  assert.equal(p.proof, true);
  assert.equal(p.carrier, 'witness');
  assert.equal(p.bytes, 880);
  assert.equal(p.inputs.pick.length, 1);
  assert.equal(p.mints, 21000n);
  const free = planDeploy(d, { nextHeight: 4, taken: ['SH20'], deployBurn: 0n, notes });
  assert.deepEqual([free.burn, free.proof, free.carrier, free.bytes, free.inputs], [0n, false, 'witness', 56, null], 'a DEPLOY is always in the witness (SPEC-WIRE §5)');
  assert.equal(planDeploy(d, { nextHeight: 4, taken: [], deployBurn: null }).burn, null, 'D unknown is shown as unknown, not as 0');
  assert.match(planDeploy({ ...d, ticker: 'ab!' }, { nextHeight: 4, deployBurn: 0n }).problems.join(), /4 characters/);
});
