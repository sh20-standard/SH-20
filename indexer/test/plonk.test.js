// End to end with real proofs: the indexer replays a chain whose TRANSFER and BURN were proved by
// the circuit crate (test/fixtures/plonk-scenario.json, written by `sh20-circuit scenario`), and
// checks them with the pinned PLONK verifier. This ties together the leaf formula, the tree, the
// body hash, the order of the public inputs and the proof encoding of the two implementations.
//
// Needs the verifier module: `cd circuit && ./build-wasm.sh`. Skipped when it has not been built.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Indexer } from '../src/indexer.js';
import { parseEnvelope, serializeEnvelope } from '../src/codec.js';
import { PROOF_BYTES, SPEND_VK_DIGEST } from '../src/constants.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { chain, deployEnv, tx } from './helpers.js';

const path = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const wasm = process.env.SH20_VERIFIER_WASM || path('../../circuit/target/wasm32-unknown-unknown/release/sh20_circuit.wasm');
const noWasm = existsSync(wasm) ? false : 'verifier module not built (cd circuit && ./build-wasm.sh)';

const fixture = JSON.parse(readFileSync(path('./fixtures/plonk-scenario.json'), 'utf8'));
const vk = Buffer.from(fixture.vk, 'hex');
const envelope = (hex) => parseEnvelope(Buffer.from(hex, 'hex')).env;
// Wire v0.3 changed the spend bytes (32-byte pk_eph, no proofLen). A fixture written before it does not parse; its proofs
// must be made again against the new bodies (`sh20-circuit scenario`), so these tests wait for it instead of failing.
const stale = (() => {
  try { envelope(fixture.transfer); return false; } catch { return 'fixture predates wire v0.3: regenerate it with `sh20-circuit scenario`'; }
})();
const skip = stale || noWasm;
const reasons = (r) => r.rejected.map((x) => x.reason);

function setup() {
  // D = 0: GENE is an ordinary token deployed without a burn; SH20 (the genesis) adds no leaf, so the
  // tree, and the roots the fixture proofs were made against, are unchanged.
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier: plonkVerifier({ wasm, vk }) });
  const c = chain(ix);
  c.block(tx({ env: deployEnv() }));
  c.block(...fixture.mints.map((m) => tx({ env: { type: 'MINT', ticker: fixture.ticker, npk: BigInt(m.npk) }, burnSats: 1000n })));
  return { ix, c };
}
const spendTx = (env) => tx({ env, carrier: 'witness' });

test('the fixture uses the pinned verifying key and 480-byte proofs', { skip: stale }, () => {
  assert.equal(fixture.vkDigest, SPEND_VK_DIGEST);
  assert.equal(fixture.ticker, deployEnv().ticker);
  for (const hex of [fixture.transfer, fixture.burn]) {
    const bytes = Buffer.from(hex, 'hex');
    const env = envelope(hex);
    assert.equal(env.spend.proof.length, PROOF_BYTES);
    assert.ok(serializeEnvelope(env).equals(bytes));
  }
  assert.equal(Buffer.from(fixture.transfer, 'hex').length, 830);
  assert.equal(Buffer.from(fixture.burn, 'hex').length, 842);
});

test('a verifying key other than the pinned one is refused', { skip }, () => {
  const other = Buffer.from(vk);
  other[100] ^= 1;
  assert.throws(() => plonkVerifier({ wasm, vk: other }), /not the pinned/);
});

test('real TRANSFER and BURN proofs are accepted, and only once', { skip }, () => {
  const { ix, c } = setup();
  assert.equal(ix.tree.size, 2);

  const b3 = c.block(spendTx(envelope(fixture.transfer)));
  assert.deepEqual(reasons(b3), []);
  assert.equal(ix.tree.size, 5);
  assert.equal(ix.nullifiers.size, 2);

  const b4 = c.block(spendTx(envelope(fixture.burn)));
  assert.deepEqual(reasons(b4), []);
  assert.equal(ix.token('GENE').burned, 900n);
  assert.equal(ix.tree.size, 8);

  // replays are double spends
  const b5 = c.block(spendTx(envelope(fixture.transfer)), spendTx(envelope(fixture.burn)));
  assert.deepEqual(reasons(b5), ['nullifier already spent', 'nullifier already spent']);
});

test('a proof does not carry over to an altered envelope', { skip }, () => {
  const alter = (hex, f) => {
    const env = envelope(hex);
    f(env);
    return spendTx(env);
  };
  const cases = [
    ['proof bit', fixture.transfer, (e) => (e.spend.proof[7] ^= 1)],
    ['output leaf', fixture.transfer, (e) => (e.spend.outs[1].leaf += 1n)],
    ['nullifier', fixture.transfer, (e) => (e.spend.nf[0] += 1n)],
    ['sealed note', fixture.transfer, (e) => (e.spend.outs[2].ct[0] ^= 1)],
    ['ephemeral key', fixture.transfer, (e) => (e.spend.outs[0].pkEph[5] ^= 1)],
  ];
  for (const [name, hex, f] of cases) {
    const { c } = setup();
    assert.deepEqual(reasons(c.block(alter(hex, f))), ['invalid proof'], name);
  }

  // the burn proof is bound to its public amount, and to the root it was anchored at
  const { c } = setup();
  c.block(spendTx(envelope(fixture.transfer)));
  assert.deepEqual(reasons(c.block(alter(fixture.burn, (e) => (e.vPub += 1n)))), ['invalid proof']);
  const early = setup();
  assert.deepEqual(reasons(early.c.block(alter(fixture.burn, (e) => (e.spend.anchorHeight = 2)))), ['invalid proof']);
});

test('a TRANSFER proof cannot be replayed as a BURN', { skip }, () => {
  const { c } = setup();
  const t = envelope(fixture.transfer);
  assert.deepEqual(reasons(c.block(spendTx({ type: 'BURN', ticker: fixture.ticker, vPub: 5n, spend: t.spend }))), ['invalid proof']);
});
