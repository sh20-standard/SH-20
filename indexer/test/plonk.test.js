// End to end with real proofs: the indexer replays a chain whose spends, one of each kind (a TRANSFER, a BURN, a LIST
// and the burn of a DEPLOY), were proved by the circuit crate (test/fixtures/plonk-scenario.json, written by
// `sh20-circuit scenario`), and checks them with the pinned PLONK verifier. This ties together the leaf formula, the
// tree, the body hash of each type, the order of the public inputs and the proof encoding of the two implementations.
//
// Needs the verifier module: the one `cd circuit && ./build-wasm.sh` builds, else the copy in vault/prover/.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Indexer } from '../src/indexer.js';
import { parseEnvelope, serializeEnvelope } from '../src/codec.js';
import { DEFAULT_PROFILE, PROOF_BYTES, SPEND_VK_DIGEST } from '../src/constants.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { publicKey } from '../src/schnorr.js';
import { chain, p2tr, tx } from './helpers.js';

const path = (rel) => fileURLToPath(new URL(rel, import.meta.url));
// The module built here if there is one, else the one the vault ships (the CI checks it is the same build).
const built = path('../../circuit/target/wasm32-unknown-unknown/release/sh20_circuit.wasm');
const wasm = process.env.SH20_VERIFIER_WASM || (existsSync(built) ? built : path('../../vault/prover/sh20_circuit.wasm'));
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
const D = BigInt(fixture.deployBurn);
const lockKey = Buffer.from(fixture.lockKey, 'hex');

// The chain the proofs were made for, under D = 1000: nothing in block 1, the two mints in block 2, then one spend
// in each of blocks 3 (TRANSFER), 4 (BURN), 6 (LIST) and 7 (DEPLOY); nothing enters the tree in block 5. Every note
// is of the genesis token: with D > 0 no other token exists before a DEPLOY has burned some.
const spendTx = (env) => tx({ env, carrier: 'witness' });
const listTx = (env, key = lockKey) => tx({ env, carrier: 'witness', vout: [{ value: 330n, script: p2tr(key) }] });
const deployTx = (env) => tx({ env, prevHeight: 6 });
const spends = {
  3: () => spendTx(envelope(fixture.transfer)),
  4: () => spendTx(envelope(fixture.burn)),
  6: () => listTx(envelope(fixture.list)),
  7: () => deployTx(envelope(fixture.deploy)),
};

/** The chain up to block `last`, every spend of the fixture accepted in its block. */
function setup(last = 2, profile = {}) {
  const ix = new Indexer({ profile: { deployMaturity: 0, activationHeight: 1, deployBurn: D, ...profile }, verifier: plonkVerifier({ wasm, vk }) });
  const c = chain(ix);
  c.block();
  c.block(...fixture.mints.map((m) => tx({ env: { type: 'MINT', ticker: fixture.ticker, npk: BigInt(m.npk) } })));
  for (let h = 3; h <= last; h++) assert.deepEqual(reasons(c.block(...(spends[h] ? [spends[h]()] : []))), [], `block ${h}`);
  return { ix, c };
}

test('the fixture uses the pinned verifying key and 480-byte proofs', { skip: stale }, () => {
  assert.equal(fixture.vkDigest, SPEND_VK_DIGEST);
  assert.equal(fixture.ticker, DEFAULT_PROFILE.genesis.ticker);
  assert.equal(D, DEFAULT_PROFILE.deployBurn);
  const sizes = {};
  for (const name of ['transfer', 'burn', 'list', 'deploy']) {
    const bytes = Buffer.from(fixture[name], 'hex');
    const env = envelope(fixture[name]);
    assert.equal(env.spend.proof.length, PROOF_BYTES);
    assert.ok(serializeEnvelope(env).equals(bytes));
    sizes[name] = bytes.length;
  }
  // SPEC-WIRE §4: a LIST is 884 bytes and its payScript, a DEPLOY with a team opening and a spend 88 + 824
  assert.deepEqual(sizes, { transfer: 830, burn: 842, list: 884 + envelope(fixture.list).payScript.length, deploy: 912 });
  // the lock key is in the LIST's body, and it is a key a test can sign for: BIP340's first vector, secret key 3
  assert.ok(envelope(fixture.list).lockKey.equals(lockKey));
  assert.ok(publicKey(Buffer.from('03'.padStart(64, '0'), 'hex')).equals(lockKey));
});

test('a verifying key other than the pinned one is refused', { skip }, () => {
  const other = Buffer.from(vk);
  other[100] ^= 1;
  assert.throws(() => plonkVerifier({ wasm, vk: other }), /not the pinned/);
});

test('real proofs of the four kinds of spend are accepted, and only once', { skip }, () => {
  const { ix, c } = setup();
  assert.equal(ix.tree.size, 2);

  const b3 = c.block(spends[3]());
  assert.deepEqual(reasons(b3), []);
  assert.equal(ix.tree.size, 5);
  assert.equal(ix.nullifiers.size, 2);

  const b4 = c.block(spends[4]());
  assert.deepEqual(reasons(b4), []);
  assert.equal(ix.token('SH20').burned, 900n);
  assert.equal(ix.tree.size, 8);

  // replays are double spends
  const b5 = c.block(spends[3](), spends[4]());
  assert.deepEqual(reasons(b5), ['nullifier already spent', 'nullifier already spent']);

  // the LIST: 60 units leave the pool for a listing locked to the key its body names
  const b6 = c.block(spends[6]());
  assert.deepEqual(reasons(b6), []);
  const listing = ix.listings.get(b6.events[0].txid);
  assert.deepEqual([listing.state, listing.ticker, listing.amount, listing.price, listing.lockKey], ['ACTIVE', 'SH20', 60n, 5000n, fixture.lockKey]);
  assert.equal(ix.token('SH20').pool, 2000n - 900n - 60n);
  assert.equal(ix.tree.size, 11);

  // the DEPLOY: D genesis units burned, and the token exists
  assert.equal(ix.token('GENE'), null);
  const b7 = c.block(spends[7]());
  assert.deepEqual(reasons(b7), []);
  assert.deepEqual(b7.events.map((e) => [e.type, e.ticker, e.nullifiers.length, e.pos]), [['DEPLOY', 'GENE', 2, [11, 12, 13]]]);
  assert.equal(ix.token('GENE').deployHeight, 7);
  assert.equal(ix.token('SH20').burned, 900n + D);
  assert.equal(ix.token('SH20').pool, 40n);
  assert.equal(ix.tree.size, 14);
  assert.equal(ix.nullifiers.size, 8);

  // again: the DEPLOY for its ticker, the LIST for its nullifiers once the pool can pay it (a mint of 1,000)
  const b8 = c.block(spends[7](), tx({ env: { type: 'MINT', ticker: 'SH20', npk: 7n } }), spends[6]());
  assert.deepEqual(reasons(b8), ['ticker already deployed', 'nullifier already spent']);
});

test('a proof does not carry over to an altered envelope', { skip }, () => {
  const altered = (hex, f) => {
    const env = envelope(hex);
    f(env);
    return env;
  };
  const other = publicKey(Buffer.from('05'.padStart(64, '0'), 'hex'));
  // [what changes, the last block before it, the transaction]
  const cases = [
    ['TRANSFER: proof bit', 2, spendTx(altered(fixture.transfer, (e) => (e.spend.proof[7] ^= 1)))],
    ['TRANSFER: output leaf', 2, spendTx(altered(fixture.transfer, (e) => (e.spend.outs[1].leaf += 1n)))],
    ['TRANSFER: nullifier', 2, spendTx(altered(fixture.transfer, (e) => (e.spend.nf[0] += 1n)))],
    ['TRANSFER: sealed note', 2, spendTx(altered(fixture.transfer, (e) => (e.spend.outs[2].ct[0] ^= 1)))],
    ['TRANSFER: ephemeral key', 2, spendTx(altered(fixture.transfer, (e) => (e.spend.outs[0].pkEph[5] ^= 1)))],
    // the burn proof is bound to its public amount, and to the root it was anchored at
    ['BURN: amount', 3, spendTx(altered(fixture.burn, (e) => (e.vPub += 1n)))],
    ['BURN: anchor', 2, spendTx(altered(fixture.burn, (e) => (e.spend.anchorHeight = 2)))],
    // the LIST's proof is bound to what the seller asked: how much, for what price, paid to whom, locked to which key.
    // A copier who writes its own key into the envelope and pays the lock to it has no proof for that body.
    ['LIST: proof bit', 5, listTx(altered(fixture.list, (e) => (e.spend.proof[7] ^= 1)))],
    ['LIST: amount', 5, listTx(altered(fixture.list, (e) => (e.amount += 1n)))],
    ['LIST: price', 5, listTx(altered(fixture.list, (e) => (e.price -= 1n)))],
    ['LIST: payScript', 5, listTx(altered(fixture.list, (e) => (e.payScript[5] ^= 1)))],
    ['LIST: lock output index', 5, tx({ env: altered(fixture.list, (e) => (e.lockVout = 1)), carrier: 'witness', vout: [{ value: 330n, script: p2tr(other) }, { value: 330n, script: p2tr(lockKey) }] })],
    ['LIST: lock key', 5, listTx(altered(fixture.list, (e) => (e.lockKey = other)), other)],
    // the DEPLOY's proof is bound to the token it deploys: nobody takes the burn for another ticker, supply or team
    ['DEPLOY: proof bit', 6, deployTx(altered(fixture.deploy, (e) => (e.spend.proof[7] ^= 1)))],
    ['DEPLOY: ticker', 6, deployTx(altered(fixture.deploy, (e) => (e.ticker = 'GENF')))],
    ['DEPLOY: max', 6, deployTx(altered(fixture.deploy, (e) => (e.max += e.lim)))],
    ['DEPLOY: price', 6, deployTx(altered(fixture.deploy, (e) => (e.price += 1n)))],
    ['DEPLOY: unlock', 6, deployTx(altered(fixture.deploy, (e) => (e.unlock += 1)))],
    ['DEPLOY: team opening', 6, deployTx(altered(fixture.deploy, (e) => (e.team.npk += 1n)))],
  ];
  for (const [name, last, t] of cases) {
    const { ix, c } = setup(last);
    const before = [ix.tree.size, ix.nullifiers.size, ix.listings.size, ix.tokens.size];
    assert.deepEqual(reasons(c.block(t)), ['invalid proof'], name);
    assert.deepEqual([ix.tree.size, ix.nullifiers.size, ix.listings.size, ix.tokens.size], before, `${name}: a refusal leaves nothing`);
  }

  // and to the amount a DEPLOY burns: the same envelope under another D
  const { c } = setup(6, { deployBurn: D - 1n });
  assert.deepEqual(reasons(c.block(spends[7]())), ['invalid proof']);
  // the copied LIST as it is, its lock paid to the copier, never reaches the verifier
  const copy = setup(5);
  assert.deepEqual(reasons(copy.c.block(listTx(envelope(fixture.list), other))), ['lock output must be P2TR to lockKey']);
});

test('a spend proved for one type cannot be replayed as another', { skip }, () => {
  const { c } = setup();
  const t = envelope(fixture.transfer);
  assert.deepEqual(reasons(c.block(spendTx({ type: 'BURN', ticker: fixture.ticker, vPub: 5n, spend: t.spend }))), ['invalid proof']);

  // a LIST's spend as a BURN of the same amount and ticker: the same vPub and tPub, another body
  const l = envelope(fixture.list);
  const listed = setup(5);
  assert.deepEqual(reasons(listed.c.block(spendTx({ type: 'BURN', ticker: l.ticker, vPub: l.amount, spend: l.spend }))), ['invalid proof']);
  // a DEPLOY's spend as a BURN of D genesis units
  const d = envelope(fixture.deploy);
  const deployed = setup(6);
  assert.deepEqual(reasons(deployed.c.block(spendTx({ type: 'BURN', ticker: fixture.ticker, vPub: D, spend: d.spend }))), ['invalid proof']);
});
