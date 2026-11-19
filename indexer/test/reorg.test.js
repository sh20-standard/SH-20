import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Indexer } from '../src/indexer.js';
import { publicKey } from '../src/schnorr.js';
import { deployEnv, mockVerifier, opening, p2tr, p2wpkh, spend, tx } from './helpers.js';

function scenario() {
  const pay = p2wpkh();
  const list = tx({
    env: { type: 'LIST', ticker: 'GENE', amount: 1000n, price: 5000n, lockVout: 0, payScript: pay, spend: spend(2) },
    carrier: 'witness',
    vout: [{ value: 330n, script: p2tr(publicKey(randomBytes(32))) }],
  });
  const blocks = [
    // The two DEPLOY burns need SH20 in the pool: a batch of two free SH20 mints comes first.
    [tx({ env: { type: 'MINT', ticker: 'SH20', ...opening(), k: 2 } }), tx({ env: deployEnv({ pre: 1000000n, team: opening(), unlock: 4, spend: spend(0) }), carrier: 'witness' })],
    [tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() }, burnSats: 1000n }), tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() }, burnSats: 1000n })],
    [list, tx({ env: { type: 'TRANSFER', spend: spend(2) }, carrier: 'witness' })],
    [tx({ env: { type: 'TAKE', ...opening() }, vin: [{ txid: list.txid, vout: 0, witness: [] }], vout: [{ value: 5000n, script: pay }] })],
    [tx({ env: deployEnv({ ticker: 'SEC2', start: 7, unlock: 7, spend: spend(4) }), carrier: 'witness' })],
    [tx({ env: { type: 'BURN', ticker: 'GENE', vPub: 10n, spend: spend(5) }, carrier: 'witness' })],
  ];
  return blocks.map((txs, i) => ({ height: i + 1, hash: `b${i + 1}`, txs }));
}

const make = () => new Indexer({ profile: { activationHeight: 1, deployBurn: 1000n }, verifier: mockVerifier() });

test('two independent indexers reach the same digest at every height', () => {
  const blocks = scenario();
  const a = make();
  const b = make();
  for (const blk of blocks) {
    const ra = a.applyBlock(blk);
    const rb = b.applyBlock(blk);
    assert.equal(ra.digest, rb.digest, `height ${blk.height}`);
    assert.deepEqual(ra.rejected, [], `height ${blk.height}`);
  }
});

test('rollback restores the exact state, and replay gives the same digests', () => {
  const blocks = scenario();
  const ix = make();
  const digests = blocks.map((blk) => ix.applyBlock(blk).digest);
  const sizes = [];
  const fresh = make();
  for (const blk of blocks.slice(0, 3)) fresh.applyBlock(blk);
  sizes.push(fresh.tree.size, fresh.nullifiers.size, fresh.listings.get(blocks[2].txs[0].txid).state);

  ix.rollback(3);
  assert.equal(ix.height, 3);
  assert.equal(ix.digest.toString('hex'), digests[2]);
  assert.deepEqual([ix.tree.size, ix.nullifiers.size, ix.listings.get(blocks[2].txs[0].txid).state], sizes);
  assert.equal(ix.token('SEC2'), null);
  assert.equal(ix.token('GENE').burned, 0n);
  assert.equal(ix.token('SH20').burned, 1000n);
  assert.deepEqual([...ix.history.keys()], [...fresh.history.keys()]);
  assert.equal(ix.txIndex.size, fresh.txIndex.size);
  assert.ok(blocks.slice(3).every((b) => b.txs.every((t) => !ix.txIndex.has(t.txid))));

  for (const blk of blocks.slice(3)) assert.equal(ix.applyBlock(blk).digest, digests[blk.height - 1]);
});

test('a competing block 4 leads to a different digest', () => {
  const blocks = scenario();
  const ix = make();
  for (const blk of blocks.slice(0, 4)) ix.applyBlock(blk);
  const d4 = ix.digest.toString('hex');
  ix.rollback(3);
  const other = ix.applyBlock({ height: 4, hash: 'b4x', txs: [] });
  assert.notEqual(other.digest, d4);
  assert.equal(ix.listings.get(blocks[2].txs[0].txid).state, 'ACTIVE');
});
