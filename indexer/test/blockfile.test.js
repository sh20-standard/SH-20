import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { Follower } from '../src/follower.js';
import { BlockFile, FILE_NAME, blockLine, blockOf } from '../src/blockfile.js';
import { deployEnv, mockVerifier, opening, spend, tx } from './helpers.js';

const h = (s) => createHash('sha256').update(s).digest('hex');
const mint = () => tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() }, burnSats: 1000n });

function blocks(txLists, { start = 1, salt = 'a', parent = 'genesis' } = {}) {
  let prev = parent;
  return txLists.map((txs, i) => {
    const b = { height: start + i, hash: h(`${salt}/${start + i}`), prev, txs };
    prev = b.hash;
    return b;
  });
}

/** A chain source that counts the blocks it is asked for. */
class CountingSource {
  constructor(list) {
    this.set(list);
    this.asked = 0;
  }
  set(list) {
    this.byHeight = new Map(list.map((b) => [b.height, b]));
    this.byHash = new Map(list.map((b) => [b.hash, b]));
  }
  async tipHeight() {
    return Math.max(...this.byHeight.keys());
  }
  async blockHash(height) {
    return this.byHeight.get(height).hash;
  }
  async block(hash) {
    this.asked++;
    return this.byHash.get(hash);
  }
}

const make = () => new Indexer({ profile: { deployMaturity: 0, activationHeight: 1, deployBurn: 0n }, verifier: mockVerifier() });
const digestOf = (list) => {
  const ix = make();
  for (const b of list) ix.applyBlock(b);
  return ix.digest.toString('hex');
};
const chainA = () => {
  const a = blocks([[tx({ env: deployEnv() })], [mint(), mint()], [mint()], [mint()], [tx({ env: { type: 'TRANSFER', spend: spend(3) }, carrier: 'witness' })]]);
  const fork = blocks([[mint()], [], [mint(), mint()]], { start: 4, salt: 'b', parent: a[2].hash });
  return { a, b: [...a.slice(0, 3), ...fork] };
};

/** A follower on `source` with the block file of `dir`, restored as follow.js --data does. */
function start(dir, source) {
  const held = BlockFile.open(dir, 1);
  const ix = make();
  const f = new Follower({ indexer: ix, source, startHeight: 1, file: held.file });
  f.restore(held.blocks);
  return { ix, f, held };
}

test('a block line gives back the same block: witnesses, amounts past 2^53, coinbase, prevHeight', () => {
  const b = {
    height: 7,
    hash: 'ab'.repeat(32),
    prev: 'cd'.repeat(32),
    txs: [
      { txid: '01'.repeat(32), vin: [{ coinbase: true }], vout: [{ value: 2100000000000000n, script: Buffer.from('51', 'hex') }] },
      { txid: '02'.repeat(32), vin: [{ txid: '03'.repeat(32), vout: 1, witness: [Buffer.from('dead', 'hex'), Buffer.alloc(0)], prevHeight: 5 }], vout: [] },
    ],
  };
  assert.deepEqual(blockOf(JSON.parse(blockLine(b))), b);
});

test('a restart applies the block file without asking the source, and goes on from its tip', async () => {
  const { a } = chainA();
  const dir = mkdtempSync(join(tmpdir(), 'sh20-blocks-'));
  const first = start(dir, new CountingSource(a.slice(0, 3)));
  assert.equal(await first.f.step(), 3);

  const source = new CountingSource(a);
  const again = start(dir, source);
  assert.equal(again.held.blocks.length, 3);
  assert.equal(again.ix.height, 3);
  assert.equal(await again.f.step(), 2);
  assert.equal(source.asked, 2); // blocks 4 and 5 only
  assert.equal(again.ix.digest.toString('hex'), digestOf(a));
  assert.equal(start(dir, source).ix.digest.toString('hex'), digestOf(a)); // and once more, from the file alone
});

test('blocks a reorg replaced while the follower was stopped are undone at the first step, and the file says so', async () => {
  const { a, b } = chainA();
  const dir = mkdtempSync(join(tmpdir(), 'sh20-blocks-'));
  await start(dir, new CountingSource(a)).f.step();

  const after = start(dir, new CountingSource(b)); // the chain moved to b (blocks 4 to 6) while stopped
  assert.equal(after.ix.height, 5);
  await after.f.step();
  assert.equal(after.ix.height, 6);
  assert.equal(after.ix.digest.toString('hex'), digestOf(b));
  assert.match(readFileSync(join(dir, FILE_NAME), 'utf8'), /\{"rollback":4\}/);

  const tidy = start(dir, new CountingSource(b)); // reopened: rewritten without the rollback and the old blocks
  assert.equal(tidy.held.dropped, 3); // blocks 4 and 5 of a, and the rollback line
  assert.deepEqual(tidy.held.blocks.map((x) => x.hash), b.map((x) => x.hash));
  assert.doesNotMatch(readFileSync(join(dir, FILE_NAME), 'utf8'), /rollback/);
  assert.equal(tidy.ix.digest.toString('hex'), digestOf(b));
});

test('a line cut short is dropped, and so is everything after a block that does not follow', async () => {
  const { a } = chainA();
  const dir = mkdtempSync(join(tmpdir(), 'sh20-blocks-'));
  await start(dir, new CountingSource(a)).f.step();
  const path = join(dir, FILE_NAME);
  const lines = readFileSync(path, 'utf8').split('\n');
  appendFileSync(path, lines[1].slice(0, 40)); // a crash in the middle of a line
  let held = BlockFile.open(dir, 1);
  assert.equal(held.blocks.length, 5);
  assert.equal(held.dropped, 1);

  // block 3 replaced by one that does not link to block 2: blocks 3 to 5 are left out, and asked again
  const broken = { ...JSON.parse(lines[3]), prev: 'ff'.repeat(32) };
  writeFileSync(path, [lines[0], lines[1], lines[2], JSON.stringify(broken), lines[4], lines[5], ''].join('\n'));
  held = BlockFile.open(dir, 1);
  assert.deepEqual(held.blocks.map((x) => x.height), [1, 2]);
  assert.equal(held.dropped, 3);
  const source = new CountingSource(a);
  const again = start(dir, source);
  await again.f.step();
  assert.equal(source.asked, 3);
  assert.equal(again.ix.digest.toString('hex'), digestOf(a));
});

test('a block file of another activation height, or of another program, is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-blocks-'));
  BlockFile.open(dir, 1);
  assert.throws(() => BlockFile.open(dir, 2), /written for activation height 1, not 2/);
  writeFileSync(join(dir, FILE_NAME), '{"sh20-indexer-rs":"blocks","version":1,"activation":1}\n');
  assert.throws(() => BlockFile.open(dir, 1), /not a block file of this indexer/);
});
