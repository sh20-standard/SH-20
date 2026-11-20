import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { serializeEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { deployEnv, opening, opReturn, witnessFor } from './helpers.js';

const rpcBlock = (height, outs) => ({
  height,
  hash: 'ab'.repeat(32),
  tx: [
    { txid: '00'.repeat(32), vin: [{ coinbase: '03aabbcc' }], vout: [{ value: 3.125, scriptPubKey: { hex: '51' } }] },
    { txid: `${height}`.padStart(64, '0'), vin: [{ txid: 'cd'.repeat(32), vout: 1, txinwitness: ['aa'] }], vout: outs },
  ],
});

test('getblock-3 JSON maps to the indexer format with exact sats and the spent outputs\' heights', () => {
  const b = fromBitcoindBlock(rpcBlock(1, [{ value: 0.00001, scriptPubKey: { hex: '51' } }]));
  assert.equal(b.txs[0].vin[0].coinbase, true);
  assert.equal(b.txs[0].vout[0].value, 312500000n);
  assert.equal(b.txs[1].vout[0].value, 1000n);
  assert.deepEqual(b.txs[1].vin[0].witness, [Buffer.from('aa', 'hex')]);
  assert.equal(b.txs[1].vin[0].prevHeight, undefined); // verbosity 2: no prevout

  // A DEPLOY in a witness, its commit confirmed at height 2: valid at height 8 with N = 6, not at 7.
  const deploy = (height) => {
    const json = rpcBlock(height, [{ value: 0, scriptPubKey: { hex: '51' } }]);
    json.tx[1].vin[0] = { txid: 'cd'.repeat(32), vout: 0, txinwitness: witnessFor(serializeEnvelope(deployEnv({ start: height + 1, unlock: height + 1 }))).map((w) => w.toString('hex')), prevout: { height: 2, value: 0.0001, scriptPubKey: { hex: '51' } } };
    return fromBitcoindBlock(json);
  };
  assert.equal(deploy(7).txs[1].vin[0].prevHeight, 2);
  const run = (height) => {
    const ix = new Indexer({ profile: { activationHeight: height, deployBurn: 0n, deployMaturity: 6 } });
    return ix.applyBlock(deploy(height));
  };
  assert.deepEqual(run(7).rejected.map((r) => r.reason), ['DEPLOY commit confirmed less than 6 blocks before']);
  assert.deepEqual(run(8).events.map((e) => e.type), ['GENESIS', 'DEPLOY']);
  // Without the height (verbosity 2) the indexer stops rather than guess.
  const blind = deploy(8);
  delete blind.txs[1].vin[0].prevHeight;
  assert.throws(() => new Indexer({ profile: { activationHeight: 8, deployBurn: 0n } }).applyBlock(blind), /height of the output spent by DEPLOY/);
});

test('a block the indexer stops in leaves nothing behind, and applies in full once given again', () => {
  // block 8: a MINT, then a DEPLOY in a witness whose commit height is missing
  const json = rpcBlock(8, [{ value: 0, scriptPubKey: { hex: opReturn(serializeEnvelope({ type: 'MINT', ticker: 'SH20', ...opening() })).toString('hex') } }]);
  const witness = witnessFor(serializeEnvelope(deployEnv({ start: 9, unlock: 9 }))).map((w) => w.toString('hex'));
  json.tx.push({ txid: 'de'.repeat(32), vin: [{ txid: 'cd'.repeat(32), vout: 0, txinwitness: witness, prevout: { height: 2, value: 0.0001, scriptPubKey: { hex: '51' } } }], vout: [{ value: 0, scriptPubKey: { hex: '51' } }] });
  const block = (withHeight) => {
    const copy = JSON.parse(JSON.stringify(json));
    if (!withHeight) delete copy.tx[2].vin[0].prevout;
    return fromBitcoindBlock(copy);
  };
  const profile = { activationHeight: 8, deployBurn: 0n, deployMaturity: 6 };
  const ix = new Indexer({ profile });
  const before = JSON.stringify({ h: ix.height, d: ix.digest.toString('hex'), root: String(ix.tree.root), n: ix.tree.size, tokens: [...ix.tokens.keys()], meta: [...ix.meta] });
  assert.throws(() => ix.applyBlock(block(false)), /height of the output spent by DEPLOY/);
  // the MINT and the GENESIS before the stop are undone
  assert.equal(JSON.stringify({ h: ix.height, d: ix.digest.toString('hex'), root: String(ix.tree.root), n: ix.tree.size, tokens: [...ix.tokens.keys()], meta: [...ix.meta] }), before);
  assert.equal(ix.notes.length, 0);
  // the same block with the height: the same result as an indexer that never stopped
  const again = ix.applyBlock(block(true));
  const fresh = new Indexer({ profile }).applyBlock(block(true));
  assert.deepEqual(again.events.map((e) => e.type), ['GENESIS', 'MINT', 'DEPLOY']);
  assert.equal(again.digest, fresh.digest);
  assert.equal(ix.tokens.get('SH20').mints, 1n);
});

test('bin/replay.js replays a folder of blocks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-'));
  const mint = (h) => JSON.stringify(rpcBlock(h, [{ value: 0, scriptPubKey: { hex: opReturn(serializeEnvelope({ type: 'MINT', ticker: 'SH20', ...opening() })).toString('hex') } }]));
  writeFileSync(join(dir, '1.json'), mint(1));
  writeFileSync(join(dir, '2.json'), mint(2));
  const out = execFileSync(process.execPath, [new URL('../bin/replay.js', import.meta.url).pathname, dir, '--activation', '1'], { encoding: 'utf8' });
  const lines = out.trim().split('\n');
  assert.match(lines[0], /^1 root=[0-9a-f]{64} digest=[0-9a-f]{64} accepted=2 rejected=0$/);
  assert.match(lines[1], /^2 .* accepted=1 rejected=0$/);
});
