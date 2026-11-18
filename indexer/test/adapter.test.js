import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { serializeEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { deployEnv, opening, opReturn } from './helpers.js';

const rpcBlock = (height, outs) => ({
  height,
  hash: 'ab'.repeat(32),
  tx: [
    { txid: '00'.repeat(32), vin: [{ coinbase: '03aabbcc' }], vout: [{ value: 3.125, scriptPubKey: { hex: '51' } }] },
    { txid: `${height}`.padStart(64, '0'), vin: [{ txid: 'cd'.repeat(32), vout: 1, txinwitness: ['aa'] }], vout: outs },
  ],
});

test('getblock-2 JSON maps to the indexer format with exact sats', () => {
  const env = serializeEnvelope(deployEnv());
  const b = fromBitcoindBlock(rpcBlock(1, [{ value: 0.00001, scriptPubKey: { hex: opReturn(env).toString('hex') } }]));
  assert.equal(b.txs[0].vin[0].coinbase, true);
  assert.equal(b.txs[0].vout[0].value, 312500000n);
  assert.equal(b.txs[1].vout[0].value, 1000n);
  assert.deepEqual(b.txs[1].vin[0].witness, [Buffer.from('aa', 'hex')]);
  const ix = new Indexer({ profile: { activationHeight: 1 } });
  assert.equal(ix.applyBlock(b).events[0].type, 'DEPLOY');
});

test('bin/replay.js replays a folder of blocks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-'));
  writeFileSync(join(dir, '1.json'), JSON.stringify(rpcBlock(1, [{ value: 0, scriptPubKey: { hex: opReturn(serializeEnvelope(deployEnv())).toString('hex') } }])));
  writeFileSync(join(dir, '2.json'), JSON.stringify(rpcBlock(2, [{ value: 0.00001, scriptPubKey: { hex: opReturn(serializeEnvelope({ type: 'MINT', tokenNum: 1, ...opening() })).toString('hex') } }])));
  const out = execFileSync(process.execPath, [new URL('../bin/replay.js', import.meta.url).pathname, dir, '--activation', '1'], { encoding: 'utf8' });
  const lines = out.trim().split('\n');
  assert.match(lines[0], /^1 root=[0-9a-f]{64} digest=[0-9a-f]{64} accepted=1 rejected=0$/);
  assert.match(lines[1], /^2 .* accepted=1 rejected=0$/);
});
