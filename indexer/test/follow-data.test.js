// bin/follow.js --data, as a process: it follows an Esplora API to the tip, stops, and a restart applies the block
// file again without fetching those blocks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chain, blockJson } from '../bin/chain-gen.js';
import { fakeEsplora } from '../bin/esplora-fake.js';

const bin = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'follow.js');
const PROFILE = ['--activation', '1', '--deploy-burn', '1000', '--window', '12', '--min-depth', '1', '--maturity', '3', '--verifier', 'test', '--network', 'regtest'];

const freePort = async () => {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
};

/** Runs follow.js until its /status reaches `height`, then stops it. Returns the status and what it printed. */
async function followTo(esplora, dir, height) {
  const port = await freePort();
  const p = spawn(process.execPath, [bin, '--esplora', esplora.url, ...PROFILE, '--data', dir, '--port', String(port), '--interval', '1'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => (out += d));
  p.stderr.on('data', (d) => (out += d));
  try {
    for (let i = 0; i < 200; i++) {
      const s = await fetch(`http://127.0.0.1:${port}/status`).then((r) => r.json()).catch(() => null);
      if (s?.height === height) return { status: s, out };
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`follow.js did not reach block ${height}:\n${out}`);
  } finally {
    p.kill();
    await new Promise((r) => p.once('exit', r));
  }
}

test('follow.js --data: a restart applies the kept blocks and fetches only the new ones', async () => {
  const all = chain('data', { blocks: 30, missingHeights: false }).map((b) => JSON.parse(blockJson(b)));
  const dir = mkdtempSync(join(tmpdir(), 'sh20-follow-'));
  const esplora = await fakeEsplora(all.slice(0, 20));
  try {
    const first = await followTo(esplora, dir, 20);
    assert.equal(readFileSync(join(dir, 'blocks.jsonl'), 'utf8').trim().split('\n').length, 21); // the header and 20 blocks
    const headers = esplora.asked.get('/block/:hash');

    esplora.serve(all); // ten more blocks while it was stopped
    const second = await followTo(esplora, dir, 30);
    assert.match(second.out, /block file: 20 blocks, up to block 20/);
    assert.equal(esplora.asked.get('/block/:hash') - headers, 10); // blocks 21 to 30 only
    assert.notEqual(second.status.digest, first.status.digest);

    const fresh = mkdtempSync(join(tmpdir(), 'sh20-follow-'));
    const third = await followTo(esplora, fresh, 30); // the same chain, read from the source alone
    assert.equal(third.status.digest, second.status.digest);
    assert.equal(third.status.root, second.status.root);
  } finally {
    await esplora.close();
  }
});
