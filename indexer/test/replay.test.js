// bin/replay.js takes the whole profile, as follow.js and indexer-rs do, and refuses an option it does not know: it
// once dropped --maturity without a word, and kept N = 6 on a chain made for N = 3.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chain, blockJson, PROOF } from '../bin/chain-gen.js';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';

const bin = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'replay.js');
const PROFILE = ['--activation', '1', '--deploy-burn', '1000', '--window', '12', '--min-depth', '1', '--maturity', '3', '--verifier', 'test'];

test('replay.js applies --window, --min-depth and --maturity, and gives the digest of an indexer with that profile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-replay-'));
  const blocks = chain('replay', { blocks: 30, missingHeights: false }).map((b) => blockJson(b));
  blocks.forEach((json, i) => writeFileSync(join(dir, `${String(i).padStart(3, '0')}.json`), json));
  const run = spawnSync(process.execPath, [bin, dir, ...PROFILE], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stderr, /W = 12, K_min = 1, N = 3/);
  const ix = new Indexer({
    profile: { activationHeight: 1, deployBurn: 1000n, anchorWindow: 12, anchorMinDepth: 1, deployMaturity: 3 },
    verifier: { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) },
  });
  for (const json of blocks) ix.applyBlock(fromBitcoindBlock(JSON.parse(json)));
  const last = run.stdout.trim().split('\n').filter((l) => /^\d+ root=/.test(l)).at(-1);
  assert.match(last, new RegExp(`digest=${ix.digest.toString('hex')}`));
});

test('replay.js and follow.js refuse an option they do not know', () => {
  for (const tool of ['replay.js', 'follow.js']) {
    const args = tool === 'replay.js' ? [mkdtempSync(join(tmpdir(), 'sh20-replay-')), '--maturty', '3'] : ['--esplora', 'http://127.0.0.1:1', '--activation', '1', '--maturty', '3'];
    const run = spawnSync(process.execPath, [join(dirname(bin), tool), ...args], { encoding: 'utf8' });
    assert.notEqual(run.status, 0, tool);
    assert.match(run.stderr, /unknown option --maturty/, tool);
  }
});
