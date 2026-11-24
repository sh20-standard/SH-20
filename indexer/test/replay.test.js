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

// What the clean-room indexer's comparison of the two `replay` commands found (2026-11-24): on the same folder and the
// same profile they agree, but replay.js took inputs indexer-rs refuses, and printed `W = NaN` or rounded a height
// without a word. Now both refuse them, and replay.js ends with a message, never a stack trace.
const run = (args) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8' });
const refused = (r, pattern, what) => {
  assert.equal(r.status, 1, `${what}: ${r.stderr}`);
  assert.match(r.stderr, pattern, what);
  assert.doesNotMatch(r.stderr, /\n\s+at /, `${what}: no stack trace`);
};
const blocks30 = chain('replay', { blocks: 30, missingHeights: false }).map((b) => blockJson(b)); // heights 1 to 30
const folder = (jsons) => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-replay-'));
  jsons.forEach((json, i) => writeFileSync(join(dir, `${String(i).padStart(3, '0')}.json`), json));
  return dir;
};
const profile = (flag, value) => {
  const out = [...PROFILE];
  const i = out.indexOf(flag);
  if (value === undefined) out.splice(i, 2);
  else out[i + 1] = value;
  return out;
};

test('replay.js refuses a command line indexer-rs refuses, before it reads a block', () => {
  const dir = folder(blocks30);
  const cases = [
    ...['abc', '1.5', '', '1e2', '0x10', '-1', '+3', ' 3'].map((v) => [profile('--window', v), /--window: ".*" is not a decimal integer/, `--window "${v}"`]),
    [profile('--maturity', '4294967296'), /--maturity: 4294967296 is above 4294967295/, 'N above u32'],
    [profile('--activation', '9007199254740993'), /--activation: 9007199254740993 is above 4294967295/, 'A past 2^53'],
    [profile('--deploy-burn', '18446744073709551616'), /--deploy-burn: 18446744073709551616 is above 18446744073709551615/, 'D above u64'],
    [profile('--deploy-burn', '-1000'), /--deploy-burn: "-1000" is not a decimal integer/, 'D negative'],
    [profile('--deploy-burn'), /--deploy-burn is required/, 'no D'],
    [[...profile('--maturity'), '--maturity'], /--maturity needs a value/, 'a flag at the end'],
    [[...profile('--maturity'), '--maturity', '--window', '3'], /--maturity needs a value/, 'a flag before a flag'],
    [[...PROFILE, '--window', '3'], /--window is given twice/, 'a flag twice'],
  ];
  for (const [args, pattern, what] of cases) {
    const r = run([dir, ...args]);
    refused(r, pattern, what);
    assert.equal(r.stdout, '', what);
  }
  refused(run([dir, folder(blocks30), ...PROFILE]), /unexpected argument/, 'a second folder');
  refused(run(PROFILE), /no folder given/, 'no folder');
});

test('replay.js refuses a folder it cannot replay from the activation block', () => {
  refused(run([folder(blocks30.slice(4)), ...PROFILE]), /error: the folder starts at block 5, after the activation block 1/, 'a folder after A');
  refused(run([folder([]), ...PROFILE]), /error: no block file \(\*\.json\) in /, 'an empty folder');
  refused(run([folder(blocks30), ...profile('--activation', '99')]), /error: no block at or after the activation block 99/, 'nothing from A on');
  refused(run([join(tmpdir(), 'sh20-no-such-folder'), ...PROFILE]), /error: cannot read the folder .*ENOENT/, 'no folder there');
  refused(run([folder([...blocks30.slice(0, 2), '{}']), ...PROFILE]), /error: 002\.json: /, 'a file that is not a block');
  // a missing block and a block given twice: the blocks before it are printed, then the stop
  const gap = run([folder([...blocks30.slice(0, 9), ...blocks30.slice(10)]), ...PROFILE]);
  refused(gap, /error: block 11: expected block 10, got 11/, 'a missing block');
  assert.equal(gap.stdout.split('\n').filter((l) => /^\d+ root=/.test(l)).length, 9);
  refused(run([folder([...blocks30.slice(0, 11), blocks30[10]]), ...PROFILE]), /error: block 11: expected block 12, got 11/, 'a block twice');
});

test('replay.js reads a JSON-RPC answer as the block it holds, and stops on an answer that is an error', () => {
  const plain = run([folder(blocks30), ...PROFILE]);
  assert.equal(plain.status, 0, plain.stderr);
  const wrapped = run([folder(blocks30.map((json, i) => `{"result":${json},"error":null,"id":${i}}`)), ...PROFILE]);
  assert.equal(wrapped.status, 0, wrapped.stderr);
  assert.equal(wrapped.stdout, plain.stdout);
  const error = '{"result":null,"error":{"code":-5,"message":"Block not found"},"id":7}';
  refused(run([folder([...blocks30.slice(0, 3), error]), ...PROFILE]), /error: 003\.json: the node answered an error: .*Block not found/, 'an error answer');
});

test('follow.js takes the same command line as indexer-rs follow: A and D required, one source, each flag once', () => {
  const follow = (args) => spawnSync(process.execPath, [join(dirname(bin), 'follow.js'), ...args], { encoding: 'utf8' });
  const esplora = ['--esplora', 'http://127.0.0.1:1'];
  refused(follow([...esplora, '--activation', '1']), /--deploy-burn is required/, 'no D');
  refused(follow([...esplora, '--deploy-burn', '1000']), /--activation is required/, 'no A');
  refused(follow(['--deploy-burn', '1000', '--activation', '1']), /give one source/, 'no source');
  refused(follow([...esplora, '--rpc', 'http://127.0.0.1:1', '--activation', '1', '--deploy-burn', '1000']), /give one source/, 'two sources');
  refused(follow([...esplora, '--activation', '1', '--deploy-burn', '1000', '--activation', '2']), /--activation is given twice/, 'A twice');
  refused(follow([...esplora, '--activation', '1.5', '--deploy-burn', '1000']), /--activation: "1.5" is not a decimal integer/, 'A not whole');
  refused(follow([...esplora, '--activation', '1', '--deploy-burn', '1000', '--port', '70000']), /--port: 70000 is above 65535/, 'a port');
});

test('--help and -h print the usage with exit 0, and a verifier file that is not there ends with a message', () => {
  for (const tool of ['replay.js', 'follow.js']) {
    for (const flag of ['--help', '-h']) {
      const r = spawnSync(process.execPath, [join(dirname(bin), tool), flag], { encoding: 'utf8' });
      assert.equal(r.status, 0, `${tool} ${flag}`);
      assert.match(r.stdout, /^usage: node bin\//, `${tool} ${flag}`);
    }
  }
  const missing = join(tmpdir(), 'sh20-no-such-verifier.wasm');
  refused(run([folder(blocks30), ...profile('--verifier', missing)]), /error: --verifier: no file .*sh20-no-such-verifier\.wasm/, 'replay.js, no verifier file');
  const follow = spawnSync(process.execPath, [join(dirname(bin), 'follow.js'), '--esplora', 'http://127.0.0.1:1', '--activation', '1', '--deploy-burn', '1000', '--verifier', missing], { encoding: 'utf8' });
  refused(follow, /error: --verifier: no file .*sh20-no-such-verifier\.wasm/, 'follow.js, no verifier file');
});
