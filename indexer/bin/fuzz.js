#!/usr/bin/env node
// Differential fuzzing: random chains through the reference indexer and `indexer-rs`, compared block by block.
//
//   node bin/fuzz.js --rs <path to sh20-indexer-rs> [--seed <text>] [--chains <n>] [--blocks <n>] [--keep <dir>]
//
// Each chain is a folder of `getblock <hash> 3` JSON files: valid and broken envelopes of every type, both carriers,
// batches, listings bought, claimed and closed, refused proofs, reused nullifiers, anchors at and past the window,
// DEPLOY commits old enough or not. The reference applies them in this process; `indexer-rs replay --json` reads the
// same folder. Every block's root and digest must agree, and so must the set of refused envelopes. A chain where they
// differ is kept (in --keep, default fuzz-failures/) with the command that replays it, and the run fails.
//
// The generator is not a model of the rules: it only makes inputs likely to reach them. Same seed, same chains.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { chain, blockJson, PROOF } from './chain-gen.js';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : dflt;
};
const RS = arg('--rs');
if (!RS) {
  console.error('usage: node bin/fuzz.js --rs <path to sh20-indexer-rs> [--seed <text>] [--chains <n>] [--blocks <n>] [--keep <dir>]');
  process.exit(2);
}
const SEED = arg('--seed', 'sh20');
const CHAINS = Number(arg('--chains', 50));
const BLOCKS = Number(arg('--blocks', 40));
const KEEP = arg('--keep', 'fuzz-failures');

// The profile both indexers are given: a short window and maturity so that chains of 40 blocks reach both ends.
const PROFILE = { activationHeight: 1, deployBurn: 1000n, deployMaturity: 3, anchorWindow: 12 };
const RS_FLAGS = ['--activation', '1', '--deploy-burn', '1000', '--maturity', '3', '--window', '12', '--verifier', 'test', '--json'];
const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) };

// The reference, in this process: per block, root, digest and the refused envelopes; or the height it stopped at.
function reference(blocks) {
  const ix = new Indexer({ profile: PROFILE, verifier });
  const out = [];
  for (const b of blocks) {
    try {
      const res = ix.applyBlock(fromBitcoindBlock(JSON.parse(blockJson(b))));
      for (const e of res.events) seen[e.type] = (seen[e.type] ?? 0) + 1;
      out.push({ height: res.height, root: res.root.toString(16).padStart(64, '0'), digest: res.digest, rejected: res.rejected.map((x) => `${x.txid}/${x.envelope ?? '-'}`).sort() });
    } catch (e) {
      return { blocks: out, stopped: b.height, why: e.message };
    }
  }
  return { blocks: out };
}

function rust(dir) {
  let stdout;
  let stopped;
  try {
    stdout = execFileSync(RS, ['replay', dir, ...RS_FLAGS], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
  } catch (e) {
    stdout = e.stdout ?? '';
    stopped = e.stderr?.toString().trim() || 'exit ' + e.status;
  }
  const blocks = stdout.split('\n').filter(Boolean).map((line) => {
    const j = JSON.parse(line);
    return { height: j.height, root: j.root, digest: j.digest, rejected: (j.rejected ?? []).map((x) => `${x.txid}/${x.envelope ?? '-'}`).sort() };
  });
  return { blocks, stopped };
}

function compare(a, b) {
  const n = Math.max(a.blocks.length, b.blocks.length);
  for (let i = 0; i < n; i++) {
    const x = a.blocks[i];
    const y = b.blocks[i];
    if (!x || !y) return `block ${(x ?? y).height}: only ${x ? 'the reference' : 'indexer-rs'} applied it (reference: ${a.why ?? 'went on'}; indexer-rs: ${b.stopped ?? 'went on'})`;
    for (const k of ['height', 'root', 'digest']) if (x[k] !== y[k]) return `block ${x.height}: ${k} differs (reference ${x[k]}, indexer-rs ${y[k]})`;
    if (JSON.stringify(x.rejected) !== JSON.stringify(y.rejected)) {
      const only = (p, q) => p.filter((t) => !q.includes(t));
      return `block ${x.height}: refusals differ (only the reference: ${only(x.rejected, y.rejected).join(' ') || '-'}; only indexer-rs: ${only(y.rejected, x.rejected).join(' ') || '-'})`;
    }
  }
  if (Boolean(a.stopped) !== Boolean(b.stopped)) return `only ${a.stopped ? 'the reference' : 'indexer-rs'} stopped (${a.why ?? b.stopped})`;
  return null;
}

const seen = {}; // accepted events by type, so that a run shows what it reached
let failures = 0;
let applied = 0;
let refused = 0;
const t0 = Date.now();
for (let c = 0; c < CHAINS; c++) {
  const seed = `${SEED}/${c}`;
  const blocks = chain(seed, { blocks: BLOCKS });
  const dir = mkdtempSync(join(tmpdir(), 'sh20-fuzz-'));
  blocks.forEach((b) => writeFileSync(join(dir, `${String(b.height).padStart(6, '0')}.json`), blockJson(b)));
  const a = reference(blocks);
  const b = rust(dir);
  applied += a.blocks.length;
  refused += a.blocks.reduce((s, x) => s + x.rejected.length, 0);
  const diff = compare(a, b);
  if (diff) {
    failures++;
    const keep = join(KEEP, seed.replace(/[^A-Za-z0-9._-]/g, '_'));
    mkdirSync(keep, { recursive: true });
    cpSync(dir, keep, { recursive: true });
    console.log(`DIVERGENCE in chain ${seed}: ${diff}\n  kept in ${keep}; replay: ${RS} replay ${keep} ${RS_FLAGS.join(' ')}`);
  }
  rmSync(dir, { recursive: true, force: true });
}
console.log(`${CHAINS} chains, ${applied} blocks, ${refused} refused envelopes, ${failures} divergence(s), ${((Date.now() - t0) / 1000).toFixed(1)} s (seed "${SEED}")`);
console.log('accepted: ' + Object.entries(seen).sort().map(([k, v]) => `${k} ${v}`).join(', '));
process.exit(failures ? 1 : 0);
