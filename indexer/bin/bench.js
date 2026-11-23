#!/usr/bin/env node
// Timings of the indexer's hot paths, for the code audit (docs/AUDIT-PROMPT.md, "The code audit"):
// Poseidon, the note tree, the codec, replaying a random chain, and the API's largest routes.
// Each figure is the best of --runs runs (default 5).
//
//   node bin/bench.js [--runs 5] [--blocks 400] [--leaves 20000]

import { performance } from 'node:perf_hooks';
import { poseidon2 } from '../src/poseidon.js';
import { NoteTree } from '../src/tree.js';
import { parseEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { listen } from '../src/api.js';
import { chain, blockJson, PROOF } from './chain-gen.js';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : dflt;
};
const RUNS = Number(arg('--runs', 5));
const BLOCKS = Number(arg('--blocks', 400));
const LEAVES = Number(arg('--leaves', 20000));

/** Best time in ms of `RUNS` runs of `fn`. */
function best(fn) {
  let min = Infinity;
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    fn();
    min = Math.min(min, performance.now() - t0);
  }
  return min;
}
const rows = [];
const row = (what, ms, n, unit) => rows.push([what, `${ms.toFixed(1)} ms`, `${((n * 1000) / ms).toFixed(0)} ${unit}/s`]);

// Poseidon of two inputs
const H = 20000;
row('poseidon2', best(() => {
  let x = 1n;
  for (let i = 0; i < H; i++) x = poseidon2(x, BigInt(i));
}), H, 'hashes');

// appending leaves to the depth-32 tree, then a path
row(`tree: ${LEAVES} appends`, best(() => {
  const t = new NoteTree();
  for (let i = 0; i < LEAVES; i++) t.append(BigInt(i + 1));
}), LEAVES, 'appends');
const tree = new NoteTree();
for (let i = 0; i < LEAVES; i++) tree.append(BigInt(i + 1));
row('tree: path of the middle leaf', best(() => {
  for (let i = 0; i < 100; i++) tree.path(LEAVES >> 1);
}), 100, 'paths');

// a random chain: its blocks as the bitcoind adapter gives them, then applied
const PROFILE = { activationHeight: 1, deployBurn: 1000n, deployMaturity: 3, anchorWindow: 12 };
const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) };
const blocks = chain('bench', { blocks: BLOCKS, missingHeights: false }).map((b) => fromBitcoindBlock(JSON.parse(blockJson(b))));
const envelopes = blocks.flatMap((b) => b.txs).flatMap((t) => t.vout.filter((o) => o.script[0] === 0x6a).map((o) => o.script));
let ix;
row(`replay: ${BLOCKS} blocks (test verifier)`, best(() => {
  ix = new Indexer({ profile: PROFILE, verifier });
  for (const b of blocks) ix.applyBlock(b);
}), BLOCKS, 'blocks');

// the codec, on the MINT envelopes of that chain
const mints = envelopes.map((s) => s.subarray(2)).filter((b) => b.subarray(0, 4).toString() === 'SH20' && b[5] === 0x02);
row(`codec: parse ${mints.length} MINTs`, best(() => {
  for (const b of mints) {
    try {
      parseEnvelope(b);
    } catch {}
  }
}), mints.length, 'envelopes');

// the API's routes that return the most, on the chain just applied
const server = await listen(ix, { port: 0, host: '127.0.0.1' });
const base = `http://127.0.0.1:${server.address().port}`;
for (const route of ['/status', '/notes', '/nullifiers', '/roots', '/listings']) {
  let bytes = 0;
  let min = Infinity;
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    const body = await (await fetch(base + route)).text();
    min = Math.min(min, performance.now() - t0);
    bytes = body.length;
  }
  rows.push([`api: GET ${route}`, `${min.toFixed(1)} ms`, `${(bytes / 1024).toFixed(0)} KiB`]);
}
server.close();

const w = [0, 1, 2].map((i) => Math.max(...rows.map((r) => r[i].length)));
for (const r of rows) console.log(`${r[0].padEnd(w[0])}  ${r[1].padStart(w[1])}  ${r[2].padStart(w[2])}`);
console.log(`best of ${RUNS}; node ${process.version}; ${ix.tree.size} leaves and ${ix.nullifiers.size} nullifiers after the replay`);
