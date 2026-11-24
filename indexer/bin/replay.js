#!/usr/bin/env node
// Replays a folder of Bitcoin Core `getblock <hash> 3` JSON files (one block per
// file, any names, the block itself or a JSON-RPC answer holding it) and prints the
// SH-20 root and digest after each block.
//
//   node bin/replay.js <folder> --deploy-burn D [--activation <height>] [--window W] [--min-depth K] [--maturity N]
//                      [--verifier sh20_circuit.wasm [--vk spend.vk] | --verifier test]
//
// D has no default: the spec gives it none (SPEC-WIRE §7), and an indexer with another D is on another chain.
// A is by default the lowest height in the folder, and the folder must hold block A and every block after it that it
// replays. Proof-less envelopes (DEPLOY genesis, MINT, TAKE, CLAIM) are fully checked. Every envelope that needs a
// proof is rejected and listed unless --verifier names the WebAssembly build of circuit/ (cd circuit && ./build-wasm.sh;
// not audited yet). Anything it cannot replay stops it with a message and exit code 1.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { options, profileFrom } from './options.js';

const USAGE = 'usage: node bin/replay.js <folder of getblock-3 JSON files> --deploy-burn D [--activation <height>] [--window W] [--min-depth K] [--maturity N] [--verifier sh20_circuit.wasm [--vk spend.vk] | --verifier test]';
const opt = options(process.argv.slice(2), ['activation', 'deploy-burn', 'window', 'min-depth', 'maturity', 'verifier', 'vk'], USAGE, { positionals: 1 });
const [dir] = opt.positional;
if (dir === undefined) opt.fail('no folder given');
opt.require('deploy-burn');

const stop = (why) => {
  console.error(`error: ${why}`);
  process.exit(1);
};

// `bitcoin-cli getblock <hash> 3` prints the block; a JSON-RPC answer holds it in `result`, next to `error` and `id`.
const blockOf = (json) => {
  if (json && typeof json === 'object' && !Array.isArray(json) && 'result' in json && !('tx' in json)) {
    if (json.error) throw new Error(`the node answered an error: ${JSON.stringify(json.error)}`);
    return json.result;
  }
  return json;
};

let names;
try {
  names = readdirSync(dir).filter((f) => f.endsWith('.json'));
} catch (e) {
  stop(`cannot read the folder ${dir}: ${e.code ?? e.message}`);
}
const blocks = names
  .map((f) => {
    try {
      return fromBitcoindBlock(blockOf(JSON.parse(readFileSync(join(dir, f), 'utf8'))));
    } catch (e) {
      return stop(`${f}: ${e.message}`);
    }
  })
  .sort((a, b) => a.height - b.height);
if (blocks.length === 0) stop(`no block file (*.json) in ${dir}`);

// Blocks below A have no root and no digest (SPEC-WIRE §6), and are not applied.
const activationHeight = opt.int('activation', blocks[0].height);
if (blocks[0].height > activationHeight) stop(`the folder starts at block ${blocks[0].height}, after the activation block ${activationHeight}`);
if (blocks.at(-1).height < activationHeight) stop(`no block at or after the activation block ${activationHeight}`);

// --verifier test: the rule of the vectors (one proof, "valid-proof" padded with zeros, is valid), for differential runs
// against indexer-rs, which has the same flag. Never for a real chain.
const TEST_PROOF = Buffer.concat([Buffer.from('valid-proof'), Buffer.alloc(480 - 11)]);
let verifier;
try {
  verifier = opt('verifier') === 'test'
    ? { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(TEST_PROOF) }
    : opt('verifier') ? plonkVerifier({ wasm: opt('verifier'), vk: opt('vk') }) : undefined;
} catch (e) {
  stop(`--verifier: ${e.code === 'ENOENT' ? `no file ${e.path}` : e.message}`);
}
const ix = new Indexer({ profile: profileFrom(opt, { activationHeight }), verifier });
const p = ix.profile;
console.error(`profile: activation ${activationHeight}, D = ${p.deployBurn}, W = ${p.anchorWindow}, K_min = ${p.anchorMinDepth}, N = ${p.deployMaturity}`);
for (const b of blocks) {
  if (b.height < activationHeight) continue;
  let r;
  try {
    r = ix.applyBlock(b);
  } catch (e) {
    stop(`block ${b.height}: ${e.message}`);
  }
  console.log(`${r.height} root=${r.root.toString(16).padStart(64, '0')} digest=${r.digest} accepted=${r.events.length} rejected=${r.rejected.length}`);
  for (const x of r.rejected) console.log(`  rejected ${x.txid}: ${x.reason}`);
}
