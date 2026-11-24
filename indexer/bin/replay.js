#!/usr/bin/env node
// Replays a folder of Bitcoin Core `getblock <hash> 3` JSON files (one block per
// file, any names) and prints the SH-20 root and digest after each block.
//
//   node bin/replay.js <folder> [--activation <height>] [--deploy-burn D] [--window W] [--min-depth K] [--maturity N]
//                      [--verifier sh20_circuit.wasm [--vk spend.vk] | --verifier test]
//
// Proof-less envelopes (DEPLOY genesis, MINT, TAKE, CLAIM) are fully checked. Every
// envelope that needs a proof is rejected and listed unless --verifier names the
// WebAssembly build of circuit/ (cd circuit && ./build-wasm.sh; not audited yet).

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { options, profileFrom } from './options.js';

const args = process.argv.slice(2);
const dir = args[0];
const USAGE = 'usage: node bin/replay.js <folder of getblock-3 JSON files> [--activation <height>] [--deploy-burn D] [--window W] [--min-depth K] [--maturity N] [--verifier sh20_circuit.wasm [--vk spend.vk] | --verifier test]';
const flag = options(args.slice(1), ['activation', 'deploy-burn', 'window', 'min-depth', 'maturity', 'verifier', 'vk'], USAGE);
if (!dir || dir.startsWith('--')) {
  console.error(USAGE);
  process.exit(1);
}
const blocks = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => fromBitcoindBlock(JSON.parse(readFileSync(join(dir, f), 'utf8'))))
  .sort((a, b) => a.height - b.height);

// Default activation: the lowest height in the folder. Blocks below A have no root and no digest (SPEC-WIRE §6).
const activationHeight = flag('activation') !== undefined ? Number(flag('activation')) : (blocks[0]?.height ?? 0);
// --verifier test: the rule of the vectors (one proof, "valid-proof" padded with zeros, is valid), for differential runs
// against indexer-rs, which has the same flag. Never for a real chain.
const TEST_PROOF = Buffer.concat([Buffer.from('valid-proof'), Buffer.alloc(480 - 11)]);
const verifier = flag('verifier') === 'test'
  ? { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(TEST_PROOF) }
  : flag('verifier') ? plonkVerifier({ wasm: flag('verifier'), vk: flag('vk') }) : undefined;
const ix = new Indexer({ profile: profileFrom(flag, { activationHeight }), verifier });
const p = ix.profile;
console.error(`profile: activation ${activationHeight}, D = ${p.deployBurn}, W = ${p.anchorWindow}, K_min = ${p.anchorMinDepth}, N = ${p.deployMaturity}`);
for (const b of blocks) {
  if (b.height < activationHeight) continue;
  const r = ix.applyBlock(b);
  console.log(`${r.height} root=${r.root.toString(16).padStart(64, '0')} digest=${r.digest} accepted=${r.events.length} rejected=${r.rejected.length}`);
  for (const x of r.rejected) console.log(`  rejected ${x.txid}: ${x.reason}`);
}
