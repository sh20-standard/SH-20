#!/usr/bin/env node
// Replays a folder of Bitcoin Core `getblock <hash> 2` JSON files (one block per
// file, any names) and prints the SH-20 root and digest after each block.
//
//   node bin/replay.js <folder> [--activation <height>] [--verifier sh20_circuit.wasm [--vk spend.vk]]
//
// Proof-less envelopes (DEPLOY genesis, MINT, TAKE, CLAIM) are fully checked. Every
// envelope that needs a proof is rejected and listed unless --verifier names the
// WebAssembly build of circuit/ (cd circuit && ./build-wasm.sh; not audited yet).

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { plonkVerifier } from '../src/adapters/plonk.js';

const args = process.argv.slice(2);
const dir = args[0];
if (!dir) {
  console.error('usage: node bin/replay.js <folder of getblock-2 JSON files> [--activation <height>] [--deploy-burn <D>] [--verifier sh20_circuit.wasm [--vk spend.vk]]');
  process.exit(1);
}
const blocks = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => fromBitcoindBlock(JSON.parse(readFileSync(join(dir, f), 'utf8'))))
  .sort((a, b) => a.height - b.height);

const flag = (name) => (args.indexOf(name) >= 0 ? args[args.indexOf(name) + 1] : undefined);
// Default activation: the lowest height in the folder. Blocks below A have no root and no digest (SPEC-WIRE §6).
const activationHeight = flag('--activation') !== undefined ? Number(flag('--activation')) : (blocks[0]?.height ?? 0);
const deployBurn = flag('--deploy-burn') !== undefined ? BigInt(flag('--deploy-burn')) : undefined;
const verifier = flag('--verifier') ? plonkVerifier({ wasm: flag('--verifier'), vk: flag('--vk') }) : undefined;
const ix = new Indexer({ profile: { activationHeight, ...(deployBurn !== undefined ? { deployBurn } : {}) }, verifier });
console.error(`profile: activation ${activationHeight}, D = ${ix.profile.deployBurn}`);
for (const b of blocks) {
  if (b.height < activationHeight) continue;
  const r = ix.applyBlock(b);
  console.log(`${r.height} root=${r.root.toString(16).padStart(64, '0')} digest=${r.digest} accepted=${r.events.length} rejected=${r.rejected.length}`);
  for (const x of r.rejected) console.log(`  rejected ${x.txid}: ${x.reason}`);
}
