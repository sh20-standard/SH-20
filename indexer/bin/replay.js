#!/usr/bin/env node
// Replays a folder of Bitcoin Core `getblock <hash> 2` JSON files (one block per
// file, any names) and prints the SH-20 root and digest after each block.
//
//   node bin/replay.js <folder> [--activation <height>]
//
// No proof verifier is pinned yet, so every envelope that needs a proof is
// rejected and listed. Proof-less envelopes (DEPLOY genesis, MINT, TAKE, CLAIM)
// are fully checked.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';

const args = process.argv.slice(2);
const dir = args[0];
if (!dir) {
  console.error('usage: node bin/replay.js <folder of getblock-2 JSON files> [--activation <height>]');
  process.exit(1);
}
const ai = args.indexOf('--activation');
const activationHeight = ai >= 0 ? Number(args[ai + 1]) : 0;

const blocks = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => fromBitcoindBlock(JSON.parse(readFileSync(join(dir, f), 'utf8'))))
  .sort((a, b) => a.height - b.height);

const ix = new Indexer({ profile: { activationHeight } });
for (const b of blocks) {
  const r = ix.applyBlock(b);
  console.log(`${r.height} root=${r.root.toString(16).padStart(64, '0')} digest=${r.digest} accepted=${r.events.length} rejected=${r.rejected.length}`);
  for (const x of r.rejected) console.log(`  rejected ${x.txid}: ${x.reason}`);
}
