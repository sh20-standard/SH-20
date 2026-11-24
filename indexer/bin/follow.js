#!/usr/bin/env node
// Follows a chain live and serves the read-only API.
//
//   node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A --deploy-burn D [--port 8020]
//   node bin/follow.js --esplora https://mempool.space/signet/api --activation A --deploy-burn D [--port 8020] [--data <folder>]
//
// A and D are the network's profile and have no default (SPEC-WIRE §7): an indexer with another A or D is on another chain.
// Your own node (--rpc) is the trust-minimised choice: an Esplora server is
// trusted to name the best chain, even though every envelope is re-checked here.
// Spends (TRANSFER, BURN, LIST, later DEPLOYs) are rejected unless --verifier names the
// WebAssembly build of circuit/ (cd circuit && ./build-wasm.sh). That verifier is not audited yet.

import { Indexer } from '../src/indexer.js';
import { BitcoindSource, EsploraSource, Follower } from '../src/follower.js';
import { listen } from '../src/api.js';
import { BlockFile } from '../src/blockfile.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { options, profileFrom } from './options.js';

const args = process.argv.slice(2);
const USAGE = 'usage: node bin/follow.js (--rpc URL [--rpcuser U --rpcpass P] | --esplora URL) --activation A --deploy-burn D [--window W] [--min-depth K] [--maturity N] [--port 8020] [--host 127.0.0.1] [--network signet] [--confirmations 0] [--interval 15] [--data <folder>] [--verifier sh20_circuit.wasm [--vk spend.vk] | --verifier test]';
const opt = options(
  args,
  ['rpc', 'rpcuser', 'rpcpass', 'esplora', 'activation', 'deploy-burn', 'window', 'min-depth', 'maturity', 'port', 'host', 'network', 'confirmations', 'interval', 'data', 'verifier', 'vk'],
  USAGE,
);

opt.require('activation', 'deploy-burn');
const activationHeight = opt.int('activation');

if ((opt('rpc') === undefined) === (opt('esplora') === undefined)) opt.fail('give one source: --rpc URL or --esplora URL');
if ((opt('rpcuser') === undefined) !== (opt('rpcpass') === undefined)) opt.fail('--rpcuser and --rpcpass go together');
if (opt('esplora') !== undefined && opt('rpcuser') !== undefined) opt.fail('--rpcuser and --rpcpass go with --rpc');
const source = opt('rpc') !== undefined
  ? new BitcoindSource(opt('rpc'), { user: opt('rpcuser', ''), pass: opt('rpcpass', '') })
  : new EsploraSource(opt('esplora'));

// What /status reports: --network, else the node's own chain name (Bitcoin Core), else "unknown" (Esplora does not say).
const network = opt('network') ?? (opt('rpc') ? (await source.rpc('getblockchaininfo').catch(() => null))?.chain : undefined) ?? 'unknown';
// --verifier test: the rule of the vectors (one proof, "valid-proof" padded with zeros, is valid), for differential runs
const TEST_PROOF = Buffer.concat([Buffer.from('valid-proof'), Buffer.alloc(480 - 11)]);
let verifier;
try {
  verifier = opt('verifier') === 'test'
    ? { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(TEST_PROOF) }
    : opt('verifier') ? plonkVerifier({ wasm: opt('verifier'), vk: opt('vk') }) : undefined;
} catch (e) {
  console.error(`error: --verifier: ${e.code === 'ENOENT' ? `no file ${e.path}` : e.message}`);
  process.exit(1);
}
// The rest of the profile, by the names indexer-rs takes: every indexer of a network must be given the same.
const profile = profileFrom(opt, { activationHeight, network });
const indexer = new Indexer({ profile, verifier });
// --data <folder>: the blocks read are kept in <folder>/blocks.jsonl (src/blockfile.js), and a restart applies them
// again from there instead of asking the source for every block since the activation height.
const held = opt('data') ? BlockFile.open(opt('data'), activationHeight) : null;
const follower = new Follower({
  indexer,
  source,
  file: held?.file ?? null,
  startHeight: activationHeight,
  confirmations: opt.int('confirmations', 0),
  log: (r) => {
    if (r.error) console.error(`error: ${r.error}`);
    else if (r.reorg) console.log(`reorg: back from ${r.from} to ${r.to}`);
    else if (r.events.length || r.rejected.length) console.log(`${r.height} accepted=${r.events.length} rejected=${r.rejected.length} digest=${r.digest}`);
  },
});

if (held) {
  const t0 = Date.now();
  follower.restore(held.blocks);
  const last = held.blocks.at(-1)?.height;
  console.log(`block file: ${held.blocks.length} blocks${last === undefined ? '' : `, up to block ${last}`}, applied in ${Date.now() - t0} ms${held.dropped ? ` (${held.dropped} lines left out)` : ''}`);
}

const server = await listen(indexer, { port: opt.int('port', 8020, 65535), host: opt('host', '127.0.0.1'), network });
console.log(`SH-20 API on http://${server.address().address}:${server.address().port} (verifier: ${indexer.verifier.name})`);
const stop = new AbortController();
process.on('SIGINT', () => {
  stop.abort();
  server.close();
});
await follower.run({ intervalMs: Math.max(1, opt.int('interval', 15)) * 1000, signal: stop.signal });
