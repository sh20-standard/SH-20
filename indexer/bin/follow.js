#!/usr/bin/env node
// Follows a chain live and serves the read-only API.
//
//   node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation H [--port 8020]
//   node bin/follow.js --esplora https://mempool.space/signet/api --activation H [--port 8020]
//
// Your own node (--rpc) is the trust-minimised choice: an Esplora server is
// trusted to name the best chain, even though every envelope is re-checked here.
// Spends (TRANSFER, BURN, LIST, later DEPLOYs) are rejected unless --verifier names the
// WebAssembly build of circuit/ (cd circuit && ./build-wasm.sh). That verifier is not audited yet.

import { Indexer } from '../src/indexer.js';
import { BitcoindSource, EsploraSource, Follower } from '../src/follower.js';
import { listen } from '../src/api.js';
import { plonkVerifier } from '../src/adapters/plonk.js';

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};

const activationHeight = Number(opt('activation', NaN));
if (!Number.isInteger(activationHeight)) {
  console.error('usage: node bin/follow.js (--rpc URL [--rpcuser U --rpcpass P] | --esplora URL) --activation HEIGHT [--port 8020] [--host 127.0.0.1] [--network signet] [--confirmations 0] [--interval 15] [--verifier sh20_circuit.wasm [--vk spend.vk]]');
  process.exit(1);
}

let source;
if (opt('rpc')) source = new BitcoindSource(opt('rpc'), { user: opt('rpcuser', ''), pass: opt('rpcpass', '') });
else if (opt('esplora')) source = new EsploraSource(opt('esplora'));
else {
  console.error('give --rpc or --esplora');
  process.exit(1);
}

const network = opt('network', 'signet');
const verifier = opt('verifier') ? plonkVerifier({ wasm: opt('verifier'), vk: opt('vk') }) : undefined;
const indexer = new Indexer({ profile: { activationHeight, network }, verifier });
const follower = new Follower({
  indexer,
  source,
  startHeight: activationHeight,
  confirmations: Number(opt('confirmations', 0)),
  log: (r) => {
    if (r.error) console.error(`error: ${r.error}`);
    else if (r.reorg) console.log(`reorg: back from ${r.from} to ${r.to}`);
    else if (r.events.length || r.rejected.length) console.log(`${r.height} accepted=${r.events.length} rejected=${r.rejected.length} digest=${r.digest}`);
  },
});

const server = await listen(indexer, { port: Number(opt('port', 8020)), host: opt('host', '127.0.0.1'), network });
console.log(`SH-20 API on http://${server.address().address}:${server.address().port} (verifier: ${indexer.verifier.name})`);
const stop = new AbortController();
process.on('SIGINT', () => {
  stop.abort();
  server.close();
});
await follower.run({ intervalMs: Number(opt('interval', 15)) * 1000, signal: stop.signal });
