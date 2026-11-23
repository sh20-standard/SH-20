#!/usr/bin/env node
// The reference relayer (docs/RELAYER.md):
//
//   node relayer/bin/relayer.js --indexer <url> --esplora <url> --fee SH20=10 [--fee TICK=n …]
//        [--words <file>] [--btc-key <file>] [--port 8040] [--host 127.0.0.1]
//        [--max-batch 10] [--max-wait 600] [--min-blocks-left 12] [--max-fee-rate 50] [--verifier <wasm>]
//
// --indexer is the relayer's own indexer (indexer/bin/follow.js on the profile it relays for): it
// trusts it for the tip, the roots, the nullifiers and W and K_min. --words holds the twelve words
// its fees are sealed to (restore the vault from them to spend what it earned); --btc-key the hex of
// the 32-byte Bitcoin key that pays the commits (fund the address it prints). Either file is made,
// readable by its owner only, when it does not exist. The queue lives in memory.

import { createServer } from 'node:http';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { IndexerApi, Esplora } from '../../vault/src/api.js';
import { newMnemonic } from '../../vault/src/bip39.js';
import { oneTimeSecret } from '../../vault/src/taproot.js';
import { fromHex, toHex } from '../../vault/src/bytes.js';
import { relayerKeys } from '../src/keys.js';
import { Relayer, DEFAULTS } from '../src/relayer.js';
import { relayerHandler } from '../src/http.js';

const argv = process.argv.slice(2);
const arg = (k, d) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : d);
const all = (k) => argv.flatMap((a, i) => (a === k ? [argv[i + 1]] : []));
const need = (k) => arg(k) ?? (console.error(`${k} is required (see the head of this file)`), process.exit(2));

function secretFile(path, make) {
  if (!existsSync(path)) {
    writeFileSync(path, make() + '\n', { mode: 0o600, flag: 'wx' });
    console.log(`wrote a new secret to ${path}: keep a copy`);
  }
  return readFileSync(path, 'utf8').trim();
}

const fees = new Map(all('--fee').map((f) => {
  const m = String(f).match(/^([A-Z0-9]{4})=(\d+)$/);
  if (!m) throw new Error(`--fee takes TICK=amount, not ${f}`);
  return [m[1], BigInt(m[2])];
}));
if (!fees.size) throw new Error('give at least one --fee TICK=amount: the tickers this relayer is paid in');

const keys = await relayerKeys({
  words: secretFile(arg('--words', 'relayer-words.txt'), newMnemonic),
  btcSecret: fromHex(secretFile(arg('--btc-key', 'relayer-btc.key'), () => toHex(oneTimeSecret()))),
});
const verifier = plonkVerifier({ wasm: arg('--verifier', new URL('../../vault/prover/sh20_circuit.wasm', import.meta.url).pathname) });
const relayer = new Relayer({
  keys, fees, verifier,
  indexer: new IndexerApi(need('--indexer')),
  esplora: new Esplora(need('--esplora')),
  maxBatch: Number(arg('--max-batch', DEFAULTS.maxBatch)),
  maxWaitSeconds: Number(arg('--max-wait', DEFAULTS.maxWaitSeconds)),
  minBlocksLeft: Number(arg('--min-blocks-left', DEFAULTS.minBlocksLeft)),
  maxFeeRate: Number(arg('--max-fee-rate', DEFAULTS.maxFeeRate)),
  log: (s) => console.log(s),
});

const tick = () => relayer.tick().catch((e) => console.error(`publish: ${e.message}`));
const port = Number(arg('--port', 8040));
createServer(relayerHandler(relayer, { onSubmitted: tick })).listen(port, arg('--host', '127.0.0.1'));
setInterval(tick, 10_000);
console.log(`relayer on :${port}: fees sealed to ${keys.notes.addressString}; commits paid from ${keys.btc.address}`);
console.log(`takes ${[...fees].map(([t, v]) => `${v} ${t}`).join(', ')} a transfer; batches of ${relayer.maxBatch}, at most ${relayer.maxWaitSeconds} s of waiting`);
