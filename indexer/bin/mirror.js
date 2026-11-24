#!/usr/bin/env node
// Writes the static mirror of a running indexer's API (docs/API.md, "The static mirror") into a folder, for a static
// host: pages.yml builds the site's /api/js/ and /api/rs/ with it, from follow.js and from indexer-rs follow.
//
//   node bin/mirror.js --api http://127.0.0.1:8020 --out <folder> [--esplora <url> [--wait 900]]
//
// With --esplora it first waits, --wait seconds at most, until the indexer's tip is the tip that Esplora server names:
// a follower started from its block file catches up, then the mirror is of the chain as it is.

import { buildMirror, waitForTip } from '../src/mirror.js';
import { options } from './options.js';

const USAGE = 'usage: node bin/mirror.js --api URL --out <folder> [--esplora URL [--wait 900]]';
const opt = options(process.argv.slice(2), ['api', 'out', 'esplora', 'wait'], USAGE);
opt.require('api', 'out');
const api = opt('api').replace(/\/+$/, '');
try {
  if (opt('esplora') !== undefined) await waitForTip({ api, esplora: opt('esplora'), timeoutMs: opt.int('wait', 900) * 1000, log: console.error });
  const t0 = Date.now();
  const m = await buildMirror({ api, out: opt('out') });
  console.log(`mirror of ${api}: block ${m.height}, digest ${m.digest}, ${m.files} files, ${(m.bytes / 1e6).toFixed(1)} MB, in ${Date.now() - t0} ms`);
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(1);
}
