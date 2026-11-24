#!/usr/bin/env node
// The site's mirror of both indexers (docs/PLAN.md, decision 3; docs/API.md, "The static mirror"): what pages.yml runs
// on a schedule. Both followers start from their block files, follow the Esplora server to its tip, each mirror is
// written, and both stop, so that the block files are whole for the next run.
//
//   node bin/mirror-site.js --esplora URL --rs <sh20-indexer-rs> --activation A --deploy-burn D
//       [--window W] [--min-depth K] [--maturity N] [--network signet]
//       [--verifier-js <sh20_circuit.wasm | test>] [--verifier-rs <plonk-bn254-hermez | test>]
//       --data <folder> --out <folder> [--wait 900]
//
// Writes <out>/js and <out>/rs; keeps the block files in <data>/js and <data>/rs. Any failure (a follower that stops,
// a tip not reached in --wait seconds) exits 1 with nothing written, so the site keeps the mirror it had.

import { spawn } from 'node:child_process';
import { mkdirSync, renameSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildMirror, waitForTip } from '../src/mirror.js';
import { options } from './options.js';

const here = dirname(fileURLToPath(import.meta.url));

const freePort = async () => {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
};

function start(name, command, args, log) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let tail = '';
  const keep = (d) => {
    tail = (tail + d).slice(-4000);
    for (const line of String(d).split('\n')) if (line.trim()) log(`[${name}] ${line}`);
  };
  child.stdout.on('data', keep);
  child.stderr.on('data', keep);
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  return {
    name,
    // rejects if the follower stops before it is told to
    died: exited.then(({ code, signal }) => {
      throw new Error(`${name} stopped (${signal ?? `exit ${code}`}):\n${tail}`);
    }),
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill('SIGINT');
      const t = setTimeout(() => child.kill('SIGKILL'), 10_000);
      await exited;
      clearTimeout(t);
    },
  };
}

/**
 * Runs both followers, waits for the tip, writes both mirrors. `profile` is the list of profile flags both take
 * (`--activation`, `--deploy-burn`, …), as they would be typed.
 */
export async function mirrorSite({ esplora, rs, profile, network = 'signet', verifierJs, verifierRs, data, out, waitMs = 900_000, log = console.error }) {
  const [p1, p2] = [await freePort(), await freePort()];
  const followers = [
    start('js', process.execPath, [
      join(here, 'follow.js'), '--esplora', esplora, ...profile, '--network', network, '--data', join(data, 'js'),
      '--host', '127.0.0.1', '--port', String(p1), '--interval', '5', ...(verifierJs ? ['--verifier', verifierJs] : []),
    ], log),
    start('rs', rs, [
      'follow', '--esplora', esplora, ...profile, '--network', network, '--data', join(data, 'rs'),
      '--listen', `127.0.0.1:${p2}`, '--poll', '5', ...(verifierRs ? ['--verifier', verifierRs] : []),
    ], log),
  ];
  const apis = [`http://127.0.0.1:${p1}`, `http://127.0.0.1:${p2}`];
  try {
    const work = (async () => {
      await Promise.all(apis.map((api) => waitForTip({ api, esplora, timeoutMs: waitMs, log })));
      // both mirrors in a sibling folder first: <out> gets both or keeps what it had
      const next = `${out.replace(/\/+$/, '')}.building-${process.pid}`;
      rmSync(next, { recursive: true, force: true });
      const built = [];
      for (const [i, api] of apis.entries()) built.push(await buildMirror({ api, out: join(next, followers[i].name) }));
      rmSync(out, { recursive: true, force: true });
      mkdirSync(dirname(out), { recursive: true });
      renameSync(next, out);
      return built;
    })();
    const built = await Promise.race([work, ...followers.map((f) => f.died)]);
    for (const [i, m] of built.entries()) log(`mirror ${followers[i].name}: block ${m.height}, digest ${m.digest}, ${m.files} files, ${(m.bytes / 1e6).toFixed(1)} MB`);
    if (built[0].height === built[1].height && built[0].digest !== built[1].digest) {
      log(`the two indexers disagree at block ${built[0].height}: the explorer shows it (docs/SIGNET.md, "When the run stops")`);
    }
    return built;
  } finally {
    for (const f of followers) f.died.catch(() => {});
    await Promise.all(followers.map((f) => f.stop()));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const USAGE = 'usage: node bin/mirror-site.js --esplora URL --rs <sh20-indexer-rs> --activation A --deploy-burn D [--window W] [--min-depth K] [--maturity N] [--network signet] [--verifier-js WASM|test] [--verifier-rs NAME|test] --data <folder> --out <folder> [--wait 900]';
  const PROFILE = ['activation', 'deploy-burn', 'window', 'min-depth', 'maturity'];
  const opt = options(process.argv.slice(2), ['esplora', 'rs', ...PROFILE, 'network', 'verifier-js', 'verifier-rs', 'data', 'out', 'wait'], USAGE);
  opt.require('esplora', 'rs', 'activation', 'deploy-burn', 'data', 'out');
  // checked here as follow.js checks them, so that a typo stops the run before two followers start
  opt.int('activation');
  opt.u64('deploy-burn');
  for (const f of ['window', 'min-depth', 'maturity']) opt.int(f);
  const profile = PROFILE.flatMap((f) => (opt(f) === undefined ? [] : [`--${f}`, opt(f)]));
  try {
    await mirrorSite({
      esplora: opt('esplora'), rs: opt('rs'), profile, network: opt('network', 'signet'),
      verifierJs: opt('verifier-js'), verifierRs: opt('verifier-rs'), data: opt('data'), out: opt('out'),
      waitMs: opt.int('wait', 900) * 1000,
    });
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(1);
  }
}
