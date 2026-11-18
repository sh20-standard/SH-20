// The prover modules the vault ships (vault/prover/, tools/prover.sh): no machine path inside
// (CLAUDE.md, hard requirement 5), the pinned verifying key, and the browser files in the site.
// `SH20_PROVER_CHECK=1 npm test` also rebuilds them from circuit/ and requires the same bytes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { site, fsReader, PROVER } from '../build.js';
import { nodeProver } from './prover-node.js';
import { SPEND_VK_DIGEST } from '../src/sh20.js';

const file = (f) => new URL(`../prover/${f}`, import.meta.url);

test('the shipped prover modules name no machine path, and give the pinned verifying key', () => {
  const repo = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
  for (const f of PROVER) {
    const text = readFileSync(file(f)).toString('latin1');
    for (const p of [homedir(), repo]) assert.ok(!text.includes(p), `${f} contains ${p}`);
    assert.match(text, /\/cargo\/registry\//, `${f} was built with the remapped paths`);
  }
  assert.equal(nodeProver().vkDigest, SPEND_VK_DIGEST);
});

test('the site carries the prover: both builds, the proving key, host.js and the pool thread', () => {
  const paths = site(fsReader()).map(([p]) => p);
  for (const p of ['vault/prover/sh20_circuit.wasm', 'vault/prover/sh20_circuit_threads.wasm', 'circuit/artifacts/spend.pk',
    'circuit/web/host.js', 'circuit/web/thread-worker.js', 'vault/src/prover.js', 'vault/src/prover-worker.js']) assert.ok(paths.includes(p), p);
});

test('the committed modules are what circuit/ builds', { skip: process.env.SH20_PROVER_CHECK ? false : 'set SH20_PROVER_CHECK=1 (rebuilds the circuit, about a minute)' }, () => {
  const out = execFileSync(fileURLToPath(new URL('../tools/prover.sh', import.meta.url)), ['--check'], { encoding: 'utf8' });
  assert.match(out, /^OK/m);
});
