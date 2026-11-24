// The prover's random seed (docs/AUDIT.md, doubt 6.6): 32 bytes from crypto.getRandomValues for each
// proof, never reused, never derived from a key or from the witness. Before the module hashed the
// witness into its generator (the audit's verifier-3), the same seed with two witnesses gave the
// same blinding scalars and unblinded the difference of their commitments; the seed is still all
// that an observer cannot recompute.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { proveWithFreshSeed } from '../src/prover-worker.js';
import { toHex } from '../src/bytes.js';

/** A prover that records the seeds it is given (a copy, taken when it is called). */
const recorder = () => {
  const seeds = [];
  return { seeds, prove: (witness, seed) => { seeds.push(Uint8Array.from(seed)); return new Uint8Array(480); } };
};

test('each proof gets 32 fresh bytes, straight from crypto.getRandomValues', () => {
  const proto = Object.getPrototypeOf(globalThis.crypto);
  const original = proto.getRandomValues;
  const drawn = [];
  proto.getRandomValues = function (b) {
    const out = original.call(this, b);
    drawn.push(Uint8Array.from(out));
    return out;
  };
  const p = recorder();
  const witness = new Uint8Array(3232).fill(7);
  try {
    for (let i = 0; i < 64; i++) proveWithFreshSeed(p, witness); // the same witness every time
  } finally {
    proto.getRandomValues = original;
  }
  assert.equal(drawn.length, 64, 'one call to crypto.getRandomValues per proof');
  assert.equal(p.seeds.length, 64);
  p.seeds.forEach((s, i) => {
    assert.equal(s.length, 32);
    assert.equal(toHex(s), toHex(drawn[i]), 'the seed is what crypto.getRandomValues gave, nothing derived from it');
    assert.ok(s.some((x) => x !== 0));
  });
  assert.equal(new Set(p.seeds.map(toHex)).size, 64, 'never the same seed twice');
});

test('the seed does not follow the witness or the key: two provers, two witnesses, unrelated seeds', () => {
  const a = recorder();
  const b = recorder();
  proveWithFreshSeed(a, new Uint8Array(3232).fill(1));
  proveWithFreshSeed(b, new Uint8Array(3232).fill(1));
  proveWithFreshSeed(a, new Uint8Array(3232).fill(2));
  assert.notEqual(toHex(a.seeds[0]), toHex(b.seeds[0]), 'same witness, other seed');
  assert.notEqual(toHex(a.seeds[0]), toHex(a.seeds[1]));
  // a random source that gives the wrong size is refused, never padded or reused
  assert.throws(() => proveWithFreshSeed(a, new Uint8Array(3232), () => new Uint8Array(16)), /32 random bytes/);
});

test('no other path hands the prover a seed: the worker and the Node prover go through proveWithFreshSeed', () => {
  const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
  const worker = src('prover-worker.js');
  assert.match(worker, /proof: proveWithFreshSeed\(api, data\.prove\)/);
  assert.equal((worker.match(/\.prove\(/g) ?? []).length, 1, 'the one call is inside proveWithFreshSeed');
  for (const f of readdirSync(new URL('../src/', import.meta.url), { recursive: true }).filter((x) => x.endsWith('.js') && x !== 'prover-worker.js')) {
    assert.ok(!/sh20_prove|\.prove\([^)]*,/.test(src(f)), `${f} calls the prover with a seed of its own`);
  }
  assert.match(readFileSync(new URL('./prover-node.js', import.meta.url), 'utf8'), /proveWithFreshSeed\(api, witness\)/);
});
