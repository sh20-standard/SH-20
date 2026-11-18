// Measures a snarkjs prover (PLONK or fflonk) on the SH-20 spend circuit.
//
//   node prove-snarkjs.mjs <plonk|fflonk> <zkey> <wasm> [runs] [--single]
//
// Prints witness time, proving time per run, verification time and the proof size, both as snarkjs
// prints it (uncompressed points) and in the wire encoding SH-20 would use (32 bytes per G1 point:
// x little-endian with the sign of y in the top bit; 32 bytes per scalar).

import * as snarkjs from 'snarkjs';
import fs from 'node:fs';
import { init, buildSpend } from './model.mjs';

const [system, zkeyPath, wasmPath, runsArg, ...rest] = process.argv.slice(2);
const runs = Number(runsArg || 3);
const single = rest.includes('--single');
const impl = snarkjs[system];
if (!impl) throw new Error('system must be plonk or fflonk');

const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const le32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();

/** G1 points and scalars of a snarkjs proof, in the order snarkjs lists them. */
function split(proof) {
  const points = [];
  const scalars = [];
  const walk = (v) => {
    if (Array.isArray(v) && v.length === 3 && v.every((x) => typeof x === 'string')) points.push(v.map(BigInt));
    else if (typeof v === 'string' && /^[0-9]+$/.test(v)) scalars.push(BigInt(v));
  };
  for (const [k, v] of Object.entries(proof)) {
    if (k === 'protocol' || k === 'curve') continue;
    if (v && typeof v === 'object' && !Array.isArray(v)) for (const x of Object.values(v)) walk(x);
    else walk(v);
  }
  return { points, scalars };
}

function encode(proof, { skip = [] } = {}) {
  const pruned = structuredClone(proof);
  for (const path of skip) {
    const [a, b] = path.split('.');
    if (b) delete pruned[a]?.[b];
    else delete pruned[a];
  }
  const { points, scalars } = split(pruned);
  const out = [];
  for (const [x, y] of points) {
    const b = le32(x);
    if (y > Q - y) b[31] |= 0x80;
    out.push(b);
  }
  for (const s of scalars) out.push(le32(s));
  return { bytes: Buffer.concat(out), nPoints: points.length, nScalars: scalars.length };
}

await init();
const { input, publics } = buildSpend();

let t = performance.now();
const wtns = { type: 'mem' };
await snarkjs.wtns.calculate(input, wasmPath, wtns);
const tWitness = (performance.now() - t) / 1000;

const opts = single ? { singleThread: true } : undefined;
const times = [];
let out;
for (let i = 0; i < runs; i++) {
  t = performance.now();
  out = await impl.prove(zkeyPath, wtns, undefined, opts);
  times.push((performance.now() - t) / 1000);
}
if (JSON.stringify(out.publicSignals) !== JSON.stringify(publics)) throw new Error('public signals differ from the verifier order');

const vk = await snarkjs.zKey.exportVerificationKey(zkeyPath);
t = performance.now();
const ok = await impl.verify(vk, out.publicSignals, out.proof);
const tVerify = (performance.now() - t) / 1000;
const badPublics = out.publicSignals.slice();
badPublics[7] = (BigInt(badPublics[7]) + 1n).toString();
const forged = await impl.verify(vk, badPublics, out.proof);
if (!ok || forged) throw new Error(`verify: valid=${ok} tampered=${forged}`);

// fflonk's `inv` is a helper for the Solidity verifier (a batch inverse the verifier can recompute)
const wire = encode(out.proof, { skip: system === 'fflonk' ? ['evaluations.inv'] : [] });
const raw = encode(out.proof);
const sorted = times.slice().sort((a, b) => a - b);
console.log(
  JSON.stringify({
    system,
    threads: single ? 1 : 'all',
    witness_s: +tWitness.toFixed(2),
    prove_s: times.map((x) => +x.toFixed(2)),
    prove_min_s: +sorted[0].toFixed(2),
    prove_median_s: +sorted[sorted.length >> 1].toFixed(2),
    verify_ms: +(tVerify * 1000).toFixed(0),
    proof_wire_bytes: wire.bytes.length,
    proof_points: wire.nPoints,
    proof_scalars: wire.nScalars,
    proof_snarkjs_uncompressed_bytes: raw.nPoints * 64 + raw.nScalars * 32,
    zkey_bytes: fs.statSync(zkeyPath).size,
    rss_peak_mb: Math.round(process.resourceUsage().maxRSS / 1024),
  }),
);
process.exit(0);
