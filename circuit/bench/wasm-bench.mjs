// Single-thread WebAssembly prover, the closest stand-in for a phone browser available on a laptop:
//   node wasm-bench.mjs <sh20_circuit.wasm> <spend.pk> [runs]
// The module has no imports: the host passes bytes in and reads bytes out.

import fs from 'node:fs';
import { randomBytes } from 'node:crypto';

const [wasmPath, pkPath, runsArg] = process.argv.slice(2);
const runs = Number(runsArg || 3);
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmPath), {});
const x = instance.exports;
const mem = () => new Uint8Array(x.memory.buffer);
const put = (bytes) => {
  const p = x.sh20_alloc(bytes.length);
  mem().set(bytes, p);
  return p;
};
const take = (p, n) => Buffer.from(mem().slice(p, p + n));
const secs = (t) => +((performance.now() - t) / 1000).toFixed(2);

const key = fs.readFileSync(pkPath);
let t = performance.now();
const keyPtr = put(key);
const pk = x.sh20_load_key(keyPtr, key.length);
x.sh20_free(keyPtr, key.length);
if (!pk) throw new Error('the proving key was refused');
const tLoad = secs(t);

const [vkPtr, digestPtr, witnessPtr, proofPtr] = [x.sh20_alloc(712), x.sh20_alloc(32), x.sh20_alloc(3232), x.sh20_alloc(480)];
x.sh20_vk(pk, vkPtr);
x.sh20_vk_digest(pk, digestPtr);
const seed = () => put(randomBytes(32));

const times = [];
let publics;
for (let i = 0; i < runs; i++) {
  x.sh20_sample_witness(seed(), witnessPtr);
  publics = put(take(witnessPtr, 9 * 32));
  t = performance.now();
  if (x.sh20_prove(pk, witnessPtr, seed(), proofPtr) !== 1) throw new Error('prove failed');
  times.push(secs(t));
}
t = performance.now();
const ok = x.sh20_verify(vkPtr, 712, publics, proofPtr, 480);
const tVerify = performance.now() - t;
mem()[publics + 7 * 32] ^= 1; // vPub
const forged = x.sh20_verify(vkPtr, 712, publics, proofPtr, 480);
if (ok !== 1 || forged !== 0) throw new Error(`verify: valid=${ok} tampered=${forged}`);

const sorted = times.slice().sort((a, b) => a - b);
console.log(
  JSON.stringify({
    system: 'plonk (Rust → wasm32, 1 thread)',
    wasm_bytes: fs.statSync(wasmPath).size,
    key_bytes: key.length,
    key_load_s: tLoad,
    prove_s: times,
    prove_min_s: sorted[0],
    prove_median_s: sorted[sorted.length >> 1],
    verify_ms: +tVerify.toFixed(1),
    proof_bytes: 480,
    wasm_memory_mb: Math.round(x.memory.buffer.byteLength / 2 ** 20),
    vk_digest: take(digestPtr, 32).toString('hex'),
  }),
);
