// A Node worker of the threaded prover: either the first instance, which loads the key and proves
// ('prover'), or one thread of its pool ('thread'). See web/host.js.

import { parentPort, workerData } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';
import { proverApi, threadedImports } from '../web/host.js';

const { role, module, memory, nextTid } = workerData;
const imports = threadedImports({
  memory,
  nextTid,
  spawn: (tid, startArg) => parentPort.postMessage({ spawn: { tid, startArg } }),
  log: (text) => parentPort.postMessage({ log: text }),
  random: (chunk) => webcrypto.getRandomValues(chunk),
});
const { exports } = new WebAssembly.Instance(module, imports);

if (role === 'thread') {
  exports.wasi_thread_start(workerData.tid, workerData.startArg);
} else {
  const secs = (t) => +((performance.now() - t) / 1000).toFixed(2);
  const seed = () => webcrypto.getRandomValues(new Uint8Array(32));
  exports.__wasi_init_tp();
  exports.__wasm_call_ctors();
  const api = proverApi(exports, memory);
  const threads = api.threads(workerData.threads);

  let t = performance.now();
  api.loadKey(workerData.key);
  const keyLoad = secs(t);
  const times = [];
  let witness;
  let proof;
  for (let i = 0; i < workerData.runs; i++) {
    witness = api.sampleWitness(seed());
    t = performance.now();
    proof = api.prove(witness, seed());
    times.push(secs(t));
    if (!proof) throw new Error('prove failed');
  }
  const publics = witness.slice(0, 9 * 32);
  t = performance.now();
  const ok = api.verify(publics, proof);
  const verifyMs = +(performance.now() - t).toFixed(1);
  publics[7 * 32] ^= 1;
  if (!ok || api.verify(publics, proof)) throw new Error('verification mismatch');
  parentPort.postMessage({ result: { threads, key_load_s: keyLoad, prove_s: times, verify_ms: verifyMs, wasm_memory_mb: Math.round(api.memoryBytes() / 2 ** 20), vk_digest: api.vkDigest() } });
}
