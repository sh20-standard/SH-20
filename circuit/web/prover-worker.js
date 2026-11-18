// The prover, off the page's main thread. One message starts a whole measurement:
//   { mode: 'threads', module, memory, nextTid, threads, key, runs }   threaded build, shared memory
//   { mode: 'single',  module, key, runs }                             single-thread build
// and progress comes back as { step, ... } messages, then { result } or { error }.

import { proverApi, threadedImports } from './host.js';

const ms = (t) => Math.round(performance.now() - t);
const seed = () => crypto.getRandomValues(new Uint8Array(32));

self.onmessage = ({ data }) => {
  try {
    run(data);
  } catch (e) {
    self.postMessage({ error: String(e && e.message ? e.message : e) });
  }
};

function run({ mode, module, memory, nextTid, threads, key, runs }) {
  let t = performance.now();
  let api;
  let poolThreads = 1;
  if (mode === 'threads') {
    const imports = threadedImports({
      memory,
      nextTid,
      spawn: (tid, startArg) => self.postMessage({ spawn: { tid, startArg } }),
      log: (text) => self.postMessage({ log: text }),
      random: (chunk) => crypto.getRandomValues(chunk),
    });
    const { exports } = new WebAssembly.Instance(module, imports);
    exports.__wasi_init_tp();
    exports.__wasm_call_ctors();
    api = proverApi(exports, memory);
    poolThreads = api.threads(threads);
  } else {
    api = proverApi(new WebAssembly.Instance(module, {}).exports);
  }
  const instantiateMs = ms(t);
  self.postMessage({ step: 'instantiated', instantiate_ms: instantiateMs, threads: poolThreads });

  t = performance.now();
  api.loadKey(key);
  const keyLoadMs = ms(t);
  const vkDigest = api.vkDigest();
  self.postMessage({ step: 'key', key_load_ms: keyLoadMs, vk_digest: vkDigest });

  const proveMs = [];
  let witness;
  let proof;
  for (let i = 0; i < runs; i++) {
    witness = api.sampleWitness(seed());
    t = performance.now();
    proof = api.prove(witness, seed());
    if (!proof) throw new Error('the prover rejected its own sample witness');
    proveMs.push(ms(t));
    self.postMessage({ step: 'proof', run: i + 1, runs, prove_ms: proveMs[i], memory_mb: Math.round(api.memoryBytes() / 2 ** 20) });
  }

  const publics = witness.slice(0, 9 * 32);
  t = performance.now();
  const valid = api.verify(publics, proof);
  const verifyMs = +(performance.now() - t).toFixed(1);
  publics[7 * 32] ^= 1; // another public amount
  const forged = api.verify(publics, proof);
  if (!valid || forged) throw new Error(`verification mismatch (valid=${valid}, tampered=${forged})`);

  self.postMessage({
    result: {
      mode,
      threads: poolThreads,
      instantiate_ms: instantiateMs,
      key_load_ms: keyLoadMs,
      prove_ms: proveMs,
      verify_ms: verifyMs,
      proof_bytes: proof.length,
      memory_mb: Math.round(api.memoryBytes() / 2 ** 20),
      vk_digest: vkDigest,
    },
  });
}
