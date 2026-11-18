// The prover, off the page's main thread. One message starts a whole measurement:
//   { mode: 'threads', module, memory, nextTid, threads, key, runs }   threaded build, shared memory
//   { mode: 'single',  module, key, runs }                             single-thread build
//   { mode: 'sweep',   module, memory, nextTid, order, passes, key }    threaded build, one proof per
//                                                                       thread count of `order`, `passes` times
//   { mode: 'keyload', variant, module, key, proofs, [memory, nextTid] }  one thread, in a fresh instance:
//                                                                       the key loaded twice, then `proofs` proofs
//   { mode: 'growth',  totalMb, stepMb, shared }                        no prover: what growing a memory costs here
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

/** One proof per thread count, in the given order, several times over; the key is loaded again each time. */
function sweep({ module, memory, nextTid, order, passes, key }) {
  let t = performance.now();
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
  const api = proverApi(exports, memory);
  const instantiateMs = ms(t);
  self.postMessage({ step: 'instantiated', instantiate_ms: instantiateMs, threads: 0 });

  const runs = [];
  let last;
  for (let pass = 1; pass <= passes; pass++) {
    for (const n of order) {
      const threads = api.pool(n);
      if (threads !== n) throw new Error(`asked for ${n} threads, got ${threads}`);
      api.freeKey();
      t = performance.now();
      api.loadKey(key);
      const keyLoadMs = ms(t);
      const witness = api.sampleWitness(seed());
      t = performance.now();
      const proof = api.prove(witness, seed());
      const proveMs = ms(t);
      if (!proof) throw new Error('the prover rejected its own sample witness');
      const phases = api.timings();
      const round = (x) => Math.round(x * 1000);
      const run = {
        pass,
        threads,
        key_load_ms: keyLoadMs,
        prove_ms: proveMs,
        msm_ms: round(phases.msm),
        fft_ms: round(phases.fft),
        quotient_ms: round(phases.quotient),
        other_ms: round(phases.other),
        memory_mb: Math.round(api.memoryBytes() / 2 ** 20),
      };
      runs.push(run);
      last = { witness, proof };
      self.postMessage({ step: 'sweep', run, done: runs.length, total: passes * order.length });
    }
  }
  const publics = last.witness.slice(0, 9 * 32);
  const valid = api.verify(publics, last.proof);
  publics[7 * 32] ^= 1;
  if (!valid || api.verify(publics, last.proof)) throw new Error('verification mismatch');
  self.postMessage({ result: { mode: 'sweep', order, passes, instantiate_ms: instantiateMs, runs, vk_digest: api.vkDigest(), proof_bytes: last.proof.length } });
}

/**
 * Key loading on one thread, from a cold start. Three variants, to tell what the first load pays for:
 *   grow      the single-thread build as it is: its memory grows as the prover allocates
 *   reserved  the same build, after one reservation of the whole heap
 *   shared    the threaded build on a shared memory (reserved by the engine, never moved), one thread
 * The second load runs on warm code in a memory that is already large: what loading costs by itself.
 */
function keyload({ variant, module, memory, nextTid, key, proofs }) {
  let t = performance.now();
  let api;
  if (variant === 'shared') {
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
    if (api.pool(1) !== 1) throw new Error('no pool of one thread');
  } else {
    api = proverApi(new WebAssembly.Instance(module, {}).exports);
  }
  const mb = () => Math.round(api.memoryBytes() / 2 ** 20);
  const run = { variant, instantiate_ms: ms(t), memory_mb_start: mb(), reserved_mb: 0, reserve_ms: 0 };

  if (variant === 'reserved') {
    t = performance.now();
    run.reserved_mb = Math.round(api.reserve() / 2 ** 20);
    run.reserve_ms = ms(t);
  }
  t = performance.now();
  api.loadKey(key);
  run.key_load_ms = ms(t);
  run.memory_mb_key = mb();
  api.freeKey();
  t = performance.now();
  api.loadKey(key);
  run.key_reload_ms = ms(t);
  self.postMessage({ step: 'keyload', run: { ...run } });

  run.prove_ms = [];
  for (let i = 0; i < proofs; i++) {
    const witness = api.sampleWitness(seed());
    t = performance.now();
    const proof = api.prove(witness, seed());
    run.prove_ms.push(ms(t));
    const publics = witness.slice(0, 9 * 32);
    if (!proof || !api.verify(publics, proof)) throw new Error('the proof does not verify');
    self.postMessage({ step: 'keyload-proof', variant, run: i + 1, runs: proofs, prove_ms: run.prove_ms[i] });
  }
  run.memory_mb_end = mb();
  self.postMessage({ result: run });
}

/**
 * What growing a WebAssembly memory costs in this engine, without the prover: `totalMb` reached in steps
 * of `stepMb`, every new page written once, as an allocator that is filling its heap does. An engine that
 * grows in place takes the time of the writes; one that moves the memory at each growth copies
 * totalMb² / (2 × stepMb) megabytes on top.
 */
function growth({ totalMb, stepMb, shared }) {
  const PAGES_PER_MB = 16;
  const t = performance.now();
  const memory = new WebAssembly.Memory(shared ? { initial: PAGES_PER_MB, maximum: totalMb * PAGES_PER_MB, shared: true } : { initial: PAGES_PER_MB });
  const touch = (fromMb, toMb) => {
    const bytes = new Uint8Array(memory.buffer);
    for (let o = fromMb * 2 ** 20; o < toMb * 2 ** 20; o += 4096) bytes[o] = 1;
  };
  touch(0, 1);
  let grows = 0;
  for (let at = 1; at < totalMb; at += stepMb) {
    const step = Math.min(stepMb, totalMb - at);
    memory.grow(step * PAGES_PER_MB);
    grows++;
    touch(at, at + step);
  }
  self.postMessage({ result: { total_mb: totalMb, step_mb: stepMb, shared, grows, ms: ms(t) } });
}

function run(job) {
  if (job.mode === 'sweep') return sweep(job);
  if (job.mode === 'keyload') return keyload(job);
  if (job.mode === 'growth') return growth(job);
  const { mode, module, memory, nextTid, threads, key, runs } = job;
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
