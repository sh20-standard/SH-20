// The spend prover in the browser, loaded on demand: the two WebAssembly builds of circuit/ (vault/prover/,
// built by tools/prover.sh) and the shipped proving key (circuit/artifacts/spend.pk, which the module
// checks against its pinned hash). Same wiring as the phone test page (circuit/web): the threaded
// build on a pool of Workers when the page is cross-origin isolated (shared memory), else the
// single-thread build in one Worker. Nothing is fetched from another origin.

import { importedMemory, sharedMemory } from '../../circuit/web/host.js';
import { SPEND_VK_DIGEST } from './sh20.js';

const url = (p) => new URL(p, import.meta.url);
export const canShare = () => globalThis.crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';

async function fetchBytes(path) {
  const r = await fetch(url(path));
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

let loading = null;

/**
 * The prover, loaded once: { mode, threads, prove(witness) → proof, verify(publics, proof) → bool }.
 * `onStatus(text)` reports the steps (download, key, ready).
 */
export function loadProver({ onStatus = () => {} } = {}) {
  return (loading ??= start(onStatus).catch((e) => {
    loading = null;
    throw e;
  }));
}

async function start(onStatus) {
  const mode = canShare() ? 'threads' : 'single';
  onStatus(`Downloading the prover (${mode === 'threads' ? 'thread pool' : 'one thread: this page is not cross-origin isolated'})…`);
  const [wasm, key] = await Promise.all([
    fetchBytes(mode === 'threads' ? '../prover/sh20_circuit_threads.wasm' : '../prover/sh20_circuit.wasm'),
    fetchBytes('../../circuit/artifacts/spend.pk'),
  ]);
  const module = await WebAssembly.compile(wasm);
  const worker = new Worker(url('./prover-worker.js'), { type: 'module' });
  const job = { mode, module, key };
  if (mode === 'threads') {
    job.memory = sharedMemory(importedMemory(wasm));
    job.nextTid = new Int32Array(new SharedArrayBuffer(4));
    job.threads = Math.max(1, Math.min(16, navigator.hardwareConcurrency || 4));
  }
  const pending = new Map();
  let id = 0;
  let ready;
  const readyP = new Promise((resolve, reject) => { ready = { resolve, reject }; });
  worker.onmessage = ({ data }) => {
    if (data.spawn) {
      // a thread of the pool: its own instance of the module on the same memory (circuit/web)
      const thread = new Worker(url('../../circuit/web/thread-worker.js'), { type: 'module' });
      thread.onmessage = worker.onmessage;
      thread.postMessage({ module, memory: job.memory, nextTid: job.nextTid, ...data.spawn });
    } else if (data.ready) ready.resolve(data.ready);
    else if (data.id !== undefined && pending.has(data.id)) {
      const p = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) p.reject(new Error(data.error));
      else p.resolve(data);
    } else if (data.error) ready.reject(new Error(data.error));
  };
  worker.onerror = (e) => ready.reject(new Error(e.message || 'the prover worker failed'));
  onStatus('Loading the proving key…');
  worker.postMessage({ init: job });
  const info = await readyP;
  if (info.vkDigest !== SPEND_VK_DIGEST) throw new Error(`the proving key gives verifying key ${info.vkDigest}, not the pinned ${SPEND_VK_DIGEST}`);
  const call = (msg) => new Promise((resolve, reject) => {
    pending.set(++id, { resolve, reject });
    worker.postMessage({ id, ...msg });
  });
  onStatus(`Prover ready on ${info.threads} thread${info.threads > 1 ? 's' : ''}.`);
  return {
    mode,
    threads: info.threads,
    prove: async (witness) => (await call({ prove: witness })).proof,
    verify: async (publics, proof) => (await call({ verify: { publics, proof } })).ok,
  };
}
