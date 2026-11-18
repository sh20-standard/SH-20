// The threaded WebAssembly prover in Node, with the host logic the browser page uses (web/host.js):
//   node wasm-threads-bench.mjs <threaded sh20_circuit.wasm> <spend.pk> [threads] [runs]
// The main thread only creates workers: one runs the prover, the others are the threads its pool asks for.

import fs from 'node:fs';
import os from 'node:os';
import { Worker } from 'node:worker_threads';
import { importedMemory, sharedMemory } from '../web/host.js';

const [wasmPath, pkPath, threadsArg, runsArg] = process.argv.slice(2);
const threads = Number(threadsArg || os.availableParallelism());
const runs = Number(runsArg || 3);
const bytes = fs.readFileSync(wasmPath);
const module = new WebAssembly.Module(bytes);
const memory = sharedMemory(importedMemory(bytes));
const nextTid = new Int32Array(new SharedArrayBuffer(4));
const workerUrl = new URL('./wasm-threads-worker.mjs', import.meta.url);

const workers = [];
function start(data) {
  const w = new Worker(workerUrl, { workerData: { module, memory, nextTid, ...data } });
  workers.push(w);
  w.on('message', (m) => {
    if (m.spawn) start({ role: 'thread', ...m.spawn });
    else if (m.log) process.stderr.write(m.log);
    else if (m.result) {
      const sorted = m.result.prove_s.slice().sort((a, b) => a - b);
      console.log(JSON.stringify({ system: 'plonk (Rust → wasm32 threads)', wasm_bytes: bytes.length, ...m.result, prove_min_s: sorted[0], prove_median_s: sorted[sorted.length >> 1] }));
      process.exit(0);
    }
  });
  w.on('error', (e) => {
    console.error(e);
    process.exit(1);
  });
}
start({ role: 'prover', key: fs.readFileSync(pkPath), threads, runs });
