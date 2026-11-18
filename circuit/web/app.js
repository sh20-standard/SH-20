// The phone test page: proves a sample SH-20 spend on this device and reports the timings.
//
// Two ways to prove. With cross-origin isolation (COOP/COEP headers, or sw.js standing in for them)
// the page has SharedArrayBuffer and runs the threaded build on a pool of Workers. Without it, the
// single-thread build runs in one Worker. `?auto=threads|single&runs=N&threads=N` starts by itself.

import { importedMemory, sharedMemory } from './host.js';

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const cores = navigator.hardwareConcurrency || 1;
const canShare = () => self.crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';

// ── cross-origin isolation, with the service worker as a fallback ──

async function ensureIsolation() {
  if (canShare()) return 'headers';
  if (!window.isSecureContext || !('serviceWorker' in navigator)) return 'unavailable';
  try {
    const registration = await navigator.serviceWorker.register('./sw.js');
    if (navigator.serviceWorker.controller) return 'refused'; // already controlled and still not isolated
    if (sessionStorage.getItem('sh20-isolation-reload')) return 'refused';
    sessionStorage.setItem('sh20-isolation-reload', '1');
    await new Promise((done) => {
      const worker = registration.installing || registration.waiting || registration.active;
      if (!worker || worker.state === 'activated') done();
      else worker.addEventListener('statechange', () => worker.state === 'activated' && done());
    });
    location.reload(); // the reloaded page is served through the service worker, with the headers
    return 'reloading';
  } catch {
    return 'unavailable';
  }
}

function describeDevice(isolation) {
  const rows = [
    ['Browser', navigator.userAgent],
    ['Logical cores', String(cores)],
    ['Device memory', navigator.deviceMemory ? `${navigator.deviceMemory} GB (as reported)` : 'not reported'],
    ['Shared memory', canShare() ? 'available' : 'not available'],
  ];
  $('device').replaceChildren(
    ...rows.flatMap(([k, v]) => {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      dd.textContent = v;
      return [dt, dd];
    }),
  );
  const notes = {
    headers: 'Cross-origin isolated by the server: the threaded prover can run.',
    'service-worker': 'Cross-origin isolated by the page’s service worker: the threaded prover can run.',
    refused: 'This browser did not grant cross-origin isolation, so only one thread is available.',
    unavailable: window.isSecureContext
      ? 'No cross-origin isolation here, so only one thread is available.'
      : 'This page is served over plain http, which browsers do not treat as secure: only one thread is available. Serve it over https to measure all cores.',
  };
  $('isolation-note').textContent = notes[isolation] || '';
}

// ── one measurement ──

const log = (label, value = '', cls = '') => {
  const li = document.createElement('li');
  if (cls) li.className = cls;
  const a = document.createElement('span');
  a.textContent = label;
  li.append(a);
  if (value !== '') {
    const b = document.createElement('span');
    b.textContent = value;
    li.append(b);
  }
  $('log').append(li);
  li.scrollIntoView({ block: 'nearest' });
};
const seconds = (ms) => `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;

async function download(url) {
  const t = performance.now();
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  return { bytes, ms: Math.round(performance.now() - t) };
}

let running = false;
async function measure(mode) {
  if (running) return;
  running = true;
  for (const id of ['run-threads', 'run-single']) $(id).disabled = true;
  $('log').replaceChildren();
  $('progress').hidden = false;
  $('result').hidden = true;
  const runs = Number($('runs').value);
  const threads = mode === 'threads' ? Number($('threads').value) : 1;
  const workers = [];
  try {
    const wasm = await download(mode === 'threads' ? './sh20_circuit_threads.wasm' : './sh20_circuit.wasm');
    log(`Prover downloaded (${(wasm.bytes.length / 2 ** 20).toFixed(1)} MB)`, seconds(wasm.ms));
    const key = await download('./spend.pk');
    log(`Proving key downloaded (${(key.bytes.length / 2 ** 20).toFixed(1)} MB)`, seconds(key.ms));

    let t = performance.now();
    const module = await WebAssembly.compile(wasm.bytes);
    const compileMs = Math.round(performance.now() - t);
    log('Prover compiled', seconds(compileMs));

    const job = { mode, module, key: key.bytes, runs };
    if (mode === 'threads') {
      job.memory = sharedMemory(importedMemory(wasm.bytes));
      job.nextTid = new Int32Array(new SharedArrayBuffer(4));
      job.threads = threads;
    }

    const result = await new Promise((resolve, reject) => {
      const listen = (worker) => {
        workers.push(worker);
        worker.onerror = (e) => reject(new Error(e.message || 'a worker failed'));
        worker.onmessage = ({ data }) => {
          if (data.spawn) {
            // a thread of the pool: its own instance of the module on the same memory
            const thread = new Worker(new URL('./thread-worker.js', import.meta.url), { type: 'module' });
            listen(thread);
            thread.postMessage({ module, memory: job.memory, nextTid: job.nextTid, ...data.spawn });
          } else if (data.log) console.log(data.log);
          else if (data.step === 'instantiated') log(`Prover started on ${data.threads} thread${data.threads > 1 ? 's' : ''}`, seconds(data.instantiate_ms));
          else if (data.step === 'key') log('Proving key loaded and checked', seconds(data.key_load_ms));
          else if (data.step === 'proof') log(`Proof ${data.run} of ${data.runs}`, seconds(data.prove_ms));
          else if (data.error) reject(new Error(data.error));
          else if (data.result) resolve(data.result);
        };
      };
      const prover = new Worker(new URL('./prover-worker.js', import.meta.url), { type: 'module' });
      listen(prover);
      prover.postMessage(job);
    });
    log('Proof verified; an altered amount is rejected', `${result.verify_ms} ms`);
    show({ ...result, download_ms: { prover: wasm.ms, key: key.ms }, compile_ms: compileMs });
  } catch (e) {
    const out = /memory|allocat|unreachable|RangeError/i.test(String(e)) ? ' The device may have run out of memory.' : '';
    log(`Failed: ${e.message || e}.${out}`, '', 'error');
    window.__result = { error: String(e.message || e) };
  } finally {
    for (const w of workers) w.terminate();
    running = false;
    $('run-single').disabled = false;
    $('run-threads').disabled = !canShare();
  }
}

function show(r) {
  const best = Math.min(...r.prove_ms);
  const sorted = r.prove_ms.slice().sort((a, b) => a - b);
  const report = {
    test: 'sh20-circuit phone prover',
    date: new Date().toISOString(),
    userAgent: navigator.userAgent,
    cores,
    deviceMemoryGB: navigator.deviceMemory ?? null,
    crossOriginIsolated: self.crossOriginIsolated === true,
    ...r,
    prove_best_ms: best,
    prove_median_ms: sorted[sorted.length >> 1],
  };
  $('headline').textContent = seconds(best);
  $('summary').textContent = `Best of ${r.prove_ms.length} proof${r.prove_ms.length > 1 ? 's' : ''} on ${r.threads} thread${r.threads > 1 ? 's' : ''}; key loaded in ${seconds(r.key_load_ms)}; ${r.memory_mb} MB of prover memory; ${r.proof_bytes}-byte proof.`;
  $('json').textContent = JSON.stringify(report, null, 1);
  $('result').hidden = false;
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  window.__result = report;
}

$('copy').addEventListener('click', async () => {
  const text = $('json').textContent;
  try {
    await navigator.clipboard.writeText(text);
    $('copy').textContent = 'Copied';
  } catch {
    // no clipboard access (plain http): select the text so it can be copied by hand
    const range = document.createRange();
    range.selectNodeContents($('json'));
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    $('copy').textContent = 'Selected: copy it by hand';
  }
});

// ── start ──

const isolation = await ensureIsolation();
if (isolation !== 'reloading') {
  const how = isolation === 'headers' && navigator.serviceWorker?.controller ? 'service-worker' : isolation;
  describeDevice(how);
  const choices = [...new Set([cores, Math.max(1, cores - 2), Math.ceil(cores / 2), 2])].filter((n) => n >= 1).sort((a, b) => b - a);
  $('threads').replaceChildren(...choices.map((n) => new Option(String(n), String(n))));
  if (params.get('threads')) $('threads').replaceChildren(new Option(params.get('threads'), params.get('threads')));
  if (params.get('runs')) $('runs').replaceChildren(new Option(params.get('runs'), params.get('runs')));
  $('run-threads').disabled = !canShare();
  $('threads-label').hidden = !canShare();
  $('run-threads').addEventListener('click', () => measure('threads'));
  $('run-single').addEventListener('click', () => measure('single'));
  const auto = params.get('auto');
  if (auto === 'single' || (auto === 'threads' && canShare())) measure(auto);
  else if (auto === 'threads') measure('single'); // asked for threads, none available: fall back
}
