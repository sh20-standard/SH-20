// The phone test page: proves a sample SH-20 spend on this device and reports the timings.
//
// Two ways to prove. With cross-origin isolation (COOP/COEP headers, or sw.js standing in for them)
// the page has SharedArrayBuffer and runs the threaded build on a pool of Workers. Without it, the
// single-thread build runs in one Worker. `?auto=threads|single|sweep|keyload` starts by itself;
// `runs`, `threads`, `order`, `passes`, `variants` and `proofs` set what is measured.
//
// The sweep proves once per thread count, in a shuffled order so that a phone warming up does not
// favour one end, and goes through the order twice. It reports where each proof spent its time:
// loading the key, commitments (MSM), transforms (FFT), and the rest. `?auto=sweep&order=1,6,2,5,3,4&passes=2`.

import { defaultThreads, importedMemory, sharedMemory } from './host.js';

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const cores = navigator.hardwareConcurrency || 1; // as the browser reports them
const pool = defaultThreads(); // what the prover takes: more than `cores` where the browser under-reports
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
    ['Logical cores', pool === cores ? String(cores) : `${cores} reported, ${pool} threads used`],
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

/**
 * Runs one job in a fresh prover Worker, with the thread Workers its pool asks for; resolves with the
 * job's result. Progress messages go to `onStep`. Every Worker created is added to `workers`.
 */
function runJob(job, workers, onStep = () => {}) {
  return new Promise((resolve, reject) => {
    const listen = (worker) => {
      workers.push(worker);
      worker.onerror = (e) => reject(new Error(e.message || 'a worker failed'));
      worker.onmessage = ({ data }) => {
        if (data.spawn) {
          // a thread of the pool: its own instance of the module on the same memory
          const thread = new Worker(new URL('./thread-worker.js', import.meta.url), { type: 'module' });
          listen(thread);
          thread.postMessage({ module: job.module, memory: job.memory, nextTid: job.nextTid, ...data.spawn });
        } else if (data.log) console.log(data.log);
        else if (data.error) reject(new Error(data.error));
        else if (data.result) resolve(data.result);
        else onStep(data);
      };
    };
    const prover = new Worker(new URL('./prover-worker.js', import.meta.url), { type: 'module' });
    listen(prover);
    prover.postMessage(job);
  });
}
const stop = (workers) => {
  for (const w of workers.splice(0)) w.terminate();
};
const BUTTONS = ['run-threads', 'run-single', 'run-sweep', 'run-keyload'];
const enableButtons = () => {
  for (const id of BUTTONS) $(id).disabled = id !== 'run-single' && id !== 'run-keyload' && !canShare();
};
const failed = (e) => {
  const out = /memory|allocat|unreachable|RangeError/i.test(String(e)) ? ' The device may have run out of memory.' : '';
  log(`Failed: ${e.message || e}.${out}`, '', 'error');
  window.__result = { error: String(e.message || e) };
};

let running = false;
async function measure(mode) {
  if (running) return;
  running = true;
  for (const id of BUTTONS) $(id).disabled = true;
  $('log').replaceChildren();
  $('progress').hidden = false;
  $('result').hidden = true;
  const runs = Number($('runs').value);
  const threads = mode === 'threads' ? Number($('threads').value) : 1;
  const workers = [];
  try {
    const wasm = await download(mode === 'single' ? './sh20_circuit.wasm' : './sh20_circuit_threads.wasm');
    log(`Prover downloaded (${(wasm.bytes.length / 2 ** 20).toFixed(1)} MB)`, seconds(wasm.ms));
    const key = await download('./spend.pk');
    log(`Proving key downloaded (${(key.bytes.length / 2 ** 20).toFixed(1)} MB)`, seconds(key.ms));

    let t = performance.now();
    const module = await WebAssembly.compile(wasm.bytes);
    const compileMs = Math.round(performance.now() - t);
    log('Prover compiled', seconds(compileMs));

    const job = { mode, module, key: key.bytes, runs };
    if (mode !== 'single') {
      job.memory = sharedMemory(importedMemory(wasm.bytes));
      job.nextTid = new Int32Array(new SharedArrayBuffer(4));
      job.threads = threads;
    }
    if (mode === 'sweep') {
      job.order = SWEEP_ORDER;
      job.passes = SWEEP_PASSES;
    }

    const result = await runJob(job, workers, (data) => {
      if (data.step === 'instantiated' && mode === 'sweep') log('Prover started', seconds(data.instantiate_ms));
      else if (data.step === 'sweep') log(`${data.done}/${data.total}: ${data.run.threads} thread${data.run.threads > 1 ? 's' : ''}, pass ${data.run.pass}`, seconds(data.run.prove_ms));
      else if (data.step === 'instantiated') log(`Prover started on ${data.threads} thread${data.threads > 1 ? 's' : ''}`, seconds(data.instantiate_ms));
      else if (data.step === 'key') log('Proving key loaded and checked', seconds(data.key_load_ms));
      else if (data.step === 'proof') log(`Proof ${data.run} of ${data.runs}`, seconds(data.prove_ms));
    });
    if (mode === 'sweep') {
      log('Last proof verified; an altered amount is rejected');
      showSweep({ ...result, download_ms: { prover: wasm.ms, key: key.ms }, compile_ms: compileMs });
    } else {
      log('Proof verified; an altered amount is rejected', `${result.verify_ms} ms`);
      show({ ...result, download_ms: { prover: wasm.ms, key: key.ms }, compile_ms: compileMs });
    }
  } catch (e) {
    failed(e);
  } finally {
    stop(workers);
    running = false;
    enableButtons();
  }
}

// ── key loading on one thread: what the first load pays for ──
//
// Every run is a cold start: a module compiled again, a new Worker, a new memory.
//   grow      the single-thread build as it is: its memory grows as the prover allocates
//   reserved  the same build, after one reservation of the whole heap
//   shared    the threaded build on a shared memory, with one thread (needs cross-origin isolation)
// Before them, the cost of growing a memory by itself, without the prover.

const KEYLOAD_VARIANTS = () =>
  (params.get('variants') || (canShare() ? 'grow,reserved,shared,shared,reserved,grow' : 'grow,reserved,reserved,grow'))
    .split(',')
    .filter((v) => v === 'grow' || v === 'reserved' || (v === 'shared' && canShare()));
const KEYLOAD_PROOFS = params.get('proofs') === null ? 1 : Math.max(0, Math.min(3, Number(params.get('proofs')) || 0));
const KEYLOAD_NAMES = { grow: 'as shipped', reserved: 'heap reserved', shared: 'shared memory' };

async function measureKeyload() {
  if (running) return;
  running = true;
  for (const id of BUTTONS) $(id).disabled = true;
  $('log').replaceChildren();
  $('progress').hidden = false;
  $('result').hidden = true;
  const variants = KEYLOAD_VARIANTS();
  const workers = [];
  try {
    const builds = { single: await download('./sh20_circuit.wasm') };
    if (variants.includes('shared')) builds.threads = await download('./sh20_circuit_threads.wasm');
    const key = await download('./spend.pk');
    log('Prover and proving key downloaded', seconds(builds.single.ms + (builds.threads?.ms ?? 0) + key.ms));

    const growth = [];
    for (const [stepMb, shared] of [[1, false], [224, false], ...(canShare() ? [[1, true]] : [])]) {
      const probe = await runJob({ mode: 'growth', totalMb: 224, stepMb, shared }, workers);
      stop(workers);
      growth.push(probe);
      log(`Memory grown to 224 MB in ${probe.grows} step${probe.grows > 1 ? 's' : ''}${shared ? ', shared' : ''}`, seconds(probe.ms));
    }

    const runs = [];
    for (const [i, variant] of variants.entries()) {
      const bytes = (variant === 'shared' ? builds.threads : builds.single).bytes;
      const job = { mode: 'keyload', variant, module: await WebAssembly.compile(bytes), key: key.bytes, proofs: KEYLOAD_PROOFS };
      if (variant === 'shared') {
        job.memory = sharedMemory(importedMemory(bytes));
        job.nextTid = new Int32Array(new SharedArrayBuffer(4));
      }
      const label = `${i + 1}/${variants.length} ${KEYLOAD_NAMES[variant]}`;
      runs.push(
        await runJob(job, workers, (data) => {
          if (data.step === 'keyload') log(`${label}: key loaded, then again`, `${seconds(data.run.key_load_ms)}, ${seconds(data.run.key_reload_ms)}`);
          else if (data.step === 'keyload-proof') log(`${label}: proof ${data.run} of ${data.runs}`, seconds(data.prove_ms));
        }),
      );
      stop(workers);
    }
    showKeyload({ mode: 'keyload', variants, proofs: KEYLOAD_PROOFS, growth, runs });
  } catch (e) {
    failed(e);
  } finally {
    stop(workers);
    running = false;
    enableButtons();
  }
}

function showKeyload(r) {
  const report = {
    test: 'sh20-circuit phone prover, key loading on one thread',
    date: new Date().toISOString(),
    userAgent: navigator.userAgent,
    cores,
    defaultThreads: pool,
    deviceMemoryGB: navigator.deviceMemory ?? null,
    crossOriginIsolated: self.crossOriginIsolated === true,
    ...r,
  };
  const s2 = (x) => (x / 1000).toFixed(2);
  const cell = (text) => {
    const td = document.createElement('td');
    td.textContent = text;
    return td;
  };
  const head = document.createElement('tr');
  for (const h of ['Run', 'Key', 'Again', 'Proof', 'MB']) {
    const th = document.createElement('th');
    th.textContent = h;
    head.append(th);
  }
  const rows = r.runs.map((run) => {
    const tr = document.createElement('tr');
    tr.append(cell(KEYLOAD_NAMES[run.variant]), cell(s2(run.key_load_ms)), cell(s2(run.key_reload_ms)), cell(run.prove_ms.length ? (run.prove_ms[0] / 1000).toFixed(1) : '–'), cell(run.memory_mb_end));
    return tr;
  });
  $('runs-table').replaceChildren(head, ...rows);
  $('runs-table').hidden = false;
  const best = (variant) => {
    const all = r.runs.filter((run) => run.variant === variant).map((run) => run.key_load_ms);
    return all.length ? Math.min(...all) : null;
  };
  const [grow, reserved] = [best('grow'), best('reserved')];
  $('headline').textContent = grow === null ? '–' : reserved === null ? seconds(grow) : `${seconds(grow)} → ${seconds(reserved)}`;
  $('summary').textContent = `First key load on one thread, as shipped${reserved === null ? '' : ' and with the heap reserved in one step'}. Seconds below, each run from a cold start: the first load, a second load in the same instance, the first proof.`;
  $('json').textContent = JSON.stringify(report, null, 1);
  $('result').hidden = false;
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  window.__result = report;
}

const SWEEP_ORDER = (params.get('order') || '1,6,2,5,3,4').split(',').map(Number).filter((n) => Number.isInteger(n) && n >= 1 && n <= 16);
const SWEEP_PASSES = Math.max(1, Math.min(5, Number(params.get('passes')) || 2));

/** The sweep: one line per proof in the order they were made, and everything in the JSON. */
function showSweep(r) {
  const report = {
    test: 'sh20-circuit phone prover, thread sweep',
    date: new Date().toISOString(),
    userAgent: navigator.userAgent,
    cores,
    defaultThreads: pool,
    deviceMemoryGB: navigator.deviceMemory ?? null,
    crossOriginIsolated: self.crossOriginIsolated === true,
    ...r,
  };
  const best = r.runs.reduce((a, b) => (b.prove_ms < a.prove_ms ? b : a));
  const s1 = (x) => (x / 1000).toFixed(1);
  const cell = (text, cls) => {
    const td = document.createElement('td');
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  };
  const head = document.createElement('tr');
  for (const h of ['Thr', 'Pass', 'Proof', 'Key', 'MSM', 'FFT', 'Rest']) {
    const th = document.createElement('th');
    th.textContent = h;
    head.append(th);
  }
  const rows = r.runs.map((run) => {
    const tr = document.createElement('tr');
    const rest = run.prove_ms - run.msm_ms - run.fft_ms;
    tr.append(cell(run.threads), cell(run.pass), cell(s1(run.prove_ms), run === best ? 'best' : ''), cell(s1(run.key_load_ms)), cell(s1(run.msm_ms)), cell(s1(run.fft_ms)), cell(s1(rest)));
    return tr;
  });
  $('runs-table').replaceChildren(head, ...rows);
  $('runs-table').hidden = false;
  $('headline').textContent = seconds(best.prove_ms);
  $('summary').textContent = `Fastest proof, on ${best.threads} thread${best.threads > 1 ? 's' : ''}. Seconds per proof below, in the order they were made: key loading, then inside the proof commitments (MSM), transforms (FFT) and the rest.`;
  $('json').textContent = JSON.stringify(report, null, 1);
  $('result').hidden = false;
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  window.__result = report;
}

function show(r) {
  const best = Math.min(...r.prove_ms);
  const sorted = r.prove_ms.slice().sort((a, b) => a - b);
  const report = {
    test: 'sh20-circuit phone prover',
    date: new Date().toISOString(),
    userAgent: navigator.userAgent,
    cores,
    defaultThreads: pool,
    deviceMemoryGB: navigator.deviceMemory ?? null,
    crossOriginIsolated: self.crossOriginIsolated === true,
    ...r,
    prove_best_ms: best,
    prove_median_ms: sorted[sorted.length >> 1],
  };
  $('runs-table').hidden = true;
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
  const choices = [...new Set([pool, cores, Math.max(1, pool - 2), Math.ceil(pool / 2), 2])].filter((n) => n >= 1).sort((a, b) => b - a);
  $('threads').replaceChildren(...choices.map((n) => new Option(String(n), String(n))));
  if (params.get('threads')) $('threads').replaceChildren(new Option(params.get('threads'), params.get('threads')));
  if (params.get('runs')) $('runs').replaceChildren(new Option(params.get('runs'), params.get('runs')));
  $('run-threads').disabled = !canShare();
  $('run-sweep').disabled = !canShare();
  $('run-sweep').textContent = `Sweep ${SWEEP_ORDER.join(', ')} threads, ${SWEEP_PASSES} pass${SWEEP_PASSES > 1 ? 'es' : ''}`;
  $('threads-label').hidden = !canShare();
  $('run-threads').addEventListener('click', () => measure('threads'));
  $('run-single').addEventListener('click', () => measure('single'));
  $('run-sweep').addEventListener('click', () => measure('sweep'));
  $('run-keyload').textContent = `Key loading on one thread: ${KEYLOAD_VARIANTS().length} cold starts${KEYLOAD_PROOFS ? `, ${KEYLOAD_PROOFS} proof${KEYLOAD_PROOFS > 1 ? 's' : ''} each` : ''}`;
  $('run-keyload').addEventListener('click', measureKeyload);
  const auto = params.get('auto');
  if (auto === 'keyload') measureKeyload();
  else if (auto === 'single' || ((auto === 'threads' || auto === 'sweep') && canShare())) measure(auto);
  else if (auto === 'threads') measure('single'); // asked for threads, none available: fall back
}
