// The spend prover, off the page's main thread, wired the way circuit/web/prover-worker.js is
// (circuit/web/host.js, unchanged; the threads of the pool are circuit/web/thread-worker.js).
// Messages:
//   { init: { mode: 'threads', module, memory, nextTid, threads, key } }   or   { init: { mode: 'single', module, key } }
//      → { ready: { threads, vkDigest } }
//   { id, prove: witness }            → { id, proof }       (null: the prover rejected the witness)
//   { id, verify: { publics, proof } } → { id, ok }
// Any failure → { id?, error }. A thread the pool asks for → { spawn: { tid, startArg } } for the page.

import { proverApi, threadedImports } from '../../circuit/web/host.js';

let api = null;

self.onmessage = ({ data }) => {
  try {
    if (data.init) return init(data.init);
    if (!api) throw new Error('the prover is not loaded');
    if (data.prove) return self.postMessage({ id: data.id, proof: api.prove(data.prove, crypto.getRandomValues(new Uint8Array(32))) });
    if (data.verify) return self.postMessage({ id: data.id, ok: api.verify(data.verify.publics, data.verify.proof) });
    throw new Error('unknown message');
  } catch (e) {
    self.postMessage({ id: data.id, error: String(e?.message ?? e) });
  }
};

function init({ mode, module, memory, nextTid, threads, key }) {
  let n = 1;
  if (mode === 'threads') {
    const imports = threadedImports({
      memory,
      nextTid,
      spawn: (tid, startArg) => self.postMessage({ spawn: { tid, startArg } }),
      log: () => {},
      random: (chunk) => crypto.getRandomValues(chunk),
    });
    const { exports } = new WebAssembly.Instance(module, imports);
    exports.__wasi_init_tp();
    exports.__wasm_call_ctors();
    api = proverApi(exports, memory);
    n = api.threads(threads);
  } else {
    api = proverApi(new WebAssembly.Instance(module, {}).exports);
  }
  api.loadKey(key);
  self.postMessage({ ready: { threads: n, vkDigest: api.vkDigest() } });
}
