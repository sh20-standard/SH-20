// One thread of the prover's pool: a Worker with its own instance of the threaded module on the
// shared memory. The page creates it when an instance calls wasi.thread-spawn (see host.js).

import { threadedImports } from './host.js';

self.onmessage = ({ data: { module, memory, nextTid, tid, startArg } }) => {
  const imports = threadedImports({
    memory,
    nextTid,
    spawn: (t, arg) => self.postMessage({ spawn: { tid: t, startArg: arg } }),
    log: (text) => self.postMessage({ log: text }),
    random: (chunk) => crypto.getRandomValues(chunk),
  });
  const { exports } = new WebAssembly.Instance(module, imports);
  // runs for as long as the thread lives; a pool that is replaced ends its threads
  exports.wasi_thread_start(tid, startArg);
  self.close();
};
