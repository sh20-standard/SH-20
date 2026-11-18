// Host side of the spend prover's WebAssembly modules, shared by the browser page and the Node
// benchmark. Two builds exist (circuit/build-wasm.sh):
//
//   single   wasm32-unknown-unknown   one thread, no imports, runs anywhere
//   threads  wasm32-wasip1-threads    a thread pool over Web Workers; needs SharedArrayBuffer, which
//                                     browsers only give to cross-origin isolated pages (COOP/COEP)
//
// In the threaded build every thread is a Worker holding its own instance of the same module on the
// same shared memory. A thread is started by the module calling the import `wasi.thread-spawn`; the
// worker that receives the call cannot create the new Worker itself while it is running WebAssembly,
// so it posts the request to the page (or the Node main thread), which creates it.

/** Limits of the memory a module imports: { initial, maximum, shared } in 64 KiB pages, or null. */
export function importedMemory(wasmBytes) {
  const b = wasmBytes instanceof Uint8Array ? wasmBytes : new Uint8Array(wasmBytes);
  let p = 8;
  const leb = () => {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = b[p++];
      result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) return result;
    }
  };
  const skipName = () => {
    const n = leb();
    p += n;
  };
  const limits = () => {
    const flags = leb();
    const initial = leb();
    const maximum = flags & 1 ? leb() : undefined;
    return { initial, maximum, shared: (flags & 2) !== 0 };
  };
  while (p < b.length) {
    const id = b[p++];
    const size = leb();
    const end = p + size;
    if (id === 2) {
      for (let n = leb(); n > 0; n--) {
        skipName();
        skipName();
        const kind = b[p++];
        if (kind === 0) leb();
        else if (kind === 1) {
          p++;
          limits();
        } else if (kind === 2) return limits();
        else if (kind === 3) p += 2;
      }
      return null;
    }
    p = end;
  }
  return null;
}

/**
 * The shared memory for a threaded module. Engines reserve the maximum up front and some phones
 * refuse a large reservation, so smaller maxima are tried in turn (the module's own maximum is 1 GiB).
 */
export function sharedMemory(limits, maximaMiB = [1024, 768, 512]) {
  let lastError;
  for (const mib of maximaMiB) {
    const maximum = Math.min(limits.maximum ?? 65536, mib * 16);
    if (maximum < limits.initial) continue;
    try {
      return new WebAssembly.Memory({ initial: limits.initial, maximum, shared: true });
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError ?? new Error('no shared memory');
}

/**
 * The imports of the threaded module: the handful of WASI calls the Rust standard library makes, and
 * thread-spawn. `spawn(tid, startArg)` must get a new thread started; `nextTid` is an Int32Array(1)
 * on a SharedArrayBuffer shared by every thread.
 */
export function threadedImports({ memory, nextTid, spawn, log = () => {}, random }) {
  const bytes = () => new Uint8Array(memory.buffer);
  const view = () => new DataView(memory.buffer);
  const ESUCCESS = 0;
  return {
    env: { memory },
    wasi: {
      'thread-spawn': (startArg) => {
        const tid = Atomics.add(nextTid, 0, 1) + 1;
        try {
          spawn(tid, startArg);
          return tid;
        } catch {
          return -6; // EAGAIN
        }
      },
    },
    wasi_snapshot_preview1: {
      random_get(ptr, len) {
        // getRandomValues refuses views on shared memory and more than 65,536 bytes at once
        for (let off = 0; off < len; off += 65536) {
          const chunk = new Uint8Array(Math.min(65536, len - off));
          random(chunk);
          bytes().set(chunk, ptr + off);
        }
        return ESUCCESS;
      },
      environ_sizes_get(countPtr, sizePtr) {
        view().setUint32(countPtr, 0, true);
        view().setUint32(sizePtr, 0, true);
        return ESUCCESS;
      },
      environ_get: () => ESUCCESS,
      clock_time_get(_id, _precision, timePtr) {
        view().setBigUint64(timePtr, BigInt(Math.round(performance.now() * 1e6)), true);
        return ESUCCESS;
      },
      fd_write(fd, iovs, iovsLen, writtenPtr) {
        let text = '';
        let written = 0;
        for (let i = 0; i < iovsLen; i++) {
          const ptr = view().getUint32(iovs + 8 * i, true);
          const len = view().getUint32(iovs + 8 * i + 4, true);
          // slice() copies out of the shared memory, which TextDecoder would refuse
          text += new TextDecoder().decode(bytes().slice(ptr, ptr + len));
          written += len;
        }
        if (text) log(text);
        view().setUint32(writtenPtr, written, true);
        return ESUCCESS;
      },
      proc_exit(code) {
        throw new Error(`the prover exited with code ${code}`);
      },
      sched_yield: () => ESUCCESS,
    },
  };
}

/** Typed access to the exports of either build. */
export function proverApi(exports, memory = exports.memory) {
  const x = exports;
  const mem = () => new Uint8Array(memory.buffer);
  const put = (data) => {
    const ptr = x.sh20_alloc(data.length);
    mem().set(data, ptr);
    return ptr;
  };
  const take = (ptr, len) => mem().slice(ptr, ptr + len);
  const WITNESS = 3232;
  const PROOF = 480;
  const VK = 712;
  let key = 0;
  const scratch = { witness: 0, proof: 0, vk: 0, seed: 0, publics: 0 };
  const ensure = () => {
    if (!scratch.witness) {
      scratch.witness = x.sh20_alloc(WITNESS);
      scratch.proof = x.sh20_alloc(PROOF);
      scratch.vk = x.sh20_alloc(VK);
      scratch.seed = x.sh20_alloc(32);
      scratch.publics = x.sh20_alloc(9 * 32);
    }
  };
  return {
    /** Starts the thread pool (threaded build); returns the threads in use. */
    threads: (n) => x.sh20_threads(n),
    /** Loads the shipped proving key; throws if it is not the pinned file. */
    loadKey(pkBytes) {
      const ptr = put(pkBytes);
      key = x.sh20_load_key(ptr, pkBytes.length);
      x.sh20_free(ptr, pkBytes.length);
      if (!key) throw new Error('the proving key was refused (not the pinned file?)');
      ensure();
      x.sh20_vk(key, scratch.vk);
    },
    vkDigest() {
      const ptr = x.sh20_alloc(32);
      x.sh20_vk_digest(key, ptr);
      return Array.from(take(ptr, 32), (v) => v.toString(16).padStart(2, '0')).join('');
    },
    /** A sample witness (3,232 bytes) from a 32-byte seed. */
    sampleWitness(seed) {
      ensure();
      mem().set(seed, scratch.seed);
      x.sh20_sample_witness(scratch.seed, scratch.witness);
      return take(scratch.witness, WITNESS);
    },
    /** Proves a witness with 32 fresh random bytes; returns the 480-byte proof or null. */
    prove(witness, seed) {
      ensure();
      mem().set(witness, scratch.witness);
      mem().set(seed, scratch.seed);
      return x.sh20_prove(key, scratch.witness, scratch.seed, scratch.proof) === 1 ? take(scratch.proof, PROOF) : null;
    },
    /** Verifies a proof against 9 × 32 bytes of public inputs (the head of a witness). */
    verify(publics, proof) {
      ensure();
      mem().set(publics, scratch.publics);
      mem().set(proof, scratch.proof);
      return x.sh20_verify(scratch.vk, VK, scratch.publics, scratch.proof, PROOF) === 1;
    },
    memoryBytes: () => memory.buffer.byteLength,
  };
}
