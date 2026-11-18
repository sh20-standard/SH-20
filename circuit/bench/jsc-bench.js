// The single-thread WebAssembly prover in JavaScriptCore's own shell, the engine of Safari:
//
//   jsc [--useWasmFastMemory=false] bench/jsc-bench.js -- <single-thread sh20_circuit.wasm> <spend.pk> [runs] [reserve MiB]
//
// macOS ships the shell at /System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc.
// With --useWasmFastMemory=false the engine does not reserve address space for a WebAssembly memory:
// growing one then means allocating a larger block and copying. This script measures what that costs
// the prover, and what one reservation up front gives back: `reserve` calls sh20_reserve first
// (see src/ffi.rs). Whether Safari on a phone runs that way is for the test page to say
// (`?auto=keyload`, circuit/web).

const [wasmPath, pkPath, runsArg, reserveArg] = arguments;
const runs = Number(runsArg || 2);
const reserveMiB = Number(reserveArg || 0);
const now = () => preciseTime() * 1000;
const secs = (t) => +((now() - t) / 1000).toFixed(2);

let t = now();
const instance = new WebAssembly.Instance(new WebAssembly.Module(readFile(wasmPath, 'binary')), {});
const x = instance.exports;
const mem = () => new Uint8Array(x.memory.buffer);
const put = (bytes) => {
  const p = x.sh20_alloc(bytes.length);
  mem().set(bytes, p);
  return p;
};
const instantiate = secs(t);
const pagesAtStart = x.memory.buffer.byteLength / 65536;
let reserve = 0;
if (reserveMiB > 0) {
  t = now();
  x.sh20_reserve(reserveMiB * 2 ** 20);
  reserve = secs(t);
}

const key = readFile(pkPath, 'binary');
t = now();
const keyPtr = put(key);
const pk = x.sh20_load_key(keyPtr, key.length);
x.sh20_free(keyPtr, key.length);
if (!pk) throw new Error('the proving key was refused');
const keyLoad = secs(t);
const pagesAfterKey = x.memory.buffer.byteLength / 65536;

const seed = () => put(Uint8Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
const [witness, proof, vk] = [x.sh20_alloc(3232), x.sh20_alloc(480), x.sh20_alloc(712)];
x.sh20_vk(pk, vk);
const prove = [];
for (let i = 0; i < runs; i++) {
  x.sh20_sample_witness(seed(), witness);
  t = now();
  if (x.sh20_prove(pk, witness, seed(), proof) !== 1) throw new Error('prove failed');
  prove.push(secs(t));
}
const publics = put(mem().slice(witness, witness + 288));
if (x.sh20_verify(vk, 712, publics, proof, 480) !== 1) throw new Error('the proof does not verify');
print(JSON.stringify({ instantiate_s: instantiate, reserve_mib: reserveMiB, reserve_s: reserve, key_load_s: keyLoad, prove_s: prove, mib_at_start: pagesAtStart / 16, mib_after_key: pagesAfterKey / 16, mib_at_end: x.memory.buffer.byteLength / 2 ** 20 }));
