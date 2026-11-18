// The prover in Node for the tests: the vault's committed single-thread module (vault/prover/,
// tools/prover.sh) through circuit/web/host.js, as the browser worker uses it, with the shipped key.
import { readFileSync } from 'node:fs';
import { proverApi } from '../../circuit/web/host.js';

export const WASM = new URL('../prover/sh20_circuit.wasm', import.meta.url);
const KEY = new URL('../../circuit/artifacts/spend.pk', import.meta.url);

let api = null;
export function nodeProver() {
  if (!api) {
    api = proverApi(new WebAssembly.Instance(new WebAssembly.Module(readFileSync(WASM)), {}).exports);
    api.loadKey(readFileSync(KEY));
  }
  return {
    vkDigest: api.vkDigest(),
    prove: async (witness) => api.prove(witness, crypto.getRandomValues(new Uint8Array(32))),
    verify: async (publics, proof) => api.verify(publics, proof),
  };
}
