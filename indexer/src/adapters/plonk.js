// Spend verifier: the pinned PLONK verifier of the spend circuit (../../circuit), compiled to
// WebAssembly. The module has no imports and needs no npm package; build it with
//   cd circuit && ./build-wasm.sh
//
// The verifying key is checked against the digest the standard pins (docs/SPEC-WIRE.md §4), so an
// indexer cannot be pointed at another circuit by mistake.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DOMAIN, PROOF_BYTES, SPEND_VK_DIGEST } from '../constants.js';
import { frToBytes } from '../notes.js';

const N_PUBLIC = 9;

/**
 * @param {{ wasm: string | Uint8Array, vk: string | Uint8Array, vkDigest?: string }} options
 *   `wasm` and `vk` are file paths or bytes.
 * @returns {{ name: string, verifySpend: (args: object) => boolean }}
 */
export function plonkVerifier({ wasm, vk, vkDigest = SPEND_VK_DIGEST }) {
  const vkBytes = Buffer.from(typeof vk === 'string' ? readFileSync(vk) : vk);
  const digest = createHash('sha256').update(DOMAIN.VK, 'utf8').update(vkBytes).digest('hex');
  if (digest !== vkDigest) throw new Error(`verifying key digest ${digest} is not the pinned ${vkDigest}`);

  const module = new WebAssembly.Module(typeof wasm === 'string' ? readFileSync(wasm) : wasm);
  const x = new WebAssembly.Instance(module, {}).exports;
  const mem = () => new Uint8Array(x.memory.buffer);
  const vkPtr = x.sh20_alloc(vkBytes.length);
  mem().set(vkBytes, vkPtr);
  const publicsPtr = x.sh20_alloc(N_PUBLIC * 32);
  const proofPtr = x.sh20_alloc(PROOF_BYTES);

  return {
    name: 'plonk-bn254-hermez',
    verifySpend({ root, nullifiers, outLeaves, bodyHash, vPub, tPub, proof }) {
      if (proof.length !== PROOF_BYTES) return false;
      const publics = [root, ...nullifiers, ...outLeaves, bodyHash, BigInt(vPub), BigInt(tPub)];
      if (publics.length !== N_PUBLIC) return false;
      const m = mem();
      publics.forEach((v, i) => m.set(frToBytes(v), publicsPtr + i * 32));
      m.set(proof, proofPtr);
      return x.sh20_verify(vkPtr, vkBytes.length, publicsPtr, proofPtr, PROOF_BYTES) === 1;
    },
  };
}
