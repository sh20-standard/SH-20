// Spend verifier: the pinned PLONK verifier of the spend circuit (../../circuit), compiled to
// WebAssembly. The module has no imports and needs no npm package; build it with
//   cd circuit && ./build-wasm.sh
//
// The verifying key is checked against the digest the standard pins (docs/SPEC-WIRE.md §4), so an
// indexer cannot be pointed at another circuit by mistake.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DOMAIN, FR, PROOF_BYTES, SPEND_VK_DIGEST } from '../constants.js';
import { frToBytes } from '../notes.js';

const N_PUBLIC = 9;

/** The verifying key kept in the repository (its digest is checked on load). */
export const DEFAULT_VK = fileURLToPath(new URL('../../../circuit/artifacts/spend.vk', import.meta.url));

/**
 * @param {{ wasm: string | Uint8Array, vk?: string | Uint8Array }} options
 *   `wasm` and `vk` are file paths or bytes; `vk` defaults to circuit/artifacts/spend.vk. The key must have the pinned
 *   digest, which is not an option (docs/audit/2026-11-24-verifier.md, verifier-5).
 * @returns {{ name: string, verifySpend: (args: object) => boolean }}
 */
export function plonkVerifier({ wasm, vk = DEFAULT_VK }) {
  const vkBytes = Buffer.from(typeof vk === 'string' ? readFileSync(vk) : vk);
  const digest = createHash('sha256').update(DOMAIN.VK, 'utf8').update(vkBytes).digest('hex');
  if (digest !== SPEND_VK_DIGEST) throw new Error(`verifying key digest ${digest} is not the pinned ${SPEND_VK_DIGEST}`);

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
      const publics = [root, ...nullifiers, ...outLeaves, bodyHash, vPub, tPub].map((v) => (typeof v === 'number' ? BigInt(v) : v));
      if (publics.length !== N_PUBLIC) return false;
      // each one a field element, so that each is written as exactly its 32 bytes: a negative number or one of
      // 2^256 or more would come out as another value, which the module cannot tell (verifier-2)
      if (!publics.every((v) => typeof v === 'bigint' && v >= 0n && v < FR)) return false;
      const m = mem();
      publics.forEach((v, i) => m.set(frToBytes(v), publicsPtr + i * 32));
      m.set(proof, proofPtr);
      return x.sh20_verify(vkPtr, vkBytes.length, publicsPtr, proofPtr, PROOF_BYTES) === 1;
    },
  };
}
