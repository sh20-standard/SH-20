// Tests written by the audit of the part `verifier` (docs/audit/2026-11-24-verifier.md), at the WebAssembly
// boundary: the module as the indexer's adapter calls it (src/adapters/plonk.js) and as the browser host calls it
// (circuit/web/host.js). Each test holds a property of that report, or shows one of its findings as the code stands.
//
// Needs the verifier module: the one `cd circuit && ./build-wasm.sh` builds, else the copy in vault/prover/.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FR, PROOF_BYTES } from '../src/constants.js';
import { plonkVerifier } from '../src/adapters/plonk.js';
import { proverApi } from '../../circuit/web/host.js';

const path = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const built = path('../../circuit/target/wasm32-unknown-unknown/release/sh20_circuit.wasm');
const wasm = process.env.SH20_VERIFIER_WASM || (existsSync(built) ? built : path('../../vault/prover/sh20_circuit.wasm'));
const skip = existsSync(wasm) ? false : 'verifier module not built (cd circuit && ./build-wasm.sh)';

// A real spend: the accepted TRANSFER of vectors/plonk-v0.3.json, with the nine inputs of its verifier call.
const vectors = JSON.parse(readFileSync(path('../vectors/plonk-v0.3.json'), 'utf8'));
const call = vectors.verifierCalls.find((c) => c.accepted);
const inputs = call.publicInputs.map((x) => BigInt('0x' + x));
const envelope = Buffer.from(vectors.envelopes.transfer.hex, 'hex');
const proof = envelope.subarray(envelope.length - PROOF_BYTES);
const args = (over = {}) => ({
  root: inputs[0], nullifiers: inputs.slice(1, 3), outLeaves: inputs.slice(3, 6), bodyHash: inputs[6], vPub: inputs[7], tPub: inputs[8], proof, ...over,
});
const le = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
const publics = Buffer.concat(inputs.map(le));
// and the accepted BURN, whose vPub is 900
const b = vectors.verifierCalls.filter((c) => c.accepted)[1].publicInputs.map((x) => BigInt('0x' + x));
const burnEnvelope = Buffer.from(vectors.envelopes.burn.hex, 'hex');
const burnArgs = { root: b[0], nullifiers: b.slice(1, 3), outLeaves: b.slice(3, 6), bodyHash: b[6], vPub: b[7], tPub: b[8], proof: burnEnvelope.subarray(burnEnvelope.length - PROOF_BYTES) };

test('the adapter: no proof makes the module trap, grow, or change a later answer', { skip }, () => {
  const v = plonkVerifier({ wasm });
  assert.equal(v.verifySpend(args()), true);
  const module = new WebAssembly.Module(readFileSync(wasm));
  assert.deepEqual(WebAssembly.Module.imports(module), [], 'the module asks nothing of its host');

  // the same calls on an instance whose memory can be watched
  const x = new WebAssembly.Instance(module, {}).exports;
  const key = readFileSync(path('../../circuit/artifacts/spend.vk'));
  const [keyPtr, inPtr, proofPtr] = [x.sh20_alloc(key.length), x.sh20_alloc(288), x.sh20_alloc(PROOF_BYTES)];
  const mem = () => new Uint8Array(x.memory.buffer);
  mem().set(key, keyPtr);
  const verify = (p, ins = publics) => {
    mem().set(ins, inPtr);
    mem().set(p, proofPtr);
    return x.sh20_verify(keyPtr, key.length, inPtr, proofPtr, p.length);
  };
  assert.equal(verify(proof), 1);
  const size = x.memory.buffer.byteLength;
  let reachedThePairing = 0;
  const started = process.hrtime.bigint();
  for (let i = 0; i < 4000; i++) {
    const p = Buffer.from(i % 4 === 0 ? randomBytes(PROOF_BYTES) : proof);
    if (i % 4 === 1) p[randomBytes(2).readUInt16LE() % PROOF_BYTES] ^= 1 << (i % 8); // one bit
    if (i % 4 === 2) randomBytes(32).copy(p, 32 * (9 + (i % 6))); // one evaluation
    if (i % 4 === 3) p.copy(p, 32 * (i % 9), 32 * ((i + 1) % 9), 32 * ((i + 1) % 9) + 32); // one commitment in another's place
    const answer = verify(p);
    assert.equal(answer, p.equals(proof) ? 1 : 0, `proof ${i}`);
    if (i % 4 === 3) reachedThePairing++;
  }
  const perCall = Number(process.hrtime.bigint() - started) / 4000 / 1e6;
  // public inputs that are not field elements: −1, never a trap
  for (let i = 0; i < 9; i++) {
    const ins = Buffer.from(publics);
    le(inputs[i] + FR).copy(ins, 32 * i);
    assert.equal(verify(proof, ins), -1, `input ${i} + r`);
  }
  assert.equal(verify(proof), 1);
  assert.equal(x.sh20_verify(keyPtr, key.length - 1, inPtr, proofPtr, PROOF_BYTES), -1);
  assert.equal(x.sh20_verify(keyPtr, key.length, inPtr, proofPtr, PROOF_BYTES - 1), 0);
  assert.equal(x.sh20_verify(keyPtr, key.length, inPtr, proofPtr, PROOF_BYTES + 1), 0);
  assert.equal(x.sh20_verify(keyPtr, key.length, inPtr, proofPtr, 0), 0);
  // after all of it: the same memory, and the real proof still verifies
  assert.equal(x.memory.buffer.byteLength, size, 'the memory grew');
  assert.equal(verify(proof), 1);
  assert.ok(reachedThePairing > 0 && perCall < 1000, `${perCall} ms per call`);
});

test('the adapter: each of the nine inputs is checked by the module, in the order of SPEC-WIRE §4', { skip }, () => {
  const v = plonkVerifier({ wasm });
  assert.equal(v.verifySpend(args()), true);
  for (const over of [
    { root: inputs[0] + 1n }, { nullifiers: [inputs[2], inputs[1]] }, { nullifiers: [inputs[1]] }, { outLeaves: [inputs[4], inputs[3], inputs[5]] },
    { outLeaves: [...inputs.slice(3, 6), 1n] }, { bodyHash: inputs[6] + 1n }, { vPub: 1n }, { tPub: 1n }, { root: inputs[1], nullifiers: [inputs[0], inputs[2]] },
    { root: inputs[0] + FR }, { vPub: FR }, { tPub: FR }, { proof: proof.subarray(1) }, { proof: Buffer.concat([proof, Buffer.alloc(1)]) },
  ]) assert.equal(v.verifySpend(args(over)), false, Object.keys(over).join());
  assert.equal(v.verifySpend(args()), true);
  // the last two, vPub and tPub, on a BURN, where they are not both zero
  assert.equal(v.verifySpend(burnArgs), true);
  assert.equal(v.verifySpend({ ...burnArgs, vPub: burnArgs.tPub, tPub: burnArgs.vPub }), false);
  assert.equal(v.verifySpend({ ...burnArgs, vPub: burnArgs.vPub + 1n }), false);
  assert.equal(v.verifySpend({ ...burnArgs, tPub: 0n }), false);
});

// Finding verifier-2. The adapter writes each input as the bytes `frToBytes` gives, whatever their number, and leaves
// the range to the module. A negative value is written on 31 bytes (its hex has a sign), all zero: the module reads 0,
// or 0 with the top byte the call before left there. 2^256 is written as 2^252, and a longer value past its 32 bytes.
// The indexer never passes such a value (its nine inputs are field elements, a u64 and a u32 by construction);
// nothing in the adapter refuses one.
test('verifier-2: the adapter reads an input that is no field element as another value', { skip }, () => {
  const v = plonkVerifier({ wasm });
  assert.equal(v.verifySpend(args()), true);
  assert.equal(inputs[7], 0n);
  // vPub = −1, and tPub = −5, are read as 0: the TRANSFER's proof "verifies" for them
  assert.equal(v.verifySpend(args({ vPub: -1n })), true, 'the adapter now refuses a negative input: update the report');
  assert.equal(v.verifySpend(args({ tPub: -5n })), true);
  // not a way to move value: the BURN's vPub, 900, has no negative that reads as 900
  assert.equal(v.verifySpend(burnArgs), true);
  assert.equal(b[7], 900n);
  assert.equal(v.verifySpend({ ...burnArgs, vPub: -900n }), false);
  assert.equal(v.verifySpend({ ...burnArgs, vPub: (1n << 256n) + 900n }), false);
  assert.equal(v.verifySpend(burnArgs), true);
});

// Finding verifier-1. The browser host copies `publics` and `proof` into buffers of 288 and 480 bytes without looking
// at their lengths, and the key the module verifies under sits in the buffer after the proof's. A "proof" that goes on
// past 480 bytes replaces that key. With the key of a circuit that has no rule (circuit/tests/fixtures/audit/no-rule.json,
// which circuit/tests/audit_verifier.rs checks), `verify` then answers true for a spend nobody proved, and false for
// every real proof from then on. No caller of the vault passes anything but 480 bytes today (the codec cuts the proof
// of an envelope to 480; the vault's own proofs are 480): the check is missing where it would cost one line.
test('verifier-1: the browser host lets a long "proof" replace the key it verifies under', { skip }, () => {
  const forged = JSON.parse(readFileSync(path('../../circuit/tests/fixtures/audit/no-rule.json'), 'utf8'));
  const [otherKey, otherPublics, otherProof] = [forged.vk, forged.publics, forged.proof].map((h) => Buffer.from(h, 'hex'));
  const x = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(wasm)), {}).exports;
  // the host, with its allocations recorded (they are the same on every run of the same module)
  const allocations = [];
  const api = proverApi({ ...x, sh20_alloc: (n) => { const ptr = x.sh20_alloc(n); allocations.push([n, ptr]); return ptr; } }, x.memory);
  api.loadKey(readFileSync(path('../../circuit/artifacts/spend.pk')));
  assert.equal(api.verify(publics, proof), true);
  assert.equal(api.verify(otherPublics, otherProof), false, 'under the pinned key, the other proof is nothing');

  const proofBuffer = allocations.find(([n]) => n === PROOF_BYTES)[1];
  const keyBuffer = allocations.find(([n]) => n === otherKey.length)[1];
  assert.ok(keyBuffer > proofBuffer && keyBuffer - proofBuffer < 1 << 20, 'the key is in a buffer after the proof');
  // 480 bytes of proof, the bytes between the two buffers as they are (18,080 of them in the module the vault ships), then the other key
  const between = Buffer.from(new Uint8Array(x.memory.buffer).slice(proofBuffer + PROOF_BYTES, keyBuffer));
  const long = Buffer.concat([otherProof, between, otherKey]);
  assert.equal(api.verify(otherPublics, long), true, 'the host now refuses a proof that is not 480 bytes: update the report');
  // and the module is left verifying under the other key
  assert.equal(api.verify(publics, proof), false);
  assert.equal(api.verify(otherPublics, otherProof), true);
});
