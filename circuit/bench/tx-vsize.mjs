// Virtual size of the Bitcoin transactions that carry SH-20 envelopes, computed from serialized
// envelopes (BIP141: vsize = ceil((4 × non-witness bytes + witness bytes) / 4)).
//
//   node tx-vsize.mjs [../../indexer/test/fixtures/plonk-scenario.json]
//
// Reveal transaction of a proof-carrying envelope: one script-path input whose tapscript is
//   <32-byte key> OP_CHECKSIG OP_0 OP_IF <"SH20"> <pushes of at most 520 bytes> OP_ENDIF
// (docs/SPEC-WIRE.md §3) and one P2TR output. The commit transaction that funds it is not counted:
// it is an ordinary payment (about 154 vB alone, or one more 43 vB output in a payment made anyway).

import fs from 'node:fs';
import { witnessFor, opReturn } from '../../indexer/test/helpers.js';

const varint = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
const stack = (items) => varint(items.length) + items.reduce((s, x) => s + varint(x.length) + x.length, 0);
const vsize = (base, witness) => Math.ceil((4 * base + witness) / 4);
const P2TR_OUT = 8 + 1 + 34;
const INPUT = 36 + 1 + 4;
const FRAME = 4 + 1 + 1 + 4; // version, input count, output count, locktime

function reveal(envelope) {
  const witness = 2 + stack(witnessFor(envelope)); // marker and flag, then the stack
  return { envelope: envelope.length, witness, vsize: vsize(FRAME + INPUT + P2TR_OUT, witness) };
}

/** One key-path P2TR input, the OP_RETURN envelope and one P2TR change output. */
function opReturnTx(envelope) {
  const script = opReturn(envelope);
  const base = FRAME + INPUT + (8 + varint(script.length) + script.length) + P2TR_OUT;
  return { envelope: envelope.length, witness: 2 + stack([Buffer.alloc(64)]), vsize: vsize(base, 2 + stack([Buffer.alloc(64)])) };
}

const fixture = JSON.parse(fs.readFileSync(process.argv[2] || new URL('../../indexer/test/fixtures/plonk-scenario.json', import.meta.url), 'utf8'));
const transfer = Buffer.from(fixture.transfer, 'hex');
const burn = Buffer.from(fixture.burn, 'hex');
const withProof = (env, bytes) => Buffer.concat([env.subarray(0, env.length - 480 - 2), Buffer.alloc(2), Buffer.alloc(bytes)]);

const rows = [
  ['P2TR payment, 1 input, 2 outputs (reference)', { envelope: 0, witness: 2 + stack([Buffer.alloc(64)]), vsize: vsize(FRAME + INPUT + 2 * P2TR_OUT, 2 + stack([Buffer.alloc(64)])) }],
  ['MINT, OP_RETURN (74-byte envelope)', opReturnTx(Buffer.alloc(74))],
  ['TRANSFER reveal, PLONK proof (480 bytes)', reveal(transfer)],
  ['BURN reveal, PLONK proof (480 bytes)', reveal(burn)],
  ['TRANSFER reveal, fflonk proof (608 bytes)', reveal(withProof(transfer, 608))],
  ['TRANSFER reveal, tightest Halo2 layout (800 bytes)', reveal(withProof(transfer, 800))],
  ['TRANSFER reveal, narrow Halo2 layout (992 bytes)', reveal(withProof(transfer, 992))],
  ['TRANSFER reveal, Tacit Halo2 proof (2,080 bytes)', reveal(withProof(transfer, 2080))],
];
for (const [name, r] of rows) console.log(`${name.padEnd(52)} envelope ${String(r.envelope).padStart(5)} B   witness ${String(r.witness).padStart(5)} B   ${String(r.vsize).padStart(4)} vB`);
