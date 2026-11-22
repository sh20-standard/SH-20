// What each way of sharing a proof would put on chain, for the table "Batches and the 150 vB target"
// of ../README.md. Sizes only: no envelope here is a rule, and only the first row exists.
//
//   node batch-vsize.mjs [transfers, default 10]
//
// The transaction is the reveal of ../bench/tx-vsize.mjs with several envelopes in its tapscript
// (docs/SPEC-WIRE.md §3): one script-path input, one P2TR output, and for each envelope
//   OP_0 OP_IF <"SH20"> <pushes of at most 520 bytes> OP_ENDIF
// vsize = ceil((4 × non-witness bytes + witness bytes) / 4), BIP141. The commit that funds it is
// not counted, as in tx-vsize.mjs: an ordinary payment, about 154 vB, shared by the batch.

import { pushData } from '../../indexer/test/helpers.js';

const N = Number(process.argv[2] ?? 10);
const varint = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
const P2TR_OUT = 8 + 1 + 34;
const INPUT = 36 + 1 + 4;
const FRAME = 4 + 1 + 1 + 4; // version, input count, output count, locktime
const MAGIC = Buffer.from('SH20');

/** The tapscript that carries envelopes of these sizes, as indexer/test/helpers.js builds it for one. */
function script(sizes) {
  const parts = [Buffer.from([0x20]), Buffer.alloc(32, 7), Buffer.from([0xac])];
  for (const size of sizes) {
    parts.push(Buffer.from([0x00, 0x63]), pushData(MAGIC));
    for (let left = size - MAGIC.length; left > 0; left -= 520) parts.push(pushData(Buffer.alloc(Math.min(left, 520))));
    parts.push(Buffer.from([0x68]));
  }
  return Buffer.concat(parts);
}

/** Witness bytes and virtual size of the reveal that carries envelopes of these sizes. */
function reveal(sizes) {
  const stack = [Buffer.alloc(64), script(sizes), Buffer.alloc(33)]; // signature, tapscript, control block
  const witness = 2 + varint(stack.length) + stack.reduce((s, x) => s + varint(x.length) + x.length, 0);
  return { witness, vsize: Math.ceil((4 * (FRAME + INPUT + P2TR_OUT) + witness) / 4) };
}

// Bytes of an envelope. A spend names its anchor (4), its nullifiers (32 each) and, for each output,
// a leaf (32), an ephemeral key (32) and a ciphertext (28): docs/SPEC-WIRE.md §4.
const HEADER = 6; // "SH20", version, type
const PLONK = 480;
const spend = ({ inputs = 2, outputs = 3, keys = outputs, sealed = outputs }) => 4 + 32 * inputs + 32 * outputs + 32 * keys + 28 * sealed;
const envelope = (spends, proof = PLONK) => HEADER + spends.reduce((s, x) => s + spend(x), 0) + proof;
const many = (n, x) => Array.from({ length: n }, () => x);

const today = envelope([{}]);
if (today !== 830) throw new Error(`a TRANSFER is 830 bytes, not ${today}`);
const groups = (per) => Array.from({ length: Math.ceil(N / per) }, (_, i) => Math.min(per, N - i * per));

const rows = [
  [`today: ${N} TRANSFERs, a proof each`, many(N, today), N],
  ['one ephemeral key for the three outputs of a transfer', many(N, envelope([{ keys: 1 }])), N],
  ["the relayer's output as a leaf alone (no key, no ciphertext)", many(N, envelope([{ keys: 2, sealed: 2 }])), N],
  ['both of the above', many(N, envelope([{ keys: 1, sealed: 2 }])), N],
  ['two outputs instead of three', many(N, envelope([{ outputs: 2 }])), N],
  ['two outputs, one ephemeral key', many(N, envelope([{ outputs: 2, keys: 1 }])), N],
  ['no ciphertext on chain at all (leaves and nullifiers only)', many(N, envelope([{ keys: 0, sealed: 0 }])), N],
  ['openings shared by the batch (7 points and 6 scalars each, 2 points for all)', [...many(N - 1, today - 64), today], N],
  ['a Groth16 proof each (128 bytes)', many(N, envelope([{}], 128)), N],
  ['two transfers under one proof', groups(2).map((k) => envelope(many(k, {}))), N],
  ['three transfers under one proof', groups(3).map((k) => envelope(many(k, {}))), N],
  [`the ${N} transfers under one proof`, [envelope(many(N, {}))], N],
  [`one transfer that pays ${N} people and keeps the change (2 inputs, ${N + 1} outputs)`, [envelope([{ outputs: N + 1 }])], N],
  ['the same with one ephemeral key', [envelope([{ outputs: N + 1, keys: 1 }])], N],
  ['one transfer that pays 24 people (2 inputs, 25 outputs: what a domain of 2^17 holds)', [envelope([{ outputs: 25 }])], 24],
];

console.log(`${'layout'.padEnd(84)} envelopes         witness   reveal   per transfer`);
for (const [name, sizes, transfers] of rows) {
  const r = reveal(sizes);
  const kinds = [...new Set(sizes)].map((s) => `${sizes.filter((x) => x === s).length}×${s}`).join(' + ');
  console.log(`${name.padEnd(84)} ${kinds.padEnd(16)} ${String(r.witness).padStart(6)} B ${String(r.vsize).padStart(5)} vB ${(r.vsize / transfers).toFixed(1).padStart(8)} vB`);
}

// Where the target stops being reachable with a proof for each transfer.
const perTransfer = (bytes) => reveal(many(N, bytes)).vsize / N;
let most = today;
while (perTransfer(most) > 150) most -= 1;
console.log(`\n150 vB each at n = ${N} leaves ${most} bytes for an envelope: ${most - HEADER - PLONK} for everything but its header and a 480-byte proof.`);
console.log(`Two nullifiers and three leaves are ${32 * 5} bytes; an anchor, two nullifiers and two leaves are ${4 + 32 * 4}.`);
