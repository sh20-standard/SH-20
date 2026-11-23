// What the relayer checks of a TRANSFER before it takes it (docs/RELAYER.md §2), the cheapest first:
// the bytes, the spend's own rules, then (relayer.js) the anchor, the nullifiers, the fee, the proof.
// Every refusal is a Refusal with the HTTP status the relayer answers.

import { parseEnvelope, bodyHash } from '../../vault/src/sh20.js';
import { scanOutput } from '../../vault/src/notekeys.js';
import { frHex } from '../../vault/src/fr.js';

/** A TRANSFER of wire v0.3: header (6) and spend section (824). */
export const TRANSFER_BYTES = 830;

export class Refusal extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** The envelope's bytes from the hex a sender posts. */
export function fromHexBody(text) {
  const s = String(text ?? '').trim().toLowerCase();
  if (!/^([0-9a-f]{2})+$/.test(s)) throw new Refusal(400, 'the body must be the envelope in hex');
  return Uint8Array.from(Buffer.from(s, 'hex'));
}

/**
 * Steps 1 and 2: 830 bytes, "SH20", version 0, type TRANSFER, parsed by the indexer's codec (which gives
 * the same bytes back or refuses them); two non-zero
 * distinct nullifiers, three non-zero leaves (docs/SPEC-WIRE.md §4, §5).
 * Returns { env, bytes, nullifiers (hex, as /nullifiers gives them), anchorHeight }.
 */
export function decodeTransfer(bytes) {
  if (bytes.length !== TRANSFER_BYTES) throw new Refusal(400, `a TRANSFER of wire v0.3 is ${TRANSFER_BYTES} bytes, not ${bytes.length}`);
  let env, body;
  try {
    ({ env, body } = parseEnvelope(Buffer.from(bytes))); // refuses trailing bytes and any other encoding of the same envelope
  } catch (e) {
    throw new Refusal(400, `not an SH-20 envelope of this version: ${e.message}`);
  }
  if (env.type !== 'TRANSFER') throw new Refusal(400, `a ${env.type}, not a TRANSFER: a relayer publishes transfers only`);
  const { nf, outs, anchorHeight } = env.spend;
  if (nf.some((x) => x === 0n) || nf[0] === nf[1]) throw new Refusal(400, 'the two nullifiers must be non-zero and distinct');
  if (outs.some((o) => o.leaf === 0n)) throw new Refusal(400, 'an output leaf is zero');
  return { env, bytes, body: Uint8Array.from(body), nullifiers: nf.map(frHex), anchorHeight };
}

/**
 * Step 3: the anchor, for a batch that confirms in block `next` at the earliest. `W`, `kMin` are the
 * profile's; the deadline `anchorHeight + W` is the last block that accepts the transfer.
 */
export function checkAnchor(anchorHeight, { next, W, kMin, minBlocksLeft }) {
  if (anchorHeight > next - kMin) throw new Refusal(422, `the anchor ${anchorHeight} is less than K_min = ${kMin} block(s) below block ${next}`);
  const deadline = anchorHeight + W;
  if (deadline - next < minBlocksLeft) {
    throw new Refusal(422, `the anchor ${anchorHeight} leaves ${Math.max(0, deadline - next)} block(s) before the transfer runs out (block ${deadline}); this relayer needs ${minBlocksLeft}: anchor it to a recent block`);
  }
  return deadline;
}

/**
 * Step 5: the outputs that open with the relayer's viewing key and hash to their leaf (scanOutput,
 * circuit/js), their ticker one it prices, their amount together at least its fee.
 * Returns { ticker, v, outputs: [index…] }.
 */
export async function feeOf(notes, env, fees) {
  let ticker = null;
  let v = 0n;
  const outputs = [];
  for (const [i, o] of env.spend.outs.entries()) {
    const got = await scanOutput(notes, { leaf: o.leaf, pkEph: Uint8Array.from(o.pkEph), ct: Uint8Array.from(o.ct) });
    if (!got || got.v === 0n) continue;
    ticker = got.ticker; // one ticker for the five notes of a spend
    v += got.v;
    outputs.push(i);
  }
  if (!outputs.length) throw new Refusal(402, 'no output pays this relayer: seal its fee to the address at /info');
  const price = fees.get(ticker);
  if (price === undefined) throw new Refusal(402, `this relayer takes no fee in ${ticker} (see /info)`);
  if (v < price) throw new Refusal(402, `the fee is ${v} ${ticker}, this relayer asks ${price}`);
  return { ticker, v, outputs };
}

/** Step 6's inputs: the nine public inputs of docs/SPEC-WIRE.md §4, as the indexer's verifier takes them. */
export function verifierArgs(t, root) {
  const { nf, outs, proof } = t.env.spend;
  return {
    root, nullifiers: nf, outLeaves: outs.map((o) => o.leaf),
    bodyHash: bodyHash(t.body), vPub: 0n, tPub: 0n, proof: Uint8Array.from(proof),
  };
}
