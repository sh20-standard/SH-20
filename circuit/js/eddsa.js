// EdDSA-Poseidon over BabyJubJub, the authorisation of a spend: the owner of Ak signs bodyHash.
//
//   h = Poseidon(R8.x, R8.y, Ak.x, Ak.y, m)        as its integer below r
//   S·B8 = R8 + h·8·Ak,   0 ≤ S < l,   4·Ak has a non-zero x
//
// The circuit checks exactly these (circuit/src/gadgets.rs eddsa_verify). The nonce is a wallet's own
// business, any nonce gives a valid signature; `sign` derives it from the key and the message as
// circuit/src/model.rs does, which is what makes the vectors reproducible:
//   r = (SHA256(tag ‖ sk ‖ m ‖ 0x00) ‖ SHA256(tag ‖ sk ‖ m ‖ 0x01)) mod l,  sk and m as 32 bytes big-endian.

import { createHash } from 'node:crypto';
import { FR } from '../../indexer/src/constants.js';
import { poseidon } from '../../indexer/src/poseidon.js';
import { L, add, equal, mul, mulBase8, onCurve } from './babyjub.js';

export const NONCE_TAG = 'sh20/v0/eddsa-nonce';

const be32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');

/** 512 bits of SHA-256 output over tag ‖ parts, reduced modulo l (never 0). */
export function hashToScalar(tag, ...parts) {
  const half = (last) => createHash('sha256').update(tag, 'utf8').update(Buffer.concat(parts)).update(Buffer.from([last])).digest('hex');
  const x = BigInt(`0x${half(0)}${half(1)}`) % L;
  if (x === 0n) throw new Error('zero scalar');
  return x;
}

const challenge = (r8, ak, m) => poseidon([r8[0], r8[1], ak[0], ak[1], m]);

/** Signs the field element `m` (a bodyHash) with the note's spend scalar `sk` in [1, l). */
export function sign(sk, m) {
  if (typeof sk !== 'bigint' || sk <= 0n || sk >= L) throw new RangeError('sk must be a BigInt in [1, l)');
  if (typeof m !== 'bigint' || m < 0n || m >= FR) throw new RangeError('the message must be a field element');
  const ak = mulBase8(sk);
  const r = hashToScalar(NONCE_TAG, be32(sk), be32(m));
  const r8 = mulBase8(r);
  return { r8, s: (r + 8n * challenge(r8, ak, m) * sk) % L };
}

/** True iff the circuit accepts (r8, s) as a signature of `m` under `ak`. */
export function verify(ak, m, { r8, s }) {
  if (typeof m !== 'bigint' || m < 0n || m >= FR) return false;
  if (typeof s !== 'bigint' || s < 0n || s >= L) return false;
  if (!onCurve(ak) || !onCurve(r8)) return false;
  if (mul(ak, 4n)[0] === 0n) return false; // a small-order key
  return equal(mulBase8(s), add(r8, mul(mul(ak, 8n), challenge(r8, ak, m))));
}
