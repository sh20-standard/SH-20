// BabyJubJub, the curve of note keys and spend signatures:
//   168700·x² + y² = 1 + 168696·x²·y²   over the BN254 scalar field.
// Points are [x, y] pairs of BigInt. Mirrors circuit/src/model.rs.
//
// Reference code: BigInt arithmetic is not constant-time. A wallet that signs with it leaks timing.

import { P } from '../../indexer/src/poseidon.js';

export const A = 168700n;
export const D = 168696n;
/** Order of the prime subgroup. */
export const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
/** circomlib's Base8, the generator of the prime subgroup used for keys and signatures. */
export const BASE8 = Object.freeze([
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]);
export const IDENTITY = Object.freeze([0n, 1n]);

const mod = (x) => ((x % P) + P) % P;

function pow(base, e) {
  let r = 1n;
  let b = mod(base);
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
}
/** The inverse, or 0 for 0 (the circuit then has no satisfying assignment). */
const inv0 = (x) => pow(x, P - 2n);

/** The unified addition law (circomlib BabyAdd). */
export function add(p, q) {
  const tau = mod(p[0] * q[0] * p[1] * q[1]);
  return [mod((p[0] * q[1] + p[1] * q[0]) * inv0(1n + D * tau)), mod((p[1] * q[1] - A * p[0] * q[0]) * inv0(1n - D * tau))];
}

/** k·P by double-and-add over the bits of k ≥ 0 (no reduction of k). */
export function mul(p, k) {
  if (typeof k !== 'bigint' || k < 0n) throw new RangeError('scalar must be a non-negative BigInt');
  let r = IDENTITY;
  let acc = p;
  for (; k > 0n; k >>= 1n) {
    if (k & 1n) r = add(r, acc);
    acc = add(acc, acc);
  }
  return [r[0], r[1]];
}

/** k·Base8 for 0 ≤ k < l. */
export function mulBase8(k) {
  if (typeof k !== 'bigint' || k < 0n || k >= L) throw new RangeError('scalar must be in [0, l)');
  return mul(BASE8, k);
}

export function onCurve(p) {
  const x2 = mod(p[0] * p[0]);
  const y2 = mod(p[1] * p[1]);
  return p[0] >= 0n && p[0] < P && p[1] >= 0n && p[1] < P && mod(A * x2 + y2) === mod(1n + D * x2 * y2);
}

export const equal = (p, q) => p[0] === q[0] && p[1] === q[1];
