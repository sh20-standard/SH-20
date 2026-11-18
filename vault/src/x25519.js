// X25519 (RFC 7748 §5) in plain JavaScript, synchronous: what circuit/js/address.js needs from
// node:crypto in the browser (src/shim/node-crypto.js). WebCrypto has X25519, but only async.
// BigInt arithmetic is not constant time (like circuit/js itself, docs/SPEC-NOTES.md §6).

const P = 2n ** 255n - 19n;
const A24 = 121665n;
const mod = (x) => ((x % P) + P) % P;

function pow(b, e) {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
}

const fromLe = (b) => {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
};
const toLe = (x) => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++, x >>= 8n) out[i] = Number(x & 0xffn);
  return out;
};

/** X25519(k, u) on 32-byte strings: the scalar is clamped, the top bit of u ignored (RFC 7748 §5). */
export function x25519(k, u) {
  if (k.length !== 32 || u.length !== 32) throw new RangeError('x25519: keys are 32 bytes');
  const kb = Uint8Array.from(k);
  kb[0] &= 248;
  kb[31] &= 127;
  kb[31] |= 64;
  const n = fromLe(kb);
  const ub = Uint8Array.from(u);
  ub[31] &= 127;
  const x1 = fromLe(ub) % P;
  let [x2, z2, x3, z3] = [1n, 0n, x1, 1n];
  let swap = 0n;
  for (let t = 254n; t >= 0n; t--) {
    const bit = (n >> t) & 1n;
    if (swap ^ bit) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = bit;
    const A = mod(x2 + z2);
    const AA = (A * A) % P;
    const B = mod(x2 - z2);
    const BB = (B * B) % P;
    const E = mod(AA - BB);
    const C = mod(x3 + z3);
    const D = mod(x3 - z3);
    const DA = (D * A) % P;
    const CB = (C * B) % P;
    x3 = mod((DA + CB) ** 2n);
    z3 = (x1 * mod((DA - CB) ** 2n)) % P;
    x2 = (AA * BB) % P;
    z2 = (E * mod(AA + A24 * E)) % P;
  }
  if (swap) [x2, z2] = [x3, z3];
  return toLe((x2 * pow(z2, P - 2n)) % P);
}

const NINE = toLe(9n);
export const x25519Base = (k) => x25519(k, NINE);
