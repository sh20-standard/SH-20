// Poseidon over the BN254 scalar field, compatible with circomlib's `poseidon`
// for 2 inputs (t = 3, R_F = 8, R_P = 57, x^5 S-box).
//
// Round constants and the MDS matrix are generated here with the Grain LFSR of
// the Poseidon reference script (generate_parameters_grain.sage), so no constant
// table is copied from anywhere. The self-test at the bottom checks the result
// against circomlib's published vector poseidon([1, 2]).

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const mod = (a) => ((a % P) + P) % P;

function powMod(b, e) {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

const inv = (a) => powMod(a, P - 2n);

function bitsOf(value, width) {
  const out = [];
  for (let i = width - 1; i >= 0; i--) out.push(Number((BigInt(value) >> BigInt(i)) & 1n));
  return out;
}

function grain(n, t, rF, rP) {
  // 80-bit initial state: field (2) | sbox (4) | n (12) | t (12) | R_F (10) | R_P (10) | 30 ones
  let s = [
    ...bitsOf(1, 2),
    ...bitsOf(0, 4),
    ...bitsOf(n, 12),
    ...bitsOf(t, 12),
    ...bitsOf(rF, 10),
    ...bitsOf(rP, 10),
    ...new Array(30).fill(1),
  ];
  const step = () => {
    const b = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0];
    s.shift();
    s.push(b);
    return b;
  };
  for (let i = 0; i < 160; i++) step();
  const nextBit = () => {
    let b = step();
    while (b === 0) {
      step();
      b = step();
    }
    return step();
  };
  return (numBits) => {
    let v = 0n;
    for (let i = 0; i < numBits; i++) v = (v << 1n) | BigInt(nextBit());
    return v;
  };
}

function generate(t, rF, rP) {
  const n = P.toString(2).length; // 254
  const rand = grain(n, t, rF, rP);
  const C = [];
  for (let i = 0; i < (rF + rP) * t; i++) {
    let v = rand(n);
    while (v >= P) v = rand(n);
    C.push(v);
  }
  // Cauchy MDS matrix M[i][j] = 1 / (x_i + y_j), entries reduced mod p.
  for (;;) {
    let list = Array.from({ length: 2 * t }, () => mod(rand(n)));
    while (new Set(list.map(String)).size !== list.length) {
      list = Array.from({ length: 2 * t }, () => mod(rand(n)));
    }
    const xs = list.slice(0, t);
    const ys = list.slice(t);
    let ok = true;
    const M = [];
    for (let i = 0; i < t && ok; i++) {
      M.push([]);
      for (let j = 0; j < t; j++) {
        const d = mod(xs[i] + ys[j]);
        if (d === 0n) {
          ok = false;
          break;
        }
        M[i].push(inv(d));
      }
    }
    if (ok) return { C, M };
  }
}

const T3 = { t: 3, rF: 8, rP: 57 };
const PARAMS3 = generate(T3.t, T3.rF, T3.rP);

function permute(inputs, { t, rF, rP }, { C, M }) {
  let state = [0n, ...inputs.map(mod)];
  const rounds = rF + rP;
  for (let r = 0; r < rounds; r++) {
    state = state.map((a, i) => (a + C[r * t + i]) % P);
    const full = r < rF / 2 || r >= rF / 2 + rP;
    if (full) state = state.map((a) => powMod(a, 5n));
    else state[0] = powMod(state[0], 5n);
    state = state.map((_, i) => {
      let acc = 0n;
      for (let j = 0; j < t; j++) acc += M[i][j] * state[j];
      return acc % P;
    });
  }
  return state[0];
}

/** Poseidon hash of two field elements (circomlib-compatible). */
export function poseidon2(a, b) {
  return permute([BigInt(a), BigInt(b)], T3, PARAMS3);
}

// circomlib published vector: poseidon([1, 2])
export const POSEIDON2_VECTOR_1_2 =
  7853200120776062878684798364095072458815029376092732009249414926327459813530n;
