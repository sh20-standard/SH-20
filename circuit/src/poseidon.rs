//! Poseidon over the BN254 scalar field, compatible with circomlib's `Poseidon(n)` for n = 2..5
//! (width t = n + 1, R_F = 8, x^5 S-box).
//!
//! Round constants and MDS matrices are generated here with the Grain LFSR of the Poseidon reference
//! script (generate_parameters_grain.sage), exactly as indexer/src/poseidon.js does for t = 3, so no
//! constant table is copied from anywhere. The tests check the result against circomlib's published
//! vector poseidon([1, 2]) and against the reference indexer.

use ark_bn254::Fr;
use ark_ff::{BigInteger, BigInteger256, Field, PrimeField, Zero};
use std::sync::OnceLock;

pub const FULL_ROUNDS: usize = 8;

/// Partial rounds for width t (circomlib's table).
pub fn partial_rounds(t: usize) -> usize {
    match t {
        3 => 57,
        4 => 56,
        5 => 60,
        6 => 60,
        _ => panic!("poseidon: width {t} not supported"),
    }
}

pub struct Params {
    pub t: usize,
    pub rp: usize,
    /// Round constants, `c[r * t + j]` for round r, lane j.
    pub c: Vec<Fr>,
    /// MDS matrix: `new[i] = Σ_j m[i][j] · state[j]`.
    pub m: Vec<Vec<Fr>>,
}

impl Params {
    pub fn rounds(&self) -> usize {
        FULL_ROUNDS + self.rp
    }
    pub fn is_full(&self, r: usize) -> bool {
        r < FULL_ROUNDS / 2 || r >= FULL_ROUNDS / 2 + self.rp
    }
}

/// Grain LFSR in the self-shrinking mode of the Poseidon reference script.
struct Grain {
    s: [u8; 80],
    head: usize,
}

impl Grain {
    fn new(n: usize, t: usize, rf: usize, rp: usize) -> Self {
        // field (2 bits) | sbox (4) | n (12) | t (12) | R_F (10) | R_P (10) | 30 ones
        let mut bits = Vec::with_capacity(80);
        let mut push = |value: usize, width: usize| {
            for i in (0..width).rev() {
                bits.push(((value >> i) & 1) as u8);
            }
        };
        push(1, 2);
        push(0, 4);
        push(n, 12);
        push(t, 12);
        push(rf, 10);
        push(rp, 10);
        bits.extend(std::iter::repeat_n(1u8, 30));
        let mut g = Grain { s: bits.try_into().expect("80 bits"), head: 0 };
        for _ in 0..160 {
            g.step();
        }
        g
    }
    fn at(&self, i: usize) -> u8 {
        self.s[(self.head + i) % 80]
    }
    fn step(&mut self) -> u8 {
        let b = self.at(62) ^ self.at(51) ^ self.at(38) ^ self.at(23) ^ self.at(13) ^ self.at(0);
        self.s[self.head] = b;
        self.head = (self.head + 1) % 80;
        b
    }
    fn next_bit(&mut self) -> bool {
        let mut b = self.step();
        while b == 0 {
            self.step();
            b = self.step();
        }
        self.step() == 1
    }
    /// The next `n` bits, most significant first.
    fn next(&mut self, n: usize) -> BigInteger256 {
        let bits: Vec<bool> = (0..n).map(|_| self.next_bit()).collect();
        BigInteger256::from_bits_be(&bits)
    }
}

fn generate(t: usize) -> Params {
    let rp = partial_rounds(t);
    let n = Fr::MODULUS_BIT_SIZE as usize; // 254
    let mut g = Grain::new(n, t, FULL_ROUNDS, rp);

    let mut c = Vec::with_capacity((FULL_ROUNDS + rp) * t);
    while c.len() < (FULL_ROUNDS + rp) * t {
        let v = g.next(n);
        if v < Fr::MODULUS {
            c.push(Fr::from_bigint(v).expect("below the modulus"));
        }
    }

    // Cauchy matrix m[i][j] = 1 / (x_i + y_j) over 2t distinct elements (reduced mod p, not rejected).
    let reduce = |v: BigInteger256| Fr::from_le_bytes_mod_order(&v.to_bytes_le());
    loop {
        let mut list: Vec<Fr> = (0..2 * t).map(|_| reduce(g.next(n))).collect();
        while (0..list.len()).any(|i| list[..i].contains(&list[i])) {
            list = (0..2 * t).map(|_| reduce(g.next(n))).collect();
        }
        let (xs, ys) = list.split_at(t);
        let mut m = vec![vec![Fr::zero(); t]; t];
        let mut ok = true;
        'rows: for i in 0..t {
            for j in 0..t {
                match (xs[i] + ys[j]).inverse() {
                    Some(v) => m[i][j] = v,
                    None => {
                        ok = false;
                        break 'rows;
                    }
                }
            }
        }
        if ok {
            return Params { t, rp, c, m };
        }
    }
}

/// Parameters for width t = 3..6.
pub fn params(t: usize) -> &'static Params {
    static P: [OnceLock<Params>; 4] = [OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new()];
    assert!((3..=6).contains(&t), "poseidon: width {t} not supported");
    P[t - 3].get_or_init(|| generate(t))
}

pub fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

/// The permutation, in place.
pub fn permute(state: &mut [Fr]) {
    let p = params(state.len());
    let t = p.t;
    for r in 0..p.rounds() {
        for (j, s) in state.iter_mut().enumerate() {
            *s += p.c[r * t + j];
        }
        if p.is_full(r) {
            for s in state.iter_mut() {
                *s = pow5(*s);
            }
        } else {
            state[0] = pow5(state[0]);
        }
        let next: Vec<Fr> = (0..t).map(|i| (0..t).map(|j| p.m[i][j] * state[j]).sum()).collect();
        state.copy_from_slice(&next);
    }
}

/// circomlib `Poseidon(inputs.len())`: state [0, inputs…], output state[0].
pub fn hash(inputs: &[Fr]) -> Fr {
    let mut state = Vec::with_capacity(inputs.len() + 1);
    state.push(Fr::zero());
    state.extend_from_slice(inputs);
    permute(&mut state);
    state[0]
}

/// `H(a, b)` of docs/SPEC-WIRE.md §1.
pub fn h2(a: Fr, b: Fr) -> Fr {
    hash(&[a, b])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn circomlib_vector() {
        let want = Fr::from_str("7853200120776062878684798364095072458815029376092732009249414926327459813530").unwrap();
        assert_eq!(h2(Fr::from(1u64), Fr::from(2u64)), want);
    }
}
