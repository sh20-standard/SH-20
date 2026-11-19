//! The building blocks of the spend circuit, in plain PLONK gates: Poseidon, bit decompositions,
//! BabyJubJub arithmetic, EdDSA-Poseidon verification and the Merkle path.
//!
//! Each block constrains exactly the function of the same name in `model` (or `poseidon`).
//! The EdDSA verifier follows circomlib's EdDSAPoseidonVerifier, as used by Tacit's Bitcoin shielded
//! pool (MIT License, Copyright (c) 2026 ross).

use crate::cs::{Cs, Var};
use crate::model::{self, Pt, BJJ_A, BJJ_D};
use crate::poseidon::{self, pow5};
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use num_bigint::BigUint;

fn fr_u(x: u64) -> Fr {
    Fr::from(x)
}
fn inv0(x: Fr) -> Fr {
    x.inverse().unwrap_or(Fr::zero())
}

// ── Poseidon ──

/// One lane of a Poseidon state: a circuit constant or a variable.
#[derive(Clone, Copy, Debug)]
pub enum Lane {
    Const(Fr),
    Var(Var),
}

/// circomlib `Poseidon(inputs.len())` for 2..5 inputs: state [0, inputs…], output state[0].
pub fn poseidon(cs: &mut Cs, inputs: &[Lane]) -> Var {
    let t = inputs.len() + 1;
    let p = poseidon::params(t);
    let mut state: Vec<Lane> = Vec::with_capacity(t);
    state.push(Lane::Const(Fr::zero()));
    state.extend_from_slice(inputs);

    let rounds = p.rounds();
    for r in 0..rounds {
        let full = p.is_full(r);
        // after the round constants and the S-box, lane j is `var + k` (or the constant k)
        let mut lanes: Vec<(Option<Var>, Fr)> = Vec::with_capacity(t);
        for (j, lane) in state.iter().enumerate() {
            let rc = p.c[r * t + j];
            let sbox = full || j == 0;
            lanes.push(match (*lane, sbox) {
                (Lane::Const(k), true) => (None, pow5(k + rc)),
                (Lane::Const(k), false) => (None, k + rc),
                (Lane::Var(x), false) => (Some(x), rc),
                (Lane::Var(x), true) => {
                    // (x + rc)^5 in three gates
                    let x2 = cs.quad(x, x, Fr::one(), rc + rc, Fr::zero(), rc.square());
                    let x4 = cs.mul(x2, x2);
                    let x5 = cs.quad(x4, x, Fr::one(), rc, Fr::zero(), Fr::zero());
                    (Some(x5), Fr::zero())
                }
            });
        }
        // the last round only needs lane 0
        let outs = if r + 1 == rounds { 1 } else { t };
        state = (0..outs)
            .map(|i| {
                let mut terms = Vec::with_capacity(t);
                let mut k = Fr::zero();
                for (j, (var, c)) in lanes.iter().enumerate() {
                    k += p.m[i][j] * c;
                    if let Some(x) = var {
                        terms.push((p.m[i][j], *x));
                    }
                }
                if terms.is_empty() {
                    Lane::Const(k)
                } else {
                    Lane::Var(cs.lc(&terms, k))
                }
            })
            .collect();
    }
    match state[0] {
        Lane::Var(x) => x,
        Lane::Const(k) => cs.constant(k),
    }
}

pub fn poseidon_vars(cs: &mut Cs, inputs: &[Var]) -> Var {
    let lanes: Vec<Lane> = inputs.iter().map(|x| Lane::Var(*x)).collect();
    poseidon(cs, &lanes)
}

// ── bits ──

/// Σ bits[i]·2^i as a new variable (the bits are not constrained here).
pub fn recompose(cs: &mut Cs, bits: &[Var]) -> Var {
    assert!(!bits.is_empty());
    let terms: Vec<(Fr, Var)> = bits.iter().enumerate().map(|(i, b)| (Fr::from(2u64).pow([i as u64]), *b)).collect();
    cs.lc(&terms, Fr::zero())
}

/// The n low bits of x, least significant first: each is boolean and Σ bits[i]·2^i = x in the
/// field. For n ≤ 253 this makes x < 2^n; a 254-bit decomposition needs `canonical_bits_254`.
pub fn to_bits(cs: &mut Cs, x: Var, n: usize) -> Vec<Var> {
    assert!((1..=254).contains(&n));
    let v = cs.value(x);
    let bits: Vec<Var> = (0..n).map(|i| cs.alloc(if model::bit(&v, i) { Fr::one() } else { Fr::zero() })).collect();
    for b in &bits {
        cs.assert_bool(*b);
    }
    tie(cs, &bits, x);
    bits
}

/// Σ bits[i]·2^i = x, the last gate of the chain landing on x itself.
fn tie(cs: &mut Cs, bits: &[Var], x: Var) {
    let n = bits.len();
    if n == 1 {
        cs.assert_eq(bits[0], x);
        return;
    }
    let pow = |i: usize| Fr::from(2u64).pow([i as u64]);
    let mut acc = bits[0];
    for (i, b) in bits.iter().enumerate().take(n - 1).skip(1) {
        acc = cs.lin2(Fr::one(), acc, pow(i), *b, Fr::zero());
    }
    cs.gate(acc, bits[n - 1], x, [Fr::one(), pow(n - 1), -Fr::one(), Fr::zero(), Fr::zero()]);
}

/// 0 ≤ x < 2^n, n ≤ 253.
pub fn range(cs: &mut Cs, x: Var, n: usize) {
    assert!(n <= 253);
    to_bits(cs, x, n);
}

/// The 251 bits of a scalar 0 ≤ x < l (the BabyJubJub subgroup order): x < 2^251 by the
/// decomposition and l − 1 − x < 2^251, which holds exactly when x ≤ l − 1.
pub fn scalar_bits(cs: &mut Cs, x: Var) -> Vec<Var> {
    let bits = to_bits(cs, x, 251);
    let gap = cs.lin1(-Fr::one(), x, model::fr(&(model::l_big() - 1u8)));
    range(cs, gap, 251);
    bits
}

/// The 254 bits of the canonical integer of x: with p = p_hi·2^128 + p_lo, the high 126 bits are at
/// most p_hi, and when they equal p_hi the low 128 bits are below p_lo.
pub fn canonical_bits_254(cs: &mut Cs, x: Var) -> Vec<Var> {
    let v = cs.value(x);
    let bits: Vec<Var> = (0..254).map(|i| cs.alloc(if model::bit(&v, i) { Fr::one() } else { Fr::zero() })).collect();
    for b in &bits {
        cs.assert_bool(*b);
    }
    let lo = recompose(cs, &bits[..128]);
    let hi = recompose(cs, &bits[128..]);
    let two128 = Fr::from(2u64).pow([128u64]);
    cs.gate(lo, hi, x, [Fr::one(), two128, -Fr::one(), Fr::zero(), Fr::zero()]);

    let p = model::p_big();
    let mask: BigUint = (BigUint::from(1u8) << 128usize) - 1u8;
    let (p_hi, p_lo) = (model::fr(&(&p >> 128usize)), model::fr(&(&p & &mask)));
    let hi_gap = cs.lin1(-Fr::one(), hi, p_hi);
    range(cs, hi_gap, 126);
    let hi_eq = cs.is_zero(hi_gap);
    let lo_gap = cs.lin1(-Fr::one(), lo, p_lo - Fr::one());
    let guarded = cs.mul(lo_gap, hi_eq);
    range(cs, guarded, 128);
    bits
}

// ── BabyJubJub ──

pub type Point = [Var; 2];

/// P is a point of the curve: a·x² + y² = 1 + d·x²·y², in four gates.
pub fn assert_on_curve(cs: &mut Cs, p: Point) {
    let (a, d) = (fr_u(BJJ_A), fr_u(BJJ_D));
    let x2 = cs.mul(p[0], p[0]);
    let y2 = cs.mul(p[1], p[1]);
    let x2y2 = cs.mul(x2, y2);
    cs.gate(x2, y2, x2y2, [a, Fr::one(), -d, Fr::zero(), -Fr::one()]);
}

/// P + Q by the unified law. The outputs are determined by the operands, on the curve or not: a
/// denominator 1 ± d·x1·x2·y1·y2 cannot vanish together with its numerator, because d and a·d are
/// not squares. For operands on the curve neither denominator vanishes and this is the group law.
pub fn ec_add(cs: &mut Cs, p: Point, q: Point) -> Point {
    let (a, d) = (fr_u(BJJ_A), fr_u(BJJ_D));
    let beta = cs.mul(p[0], q[1]);
    let gamma = cs.mul(p[1], q[0]);
    let tau = cs.mul(beta, gamma);
    let w = cs.add(beta, gamma);
    let yy = cs.mul(p[1], q[1]);
    let xx = cs.mul(p[0], q[0]);
    let delta = cs.lin2(Fr::one(), yy, -a, xx, Fr::zero());
    finish_add(cs, tau, w, delta, d)
}

/// x3·(1 + d·τ) = w and y3·(1 − d·τ) = δ.
fn finish_add(cs: &mut Cs, tau: Var, w: Var, delta: Var, d: Fr) -> Point {
    let t = cs.value(tau);
    let x3 = cs.alloc(cs.value(w) * inv0(Fr::one() + d * t));
    cs.gate(x3, tau, w, [Fr::one(), Fr::zero(), -Fr::one(), d, Fr::zero()]);
    let y3 = cs.alloc(cs.value(delta) * inv0(Fr::one() - d * t));
    cs.gate(y3, tau, delta, [Fr::one(), Fr::zero(), -Fr::one(), -d, Fr::zero()]);
    [x3, y3]
}

/// bit ? c : identity, for a constant point c and a boolean bit.
fn const_or_identity(cs: &mut Cs, bit: Var, c: &Pt) -> Point {
    [cs.lin1(c[0], bit, Fr::zero()), cs.lin1(c[1] - Fr::one(), bit, Fr::one())]
}

/// bit ? P : identity, for a boolean bit.
fn point_or_identity(cs: &mut Cs, bit: Var, p: Point) -> Point {
    [cs.mul(bit, p[0]), cs.quad(bit, p[1], Fr::one(), -Fr::one(), Fr::zero(), Fr::one())]
}

/// P + (bit ? c : identity) for a constant point c on the curve and a boolean bit.
fn add_const_if(cs: &mut Cs, p: Point, bit: Var, c: &Pt) -> Point {
    let (a, d) = (fr_u(BJJ_A), fr_u(BJJ_D));
    // the addend is (bit·cx, 1 + bit·(cy − 1))
    let cy1 = c[1] - Fr::one();
    let beta = cs.quad(p[0], bit, cy1, Fr::one(), Fr::zero(), Fr::zero());
    let gamma = cs.quad(p[1], bit, c[0], Fr::zero(), Fr::zero(), Fr::zero());
    let tau = cs.mul(beta, gamma);
    let w = cs.add(beta, gamma);
    let yy = cs.quad(p[1], bit, cy1, Fr::one(), Fr::zero(), Fr::zero());
    let xb = cs.mul(p[0], bit);
    let delta = cs.lin2(Fr::one(), yy, -a * c[0], xb, Fr::zero());
    finish_add(cs, tau, w, delta, d)
}

/// Σ bits[i]·2^i·base for a constant base on the curve; the bits are boolean, least significant first.
pub fn fixed_mul(cs: &mut Cs, bits: &[Var], base: &Pt) -> Point {
    let mut table = *base;
    let mut acc = const_or_identity(cs, bits[0], &table);
    for b in &bits[1..] {
        table = model::add(&table, &table);
        acc = add_const_if(cs, acc, *b, &table);
    }
    acc
}

/// (Σ bits[i]·2^i)·P by double-and-add from the top bit; the bits are boolean, least significant first.
pub fn var_mul(cs: &mut Cs, bits: &[Var], p: Point) -> Point {
    let n = bits.len();
    let mut acc = point_or_identity(cs, bits[n - 1], p);
    for b in bits[..n - 1].iter().rev() {
        acc = ec_add(cs, acc, acc);
        let addend = point_or_identity(cs, *b, p);
        acc = ec_add(cs, acc, addend);
    }
    acc
}

// ── EdDSA-Poseidon ──

/// S·B8 = R8 + h·8·A with h = Poseidon(R8, A, m), for A and R8 on the curve, 0 ≤ S < l, h taken as
/// its canonical 254-bit integer, and 4·A not of the form (0, ±1) (A is not a small-order point).
///
/// circomlib's verifier does not check that A and R8 are on the curve. Here they are: every addition
/// below is then the group law, and the equation is the one EdDSA is proved secure for.
pub fn eddsa_verify(cs: &mut Cs, a: Point, r8: Point, s: Var, m: Var) {
    assert_on_curve(cs, a);
    assert_on_curve(cs, r8);

    let s_bits = scalar_bits(cs, s);
    let left = fixed_mul(cs, &s_bits, &model::base8());

    let h = poseidon_vars(cs, &[r8[0], r8[1], a[0], a[1], m]);
    let h_bits = canonical_bits_254(cs, h);

    let a2 = ec_add(cs, a, a);
    let a4 = ec_add(cs, a2, a2);
    cs.assert_nonzero(a4[0]);
    let a8 = ec_add(cs, a4, a4);

    let ha = var_mul(cs, &h_bits, a8);
    let right = ec_add(cs, r8, ha);
    cs.assert_eq(left[0], right[0]);
    cs.assert_eq(left[1], right[1]);
}

// ── Merkle path ──

/// The root reached from `leaf` along `path`; `index_bits` are boolean, level 0 first.
pub fn merkle_root(cs: &mut Cs, leaf: Var, index_bits: &[Var], path: &[Var]) -> Var {
    assert_eq!(index_bits.len(), path.len());
    let mut cur = leaf;
    for (bit, sib) in index_bits.iter().zip(path) {
        // (left, right) = bit ? (sib, cur) : (cur, sib)
        let diff = cs.sub(*sib, cur);
        let m = cs.mul(*bit, diff);
        let left = cs.add(cur, m);
        let right = cs.sub(*sib, m);
        cur = poseidon_vars(cs, &[left, right]);
    }
    cur
}
