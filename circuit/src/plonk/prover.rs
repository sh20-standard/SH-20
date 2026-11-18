//! The prover: the five rounds of section 8.3 of the PLONK paper.
//!
//! Wire and permutation polynomials are blinded with random multiples of the vanishing polynomial
//! (b1..b9 of the paper) and the quotient parts with b10, b11, so a proof reveals nothing about the
//! assignment. The quotient is computed on a coset of size 4n, walked as four cosets of the domain so
//! that no array of the prover or of its key is larger than the quotient itself.

use super::keys::{commit, coset4, domain, quarter, ProvingKey};
use super::{transcript, Proof};
use ark_bn254::Fr;
use ark_ff::{batch_inversion, Field, One, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Where the time of one proof went, in seconds: commitments (multi-scalar multiplications), Fourier
/// transforms, the evaluation of the quotient, and the rest (permutation product, openings, …).
/// All zero where the platform has no clock (the single-thread WebAssembly build).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Timings {
    pub msm: f64,
    pub fft: f64,
    pub quotient: f64,
    pub other: f64,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now() -> Option<std::time::Instant> {
    Some(std::time::Instant::now())
}
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now() -> Option<()> {
    None
}

/// Runs `f` and adds its duration to `slot`.
fn timed<T>(slot: &mut f64, f: impl FnOnce() -> T) -> T {
    let start = now();
    let out = f();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    if let Some(t) = start {
        *slot += t.elapsed().as_secs_f64();
    }
    let _ = (start, slot); // no clock in the build without imports: nothing is recorded
    out
}

/// p(X) += r(X)·(X^n − 1), r given from its constant coefficient up.
fn blind(p: &mut Vec<Fr>, r: &[Fr], n: usize) {
    p.resize(n + r.len(), Fr::zero());
    for (i, c) in r.iter().enumerate() {
        p[n + i] += c;
        p[i] -= c;
    }
}

fn evaluate(p: &[Fr], x: Fr) -> Fr {
    p.iter().rev().fold(Fr::zero(), |acc, c| acc * x + c)
}

/// p(X) / (X − a); the remainder must be zero.
fn divide(p: &[Fr], a: Fr) -> Result<Vec<Fr>, String> {
    let d = p.len() - 1;
    let mut q = vec![Fr::zero(); d];
    let mut carry = Fr::zero();
    for i in (1..=d).rev() {
        carry = p[i] + a * carry;
        q[i - 1] = carry;
    }
    if !(p[0] + a * carry).is_zero() {
        return Err("opening quotient has a remainder".into());
    }
    Ok(q)
}

fn add_scaled(dst: &mut [Fr], src: &[Fr], k: Fr) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d += k * s;
    }
}

/// Proves that `values` (one field element per variable of the circuit) satisfies the gates of `pk`.
pub fn prove(pk: &ProvingKey, values: &[Fr], rng: &mut impl RngCore) -> Result<Proof, String> {
    prove_timed(pk, values, rng).map(|(proof, _)| proof)
}

/// `prove`, also reporting where the time went.
pub fn prove_timed(pk: &ProvingKey, values: &[Fr], rng: &mut impl RngCore) -> Result<(Proof, Timings), String> {
    let mut tm = Timings::default();
    let n = pk.n;
    if values.len() != pk.n_vars {
        return Err(format!("the assignment has {} values, the circuit has {} variables", values.len(), pk.n_vars));
    }
    let vk = &pk.vk;
    let dom = domain(n);
    let (k1, k2) = (vk.k1, vk.k2);
    let omega = dom.group_gen();
    let srs = &pk.srs_g1;

    let w: [Vec<Fr>; 3] = std::array::from_fn(|j| pk.wires[j].iter().map(|&v| values[v as usize]).collect());
    let publics: Vec<Fr> = w[0][..vk.n_public].to_vec();

    // ── round 1: wire polynomials ──
    let b: [Fr; 11] = std::array::from_fn(|_| Fr::rand(rng));
    let mut pw: [Vec<Fr>; 3] = timed(&mut tm.fft, || std::array::from_fn(|j| dom.ifft(&w[j])));
    for (j, p) in pw.iter_mut().enumerate() {
        blind(p, &[b[2 * j + 1], b[2 * j]], n);
    }
    let cm: [_; 3] = timed(&mut tm.msm, || std::array::from_fn(|j| commit(srs, &pw[j])));

    // ── round 2: permutation polynomial ──
    let (beta, gamma) = transcript::beta_gamma(vk, &publics, &cm[0], &cm[1], &cm[2]);
    let other_start = now();
    let omegas: Vec<Fr> = dom.elements().collect();
    let mut num = vec![Fr::zero(); n];
    let mut den = vec![Fr::zero(); n];
    for i in 0..n {
        let bx = beta * omegas[i];
        num[i] = (w[0][i] + bx + gamma) * (w[1][i] + bx * k1 + gamma) * (w[2][i] + bx * k2 + gamma);
        den[i] = (w[0][i] + beta * pk.sigma_h[0][i] + gamma) * (w[1][i] + beta * pk.sigma_h[1][i] + gamma) * (w[2][i] + beta * pk.sigma_h[2][i] + gamma);
    }
    batch_inversion(&mut den);
    let mut z = vec![Fr::one(); n];
    for i in 0..n - 1 {
        z[i + 1] = z[i] * num[i] * den[i];
    }
    if !(z[n - 1] * num[n - 1] * den[n - 1]).is_one() {
        return Err("the permutation product does not close".into());
    }
    drop((num, den));
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    if let Some(t) = other_start {
        tm.other += t.elapsed().as_secs_f64();
    }
    let _ = other_start;
    let mut pz = timed(&mut tm.fft, || dom.ifft(&z));
    blind(&mut pz, &[b[8], b[7], b[6]], n);
    let cm_z = timed(&mut tm.msm, || commit(srs, &pz));

    // ── round 3: quotient polynomial ──
    let alpha = transcript::alpha(&beta, &gamma, &cm_z);
    let alpha2 = alpha.square();
    let mut pi_h = vec![Fr::zero(); n];
    for (i, x) in publics.iter().enumerate() {
        pi_h[i] = -*x;
    }
    let p_pi = timed(&mut tm.fft, || dom.ifft(&pi_h));
    drop(pi_h);
    let n_fr = Fr::from(n as u64);
    let [ql, qr, qo, qm, qc] = &pk.q;
    let m = 4 * n;
    let mut t4 = vec![Fr::zero(); m];
    for j in 0..4 {
        // the coset shift·H: on it Z_H is the constant shift^n − 1, and a polynomial of degree ≥ n
        // folds onto n coefficients (x^(n+k) = shift^n·x^k)
        let coset = quarter(n, j);
        let shift_n = coset.coset_offset().pow([n as u64]);
        let on_coset = |p: &[Fr]| -> Vec<Fr> {
            if p.len() <= n {
                return coset.fft(p);
            }
            let mut folded = p[..n].to_vec();
            for (k, c) in p[n..].iter().enumerate() {
                folded[k] += shift_n * c;
            }
            coset.fft(&folded)
        };
        let fft_start = now();
        let (a, b_, c, z) = (on_coset(&pw[0]), on_coset(&pw[1]), on_coset(&pw[2]), on_coset(&pz));
        let (e_ql, e_qr, e_qo, e_qm, e_qc) = (on_coset(ql), on_coset(qr), on_coset(qo), on_coset(qm), on_coset(qc));
        let (s1, s2, s3) = (on_coset(&pk.sigma[0]), on_coset(&pk.sigma[1]), on_coset(&pk.sigma[2]));
        let pi = on_coset(&p_pi);
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        if let Some(t) = fft_start {
            tm.fft += t.elapsed().as_secs_f64();
        }
        let _ = fft_start;
        let quotient_start = now();
        let xs: Vec<Fr> = coset.elements().collect();
        let zh = shift_n - Fr::one();
        let zh_inv = zh.inverse().expect("coset outside the domain");
        // L1(x) = (x^n − 1) / (n·(x − 1))
        let mut l1_den: Vec<Fr> = xs.iter().map(|x| n_fr * (*x - Fr::one())).collect();
        batch_inversion(&mut l1_den);

        let quotient_at = |i: usize| -> Fr {
            let (va, vb, vc, vz, vzw) = (a[i], b_[i], c[i], z[i], z[(i + 1) % n]);
            let gate = va * vb * e_qm[i] + va * e_ql[i] + vb * e_qr[i] + vc * e_qo[i] + e_qc[i] + pi[i];
            let bx = beta * xs[i];
            let p1 = (va + bx + gamma) * (vb + bx * k1 + gamma) * (vc + bx * k2 + gamma) * vz;
            let p2 = (va + beta * s1[i] + gamma) * (vb + beta * s2[i] + gamma) * (vc + beta * s3[i] + gamma) * vzw;
            (gate + alpha * (p1 - p2) + alpha2 * (vz - Fr::one()) * zh * l1_den[i]) * zh_inv
        };
        #[cfg(feature = "parallel")]
        let part: Vec<Fr> = (0..n).into_par_iter().map(quotient_at).collect();
        #[cfg(not(feature = "parallel"))]
        let part: Vec<Fr> = (0..n).map(quotient_at).collect();
        for (i, v) in part.into_iter().enumerate() {
            t4[4 * i + j] = v;
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        if let Some(t) = quotient_start {
            tm.quotient += t.elapsed().as_secs_f64();
        }
        let _ = quotient_start;
    }
    drop(p_pi);
    let pt = timed(&mut tm.fft, || coset4(n).ifft(&t4));
    drop(t4);
    if pt[3 * n + 6..].iter().any(|c| !c.is_zero()) {
        return Err("the assignment does not satisfy the circuit".into());
    }
    let mut t1 = pt[..n].to_vec();
    t1.push(b[9]);
    let mut t2 = pt[n..2 * n].to_vec();
    t2[0] -= b[9];
    t2.push(b[10]);
    let mut t3 = pt[2 * n..3 * n + 6].to_vec();
    t3[0] -= b[10];
    drop(pt);
    let (cm_t1, cm_t2, cm_t3) = timed(&mut tm.msm, || (commit(srs, &t1), commit(srs, &t2), commit(srs, &t3)));
    let other_start = now();

    // ── round 4: evaluations ──
    let xi = transcript::xi(&alpha, &cm_t1, &cm_t2, &cm_t3);
    let (eval_a, eval_b, eval_c) = (evaluate(&pw[0], xi), evaluate(&pw[1], xi), evaluate(&pw[2], xi));
    let (eval_s1, eval_s2) = (evaluate(&pk.sigma[0], xi), evaluate(&pk.sigma[1], xi));
    let eval_zw = evaluate(&pz, xi * omega);

    // ── round 5: opening proofs ──
    let v = transcript::v(&xi, [&eval_a, &eval_b, &eval_c, &eval_s1, &eval_s2, &eval_zw]);
    let xin = xi.pow([n as u64]);
    let zh_xi = xin - Fr::one();
    let n_inv = n_fr.inverse().unwrap();
    let lagrange = |i: usize| -> Result<Fr, String> { Ok(omegas[i] * zh_xi * n_inv * (xi - omegas[i]).inverse().ok_or("challenge inside the domain")?) };
    let l1 = lagrange(0)?;
    let mut pi = Fr::zero();
    for (i, x) in publics.iter().enumerate() {
        pi -= *x * lagrange(i)?;
    }
    let sa = eval_a + beta * eval_s1 + gamma;
    let sb = eval_b + beta * eval_s2 + gamma;
    let coef_z = alpha * (eval_a + beta * xi + gamma) * (eval_b + beta * k1 * xi + gamma) * (eval_c + beta * k2 * xi + gamma) + alpha2 * l1;
    let coef_s3 = alpha * sa * sb * beta * eval_zw;
    let r0 = pi - l1 * alpha2 - alpha * sa * sb * (eval_c + gamma) * eval_zw;

    // linearisation r(X) plus the batched wire and permutation openings at ξ
    let (v2, v3, v4, v5) = (v * v, v * v * v, v.square().square(), v.square().square() * v);
    let mut r = vec![Fr::zero(); n + 6];
    let eab = eval_a * eval_b;
    for i in 0..n {
        r[i] = eab * qm[i] + eval_a * ql[i] + eval_b * qr[i] + eval_c * qo[i] + qc[i] - coef_s3 * pk.sigma[2][i] + v4 * pk.sigma[0][i] + v5 * pk.sigma[1][i];
    }
    add_scaled(&mut r, &pz, coef_z);
    add_scaled(&mut r, &t1, -zh_xi);
    add_scaled(&mut r, &t2, -zh_xi * xin);
    add_scaled(&mut r, &t3, -zh_xi * xin * xin);
    add_scaled(&mut r, &pw[0], v);
    add_scaled(&mut r, &pw[1], v2);
    add_scaled(&mut r, &pw[2], v3);
    r[0] += r0 - (v * eval_a + v2 * eval_b + v3 * eval_c + v4 * eval_s1 + v5 * eval_s2);
    let wxi = divide(&r, xi)?;
    let mut pz_shift = pz;
    pz_shift[0] -= eval_zw;
    let wxiw = divide(&pz_shift, xi * omega)?;
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    if let Some(t) = other_start {
        tm.other += t.elapsed().as_secs_f64();
    }
    let _ = other_start;
    let (cm_wxi, cm_wxiw) = timed(&mut tm.msm, || (commit(srs, &wxi), commit(srs, &wxiw)));

    let proof = Proof {
        a: cm[0],
        b: cm[1],
        c: cm[2],
        z: cm_z,
        t1: cm_t1,
        t2: cm_t2,
        t3: cm_t3,
        wxi: cm_wxi,
        wxiw: cm_wxiw,
        eval_a,
        eval_b,
        eval_c,
        eval_s1,
        eval_s2,
        eval_zw,
    };
    Ok((proof, tm))
}
