//! The prover: the five rounds of section 8.3 of the PLONK paper.
//!
//! Wire and permutation polynomials are blinded with random multiples of the vanishing polynomial
//! (b1..b9 of the paper) and the quotient parts with b10, b11, so a proof reveals nothing about the
//! assignment. The quotient is computed on a coset of size 4n.

use super::keys::{commit, coset4, domain, ProvingKey};
use super::{transcript, Proof};
use ark_bn254::Fr;
use ark_ff::{batch_inversion, Field, One, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
    let n = pk.n;
    if values.len() != pk.n_vars {
        return Err(format!("the assignment has {} values, the circuit has {} variables", values.len(), pk.n_vars));
    }
    let vk = &pk.vk;
    let dom = domain(n);
    let dom4 = coset4(n);
    let (k1, k2) = (vk.k1, vk.k2);
    let omega = dom.group_gen();
    let srs = &pk.srs_g1;

    let w: [Vec<Fr>; 3] = std::array::from_fn(|j| pk.wires[j].iter().map(|&v| values[v as usize]).collect());
    let publics: Vec<Fr> = w[0][..vk.n_public].to_vec();

    // ── round 1: wire polynomials ──
    let b: [Fr; 11] = std::array::from_fn(|_| Fr::rand(rng));
    let mut pw: [Vec<Fr>; 3] = std::array::from_fn(|j| dom.ifft(&w[j]));
    for (j, p) in pw.iter_mut().enumerate() {
        blind(p, &[b[2 * j + 1], b[2 * j]], n);
    }
    let cm: [_; 3] = std::array::from_fn(|j| commit(srs, &pw[j]));

    // ── round 2: permutation polynomial ──
    let (beta, gamma) = transcript::beta_gamma(vk, &publics, &cm[0], &cm[1], &cm[2]);
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
    let mut pz = dom.ifft(&z);
    blind(&mut pz, &[b[8], b[7], b[6]], n);
    let cm_z = commit(srs, &pz);

    // ── round 3: quotient polynomial ──
    let alpha = transcript::alpha(&beta, &gamma, &cm_z);
    let alpha2 = alpha.square();
    let w4: [Vec<Fr>; 3] = std::array::from_fn(|j| dom4.fft(&pw[j]));
    let z4 = dom4.fft(&pz);
    let mut pi_h = vec![Fr::zero(); n];
    for (i, x) in publics.iter().enumerate() {
        pi_h[i] = -*x;
    }
    let pi4 = dom4.fft(&dom.ifft(&pi_h));
    let xs: Vec<Fr> = dom4.elements().collect();
    // Z_H takes four values on the coset
    let zh: [Fr; 4] = std::array::from_fn(|i| xs[i].pow([n as u64]) - Fr::one());
    let zh_inv: [Fr; 4] = std::array::from_fn(|i| zh[i].inverse().expect("coset outside the domain"));
    // L1(x) = (x^n − 1) / (n·(x − 1))
    let n_fr = Fr::from(n as u64);
    let mut l1_den: Vec<Fr> = xs.iter().map(|x| n_fr * (*x - Fr::one())).collect();
    batch_inversion(&mut l1_den);

    let [ql4, qr4, qo4, qm4, qc4] = &pk.q4;
    let [s1_4, s2_4, s3_4] = &pk.sigma4;
    let m = 4 * n;
    let quotient_at = |i: usize| -> Fr {
        let (a, bb, c, zz, zw) = (w4[0][i], w4[1][i], w4[2][i], z4[i], z4[(i + 4) % m]);
        let gate = a * bb * qm4[i] + a * ql4[i] + bb * qr4[i] + c * qo4[i] + qc4[i] + pi4[i];
        let bx = beta * xs[i];
        let p1 = (a + bx + gamma) * (bb + bx * k1 + gamma) * (c + bx * k2 + gamma) * zz;
        let p2 = (a + beta * s1_4[i] + gamma) * (bb + beta * s2_4[i] + gamma) * (c + beta * s3_4[i] + gamma) * zw;
        let l1 = zh[i % 4] * l1_den[i];
        (gate + alpha * (p1 - p2) + alpha2 * (zz - Fr::one()) * l1) * zh_inv[i % 4]
    };
    #[cfg(feature = "parallel")]
    let t4: Vec<Fr> = (0..m).into_par_iter().map(quotient_at).collect();
    #[cfg(not(feature = "parallel"))]
    let t4: Vec<Fr> = (0..m).map(quotient_at).collect();
    drop((w4, z4, pi4, xs, l1_den));
    let pt = dom4.ifft(&t4);
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
    let (cm_t1, cm_t2, cm_t3) = (commit(srs, &t1), commit(srs, &t2), commit(srs, &t3));

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
    let [ql, qr, qo, qm, qc] = &pk.q;
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

    Ok(Proof {
        a: cm[0],
        b: cm[1],
        c: cm[2],
        z: cm_z,
        t1: cm_t1,
        t2: cm_t2,
        t3: cm_t3,
        wxi: commit(srs, &wxi),
        wxiw: commit(srs, &wxiw),
        eval_a,
        eval_b,
        eval_c,
        eval_s1,
        eval_s2,
        eval_zw,
    })
}
