//! The verifier: section 8.3 of the PLONK paper, with the linearisation trick, so a proof carries six
//! evaluations and the check is one pairing equation.

use super::keys::{domain, VerifyingKey};
use super::{transcript, Proof};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, Zero};
use ark_poly::EvaluationDomain;

/// True iff `proof` shows that some assignment with these public inputs satisfies the circuit of `vk`.
pub fn verify(vk: &VerifyingKey, publics: &[Fr], proof: &Proof) -> bool {
    check(vk, publics, proof).unwrap_or(false)
}

fn check(vk: &VerifyingKey, publics: &[Fr], p: &Proof) -> Option<bool> {
    if publics.len() != vk.n_public {
        return Some(false);
    }
    for pt in [&p.a, &p.b, &p.c, &p.z, &p.t1, &p.t2, &p.t3, &p.wxi, &p.wxiw] {
        if pt.infinity || !pt.is_on_curve() {
            return Some(false);
        }
    }
    let n = 1usize << vk.power;
    let omega = domain(n).group_gen();
    let (k1, k2) = (vk.k1, vk.k2);

    let (beta, gamma) = transcript::beta_gamma(vk, publics, &p.a, &p.b, &p.c);
    let alpha = transcript::alpha(&beta, &gamma, &p.z);
    let xi = transcript::xi(&alpha, &p.t1, &p.t2, &p.t3);
    let v = transcript::v(&xi, [&p.eval_a, &p.eval_b, &p.eval_c, &p.eval_s1, &p.eval_s2, &p.eval_zw]);
    let u = transcript::u(&p.wxi, &p.wxiw);
    let alpha2 = alpha.square();

    // Z_H(ξ) and the Lagrange evaluations L_i(ξ) = ω^i·Z_H(ξ) / (n·(ξ − ω^i))
    let xin = xi.pow([n as u64]);
    let zh = xin - Fr::one();
    let n_inv = Fr::from(n as u64).inverse()?;
    let mut w = Fr::one();
    let mut pi = Fr::zero();
    let mut l1 = Fr::zero();
    for i in 0..publics.len().max(1) {
        let l = w * zh * n_inv * (xi - w).inverse()?;
        if i == 0 {
            l1 = l;
        }
        if let Some(x) = publics.get(i) {
            pi -= *x * l;
        }
        w *= omega;
    }

    let (a, b, c, s1, s2, zw) = (p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw);
    let sa = a + beta * s1 + gamma;
    let sb = b + beta * s2 + gamma;
    let r0 = pi - l1 * alpha2 - alpha * sa * sb * (c + gamma) * zw;

    let (v2, v3, v4, v5) = (v * v, v * v * v, v.square().square(), v.square().square() * v);
    let coef_z = alpha * (a + beta * xi + gamma) * (b + beta * k1 * xi + gamma) * (c + beta * k2 * xi + gamma) + alpha2 * l1 + u;
    let coef_s3 = alpha * sa * sb * beta * zw;
    let e = -r0 + v * a + v2 * b + v3 * c + v4 * s1 + v5 * s2 + u * zw;

    // rhs = ξ·Wξ + u·ξω·Wξω + F − E, with F = D + v·A + v²·B + v³·C + v⁴·S1 + v⁵·S2
    let bases = [vk.qm, vk.ql, vk.qr, vk.qo, vk.qc, p.z, vk.s3, p.t1, p.t2, p.t3, p.a, p.b, p.c, vk.s1, vk.s2, G1Affine::generator(), p.wxi, p.wxiw];
    let scalars = [a * b, a, b, c, Fr::one(), coef_z, -coef_s3, -zh, -zh * xin, -zh * xin * xin, v, v2, v3, v4, v5, -e, xi, u * xi * omega];
    let rhs = G1Projective::msm_unchecked(&bases, &scalars);
    let lhs = p.wxi.into_group() + p.wxiw * u;

    Some(Bn254::multi_pairing([(-lhs).into_affine(), rhs.into_affine()], [vk.x2, G2Affine::generator()]).is_zero())
}
