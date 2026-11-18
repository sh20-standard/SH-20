//! snarkjs' JSON encodings of a verifying key, a proof and the public signals, so that
//! `snarkjs plonk verify` can check proofs made here (and `Proof`/`VerifyingKey` can be compared with
//! what snarkjs produces). Only used for cross-implementation tests.

use super::{keys::VerifyingKey, Proof};
use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

fn dq(x: &Fq) -> String {
    BigUint::from_bytes_le(&x.into_bigint().to_bytes_le()).to_string()
}
pub fn dr(x: &Fr) -> String {
    BigUint::from_bytes_le(&x.into_bigint().to_bytes_le()).to_string()
}
fn g1(p: &G1Affine) -> String {
    if p.infinity {
        return r#"["0","1","0"]"#.to_string();
    }
    format!(r#"["{}","{}","1"]"#, dq(&p.x), dq(&p.y))
}

pub fn vk_json(vk: &VerifyingKey) -> String {
    let x2 = &vk.x2;
    format!(
        r#"{{"protocol":"plonk","curve":"bn128","nPublic":{},"power":{},"k1":"{}","k2":"{}","Qm":{},"Ql":{},"Qr":{},"Qo":{},"Qc":{},"S1":{},"S2":{},"S3":{},"X_2":[["{}","{}"],["{}","{}"],["1","0"]]}}"#,
        vk.n_public,
        vk.power,
        dr(&vk.k1),
        dr(&vk.k2),
        g1(&vk.qm),
        g1(&vk.ql),
        g1(&vk.qr),
        g1(&vk.qo),
        g1(&vk.qc),
        g1(&vk.s1),
        g1(&vk.s2),
        g1(&vk.s3),
        dq(&x2.x.c0),
        dq(&x2.x.c1),
        dq(&x2.y.c0),
        dq(&x2.y.c1),
    )
}

pub fn proof_json(p: &Proof) -> String {
    format!(
        r#"{{"A":{},"B":{},"C":{},"Z":{},"T1":{},"T2":{},"T3":{},"Wxi":{},"Wxiw":{},"eval_a":"{}","eval_b":"{}","eval_c":"{}","eval_s1":"{}","eval_s2":"{}","eval_zw":"{}","protocol":"plonk","curve":"bn128"}}"#,
        g1(&p.a),
        g1(&p.b),
        g1(&p.c),
        g1(&p.z),
        g1(&p.t1),
        g1(&p.t2),
        g1(&p.t3),
        g1(&p.wxi),
        g1(&p.wxiw),
        dr(&p.eval_a),
        dr(&p.eval_b),
        dr(&p.eval_c),
        dr(&p.eval_s1),
        dr(&p.eval_s2),
        dr(&p.eval_zw),
    )
}

pub fn publics_json(publics: &[Fr]) -> String {
    format!("[{}]", publics.iter().map(|x| format!("\"{}\"", dr(x))).collect::<Vec<_>>().join(","))
}
