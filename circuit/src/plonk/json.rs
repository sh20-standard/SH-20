//! snarkjs' JSON encodings of a verifying key, a proof and the public signals, in both directions:
//! `snarkjs plonk verify` checks proofs made here, and the verifier here checks proofs made by
//! snarkjs. Only used for those cross-implementation tests; nothing on the wire is JSON.

use super::{keys::VerifyingKey, Proof};
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField, Zero};
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

// ── reading ──

/// The decimal strings (or the bare number) of the value that follows `"key":`, in order, whatever
/// the nesting of arrays. Enough for the flat documents snarkjs writes.
fn values(json: &str, key: &str) -> Result<Vec<String>, String> {
    let at = json.find(&format!("\"{key}\"")).ok_or_else(|| format!("missing {key}"))?;
    let rest = json[at + key.len() + 2..].trim_start().strip_prefix(':').ok_or_else(|| format!("malformed {key}"))?.trim_start();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut chars = rest.char_indices();
    while let Some((i, ch)) = chars.next() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth = depth.checked_sub(1).ok_or_else(|| format!("malformed {key}"))?;
                if depth == 0 {
                    return Ok(out);
                }
            }
            '"' => {
                let len = rest[i + 1..].find('"').ok_or_else(|| format!("malformed {key}"))?;
                out.push(rest[i + 1..i + 1 + len].to_string());
                for _ in 0..=len {
                    chars.next();
                }
                if depth == 0 {
                    return Ok(out);
                }
            }
            c if c.is_ascii_digit() && depth == 0 => {
                let len = rest[i..].find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len() - i);
                return Ok(vec![rest[i..i + len].to_string()]);
            }
            c if c.is_whitespace() || c == ',' => {}
            _ => return Err(format!("malformed {key}")),
        }
    }
    Err(format!("malformed {key}"))
}

fn dec(s: &str) -> Result<BigUint, String> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err("not a decimal".into());
    }
    Ok(BigUint::parse_bytes(s.as_bytes(), 10).expect("digits"))
}
fn le32(x: &BigUint) -> Option<[u64; 4]> {
    let b = x.to_bytes_le();
    if b.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..b.len()].copy_from_slice(&b);
    Some(std::array::from_fn(|i| u64::from_le_bytes(padded[i * 8..i * 8 + 8].try_into().unwrap())))
}
/// Strict: below the modulus.
fn fr_of(s: &str) -> Result<Fr, String> {
    Fr::from_bigint(ark_ff::BigInt::new(le32(&dec(s)?).ok_or("too large")?)).ok_or_else(|| "scalar not in the field".to_string())
}
fn fq_of(s: &str) -> Result<Fq, String> {
    Fq::from_bigint(ark_ff::BigInt::new(le32(&dec(s)?).ok_or("too large")?)).ok_or_else(|| "coordinate not in the field".to_string())
}
fn g1_of(json: &str, key: &str) -> Result<G1Affine, String> {
    let v = values(json, key)?;
    if v.len() != 3 {
        return Err(format!("{key}: expected a point"));
    }
    if fq_of(&v[2])?.is_zero() {
        return Ok(G1Affine::identity());
    }
    let p = G1Affine::new_unchecked(fq_of(&v[0])?, fq_of(&v[1])?);
    if !p.is_on_curve() {
        return Err(format!("{key}: not on the curve"));
    }
    Ok(p)
}

pub fn vk_from_json(json: &str) -> Result<VerifyingKey, String> {
    let number = |key: &str| -> Result<u64, String> { values(json, key)?.first().and_then(|s| s.parse().ok()).ok_or_else(|| format!("{key}: not a number")) };
    let x2 = values(json, "X_2")?;
    if x2.len() != 6 {
        return Err("X_2: expected a G2 point".into());
    }
    let x2 = G2Affine::new_unchecked(Fq2::new(fq_of(&x2[0])?, fq_of(&x2[1])?), Fq2::new(fq_of(&x2[2])?, fq_of(&x2[3])?));
    if !x2.is_on_curve() || !x2.is_in_correct_subgroup_assuming_on_curve() {
        return Err("X_2: not in the group".into());
    }
    let scalar = |key: &str| -> Result<Fr, String> { fr_of(values(json, key)?.first().ok_or("missing")?) };
    Ok(VerifyingKey {
        power: number("power")? as u32,
        n_public: number("nPublic")? as usize,
        k1: scalar("k1")?,
        k2: scalar("k2")?,
        qm: g1_of(json, "Qm")?,
        ql: g1_of(json, "Ql")?,
        qr: g1_of(json, "Qr")?,
        qo: g1_of(json, "Qo")?,
        qc: g1_of(json, "Qc")?,
        s1: g1_of(json, "S1")?,
        s2: g1_of(json, "S2")?,
        s3: g1_of(json, "S3")?,
        x2,
    })
}

pub fn proof_from_json(json: &str) -> Result<Proof, String> {
    let scalar = |key: &str| -> Result<Fr, String> { fr_of(values(json, key)?.first().ok_or("missing")?) };
    Ok(Proof {
        a: g1_of(json, "A")?,
        b: g1_of(json, "B")?,
        c: g1_of(json, "C")?,
        z: g1_of(json, "Z")?,
        t1: g1_of(json, "T1")?,
        t2: g1_of(json, "T2")?,
        t3: g1_of(json, "T3")?,
        wxi: g1_of(json, "Wxi")?,
        wxiw: g1_of(json, "Wxiw")?,
        eval_a: scalar("eval_a")?,
        eval_b: scalar("eval_b")?,
        eval_c: scalar("eval_c")?,
        eval_s1: scalar("eval_s1")?,
        eval_s2: scalar("eval_s2")?,
        eval_zw: scalar("eval_zw")?,
    })
}

/// A JSON array of decimal strings.
pub fn publics_from_json(json: &str) -> Result<Vec<Fr>, String> {
    let body = json.trim().strip_prefix('[').and_then(|s| s.strip_suffix(']')).ok_or("public signals: expected an array")?;
    body.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| fr_of(s.trim_matches('"'))).collect()
}
