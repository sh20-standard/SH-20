//! Key generation. It is deterministic: the keys depend only on the gates of the circuit and on the
//! public SRS, so anyone can recompute them and compare the verifying-key digest. There is no
//! circuit-specific ceremony and no secret.

use super::srs::Srs;
use crate::cs::Cs;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use sha2::{Digest, Sha256};

pub type Domain = Radix2EvaluationDomain<Fr>;

/// Smallest domain: the quotient needs a few coefficients above n.
const MIN_POWER: u32 = 3;
/// Extra SRS powers above n (the blinded quotient part t_hi has degree n + 5).
pub const SRS_EXTRA: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The domain has 2^power rows.
    pub power: u32,
    pub n_public: usize,
    /// Coset shifts of the second and third wire columns.
    pub k1: Fr,
    pub k2: Fr,
    pub qm: G1Affine,
    pub ql: G1Affine,
    pub qr: G1Affine,
    pub qo: G1Affine,
    pub qc: G1Affine,
    pub s1: G1Affine,
    pub s2: G1Affine,
    pub s3: G1Affine,
    /// τ·G2 of the SRS.
    pub x2: G2Affine,
}

pub struct ProvingKey {
    pub vk: VerifyingKey,
    /// Rows of the domain.
    pub n: usize,
    pub n_vars: usize,
    /// Variable on each wire of each row (padding rows hold variable 0).
    pub wires: [Vec<u32>; 3],
    /// Selector polynomials ql, qr, qo, qm, qc, as coefficients.
    pub q: [Vec<Fr>; 5],
    /// Permutation polynomials: coefficients, and evaluations on the domain.
    pub sigma: [Vec<Fr>; 3],
    pub sigma_h: [Vec<Fr>; 3],
    /// τ^i·G1 for i < n + 6.
    pub srs_g1: Vec<G1Affine>,
}

pub fn domain(n: usize) -> Domain {
    let d = Domain::new(n).expect("domain size");
    assert_eq!(d.size(), n);
    d
}

/// The coset g·H' of size 4n the quotient is computed on (g = the field's multiplicative generator).
/// The prover walks it as four cosets of the domain, `quarter(n, j)` for j < 4: element 4i + j of the
/// large coset is element i of quarter j.
pub fn coset4(n: usize) -> Domain {
    domain(4 * n).get_coset(Fr::GENERATOR).expect("coset")
}

/// The coset g·ω'^j·H of the domain, ω' the generator of the group of size 4n.
pub fn quarter(n: usize, j: usize) -> Domain {
    let shift = Fr::GENERATOR * domain(4 * n).group_gen().pow([j as u64]);
    domain(n).get_coset(shift).expect("coset")
}

pub fn commit(srs_g1: &[G1Affine], coeffs: &[Fr]) -> G1Affine {
    assert!(coeffs.len() <= srs_g1.len(), "polynomial larger than the SRS");
    G1Projective::msm_unchecked(&srs_g1[..coeffs.len()], coeffs).into_affine()
}

/// Rows needed for `gates` gates.
pub fn rows_for(gates: usize) -> usize {
    gates.next_power_of_two().max(1 << MIN_POWER)
}

/// The parts of a proving key that depend only on the gates: wires, selector and permutation
/// polynomials. No group operation.
struct Structure {
    n: usize,
    n_vars: usize,
    wires: [Vec<u32>; 3],
    q: [Vec<Fr>; 5],
    sigma: [Vec<Fr>; 3],
    sigma_h: [Vec<Fr>; 3],
}

const K1: u64 = 2;
const K2: u64 = 3;

fn structure(cs: &Cs) -> Result<Structure, String> {
    let n = rows_for(cs.gates.len());
    let dom = domain(n);
    let (k1, k2) = (Fr::from(K1), Fr::from(K2));
    let pow_n = |x: Fr| x.pow([n as u64]);
    if pow_n(k1).is_one() || pow_n(k2).is_one() || pow_n(k2 * k1.inverse().unwrap()).is_one() {
        return Err("wire cosets are not disjoint".into());
    }

    // selectors
    let mut q_h: [Vec<Fr>; 5] = std::array::from_fn(|_| vec![Fr::zero(); n]);
    let mut wires: [Vec<u32>; 3] = std::array::from_fn(|_| vec![0u32; n]);
    for (i, g) in cs.gates.iter().enumerate() {
        for j in 0..5 {
            q_h[j][i] = g.q[j];
        }
        for j in 0..3 {
            wires[j][i] = g.w[j];
        }
    }

    // copy constraints: the slots holding one variable form one cycle of the permutation
    const NONE: u32 = u32::MAX;
    let n_vars = cs.values.len();
    let mut first = vec![NONE; n_vars];
    let mut last = vec![NONE; n_vars];
    let mut next = vec![0u32; 3 * n];
    for (j, column) in wires.iter().enumerate() {
        for (i, &v) in column.iter().enumerate() {
            let slot = (j * n + i) as u32;
            let v = v as usize;
            if last[v] == NONE {
                first[v] = slot;
            } else {
                next[last[v] as usize] = slot;
            }
            last[v] = slot;
        }
    }
    for v in 0..n_vars {
        if last[v] != NONE {
            next[last[v] as usize] = first[v];
        }
    }
    let omegas: Vec<Fr> = dom.elements().collect();
    let shifts = [Fr::one(), k1, k2];
    let sigma_h: [Vec<Fr>; 3] = std::array::from_fn(|j| {
        (0..n)
            .map(|i| {
                let to = next[j * n + i] as usize;
                shifts[to / n] * omegas[to % n]
            })
            .collect()
    });

    let q: [Vec<Fr>; 5] = std::array::from_fn(|j| dom.ifft(&q_h[j]));
    let sigma: [Vec<Fr>; 3] = std::array::from_fn(|j| dom.ifft(&sigma_h[j]));
    Ok(Structure { n, n_vars, wires, q, sigma, sigma_h })
}

/// Key generation: the structure of the circuit and the eight commitments of its verifying key.
pub fn setup(cs: &Cs, srs: &Srs) -> Result<ProvingKey, String> {
    let st = structure(cs)?;
    let n = st.n;
    if srs.g1.len() < n + SRS_EXTRA {
        return Err(format!("the SRS holds {} powers, this circuit needs {}", srs.g1.len(), n + SRS_EXTRA));
    }
    let srs_g1 = srs.g1[..n + SRS_EXTRA].to_vec();
    let c = |p: &[Fr]| commit(&srs_g1, p);
    let vk = VerifyingKey {
        power: n.trailing_zeros(),
        n_public: cs.n_public,
        k1: Fr::from(K1),
        k2: Fr::from(K2),
        ql: c(&st.q[0]),
        qr: c(&st.q[1]),
        qo: c(&st.q[2]),
        qm: c(&st.q[3]),
        qc: c(&st.q[4]),
        s1: c(&st.sigma[0]),
        s2: c(&st.sigma[1]),
        s3: c(&st.sigma[2]),
        x2: srs.g2_tau,
    };
    Ok(ProvingKey { vk, n, n_vars: st.n_vars, wires: st.wires, q: st.q, sigma: st.sigma, sigma_h: st.sigma_h, srs_g1 })
}

/// A proving key from a verifying key that is already known (shipped with its digest): the
/// structure is recomputed from the gates, the commitments are taken from `vk`. A key that does
/// not belong to this circuit and SRS only yields proofs that do not verify.
pub fn setup_with_vk(cs: &Cs, srs_g1: Vec<G1Affine>, vk: VerifyingKey) -> Result<ProvingKey, String> {
    let st = structure(cs)?;
    if vk.power != st.n.trailing_zeros() || vk.n_public != cs.n_public || vk.k1 != Fr::from(K1) || vk.k2 != Fr::from(K2) {
        return Err("the verifying key is not for this circuit".into());
    }
    if srs_g1.len() != st.n + SRS_EXTRA {
        return Err(format!("the key holds {} SRS powers, this circuit needs {}", srs_g1.len(), st.n + SRS_EXTRA));
    }
    Ok(ProvingKey { vk, n: st.n, n_vars: st.n_vars, wires: st.wires, q: st.q, sigma: st.sigma, sigma_h: st.sigma_h, srs_g1 })
}

/// Magic of a serialized proving key.
const PK_MAGIC: &[u8; 8] = b"SH20PK01";

impl ProvingKey {
    /// "SH20PK01" ‖ verifying key (712) ‖ count u32 ‖ count × (x ‖ y, 32-byte little-endian each):
    /// the verifying key and the SRS powers. Everything else in a proving key follows from the gates.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + VK_BYTES + 4 + self.srs_g1.len() * 64);
        out.extend_from_slice(PK_MAGIC);
        out.extend_from_slice(&self.vk.to_bytes());
        out.extend_from_slice(&(self.srs_g1.len() as u32).to_le_bytes());
        for p in &self.srs_g1 {
            out.extend_from_slice(&fq_le(&p.x));
            out.extend_from_slice(&fq_le(&p.y));
        }
        out
    }

    /// Parses `to_bytes` for the circuit `cs`. Points are checked to be on the curve; the caller
    /// checks the digest of the file.
    pub fn from_bytes(cs: &Cs, b: &[u8]) -> Result<ProvingKey, String> {
        if b.len() < 8 + VK_BYTES + 4 || &b[..8] != PK_MAGIC {
            return Err("not an SH-20 proving key".into());
        }
        let vk = VerifyingKey::from_bytes(&b[8..8 + VK_BYTES])?;
        let rest = &b[8 + VK_BYTES..];
        let count = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        if rest.len() != 4 + count * 64 {
            return Err("proving key has the wrong length".into());
        }
        let mut srs_g1 = Vec::with_capacity(count);
        for p in rest[4..].chunks(64) {
            let pt = G1Affine::new_unchecked(fq_from(&p[..32]).ok_or("coordinate")?, fq_from(&p[32..]).ok_or("coordinate")?);
            if !pt.is_on_curve() {
                return Err("proving key point not on the curve".into());
            }
            srs_g1.push(pt);
        }
        setup_with_vk(cs, srs_g1, vk)
    }

    /// The SRS inside the key (the G2 power comes from the verifying key).
    pub fn srs(&self) -> Srs {
        Srs { g1: self.srs_g1.clone(), g2_tau: self.vk.x2 }
    }
}

fn fq_le(x: &Fq) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().unwrap()
}
fn fq_from(b: &[u8]) -> Option<Fq> {
    let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    Fq::from_bigint(ark_ff::BigInt::new(limbs))
}

/// Bytes of a serialized verifying key.
pub const VK_BYTES: usize = 4 + 4 + 2 * 32 + 8 * 64 + 128;

impl VerifyingKey {
    fn g1s(&self) -> [&G1Affine; 8] {
        [&self.qm, &self.ql, &self.qr, &self.qo, &self.qc, &self.s1, &self.s2, &self.s3]
    }

    /// power u32 ‖ nPublic u32 ‖ k1 ‖ k2 ‖ Qm ‖ Ql ‖ Qr ‖ Qo ‖ Qc ‖ S1 ‖ S2 ‖ S3 (x ‖ y each) ‖
    /// X2 (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1); every integer little-endian, every coordinate 32 bytes.
    /// A commitment at infinity is written as 64 zero bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VK_BYTES);
        out.extend_from_slice(&self.power.to_le_bytes());
        out.extend_from_slice(&(self.n_public as u32).to_le_bytes());
        out.extend_from_slice(&super::fr_to_bytes(&self.k1));
        out.extend_from_slice(&super::fr_to_bytes(&self.k2));
        for p in self.g1s() {
            if p.infinity {
                out.extend_from_slice(&[0u8; 64]);
            } else {
                out.extend_from_slice(&fq_le(&p.x));
                out.extend_from_slice(&fq_le(&p.y));
            }
        }
        for c in [self.x2.x.c0, self.x2.x.c1, self.x2.y.c0, self.x2.y.c1] {
            out.extend_from_slice(&fq_le(&c));
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<VerifyingKey, String> {
        if b.len() != VK_BYTES {
            return Err("verifying key has the wrong length".into());
        }
        let power = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let n_public = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        if !(MIN_POWER..=Fr::TWO_ADICITY - 2).contains(&power) || n_public > 1 << power {
            return Err("verifying key has an invalid size".into());
        }
        let k1 = super::fr_from_bytes(&b[8..40]).ok_or("k1")?;
        let k2 = super::fr_from_bytes(&b[40..72]).ok_or("k2")?;
        let g1 = |i: usize| -> Result<G1Affine, String> {
            let p = &b[72 + i * 64..72 + (i + 1) * 64];
            if p.iter().all(|x| *x == 0) {
                return Ok(G1Affine::identity());
            }
            let pt = G1Affine::new_unchecked(fq_from(&p[..32]).ok_or("coordinate")?, fq_from(&p[32..]).ok_or("coordinate")?);
            if !pt.is_on_curve() {
                return Err("verifying key point not on the curve".into());
            }
            Ok(pt)
        };
        let c = &b[72 + 8 * 64..];
        let f = |i: usize| fq_from(&c[i * 32..(i + 1) * 32]).ok_or("coordinate".to_string());
        let x2 = G2Affine::new_unchecked(ark_bn254::Fq2::new(f(0)?, f(1)?), ark_bn254::Fq2::new(f(2)?, f(3)?));
        if !x2.is_on_curve() || !x2.is_in_correct_subgroup_assuming_on_curve() {
            return Err("verifying key G2 point not in the group".into());
        }
        Ok(VerifyingKey { power, n_public, k1, k2, qm: g1(0)?, ql: g1(1)?, qr: g1(2)?, qo: g1(3)?, qc: g1(4)?, s1: g1(5)?, s2: g1(6)?, s3: g1(7)?, x2 })
    }

    /// SHA-256("sh20/v0/vk" ‖ serialized key): the value the standard pins.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sh20/v0/vk");
        h.update(self.to_bytes());
        h.finalize().into()
    }
}
