//! The structured reference string: g1[i] = τ^i·G1 and τ·G2, copied from the public Hermez powers of
//! tau (snarkjs .ptau). No randomness of ours enters it and nothing here is circuit-specific.
//!
//! ptau layout (snarkjs binfileutils): "ptau" ‖ version u32 ‖ nSections u32, then per section
//! type u32 ‖ size u64 ‖ data. Section 1: n8 u32 ‖ q (n8 bytes) ‖ power u32 ‖ ceremonyPower u32.
//! Section 2: τ^i·G1 for i < 2^(power+1) − 1. Section 3: τ^i·G2 for i < 2^power. Coordinates are
//! little-endian Montgomery limbs; G2 coordinates are c0 ‖ c1.
//!
//! The compact file written by `to_bytes` holds only what the prover and the verifier need:
//! "SH20SRS1" ‖ count u32 ‖ count × (x ‖ y, 32-byte little-endian each) ‖ τ·G2 (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1).
//!
//! The ptau reader follows the layout notes of Tacit's Bitcoin shielded pool (btc-pool-halo2/src/srs.rs),
//! MIT License, Copyright (c) 2026 ross.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use blake2::{Blake2b512, Digest};

/// BLAKE2b-512 of Hermez `powersOfTau28_hez_final_18.ptau`, as listed in the snarkjs README.
pub const POT18_BLAKE2B: &str = "7e6a9c2e5f05179ddfc923f38f917c9e6831d16922a902b0b4758b8e79c2ab8a81bb5f29952e16ee6c5067ed044d7857b5de120a90704c1d3b637fd94b95b13e";

const MAGIC: &[u8; 8] = b"SH20SRS1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srs {
    pub g1: Vec<G1Affine>,
    pub g2_tau: G2Affine,
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn fq_montgomery(b: &[u8]) -> Fq {
    let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    Fq::new_unchecked(BigInt::new(limbs))
}
fn fq_canonical(b: &[u8]) -> Result<Fq, String> {
    let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    Fq::from_bigint(BigInt::new(limbs)).ok_or_else(|| "coordinate not in the field".to_string())
}
fn fq_bytes(x: &Fq) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().unwrap()
}

fn g1(x: Fq, y: Fq) -> Result<G1Affine, String> {
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err("G1 point not on the curve".into());
    }
    Ok(p)
}
fn g2(c: [Fq; 4]) -> Result<G2Affine, String> {
    let p = G2Affine::new_unchecked(Fq2::new(c[0], c[1]), Fq2::new(c[2], c[3]));
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("G2 point not in the group".into());
    }
    Ok(p)
}

impl Srs {
    /// The first `count` powers from a ptau file.
    pub fn from_ptau(bytes: &[u8], count: usize) -> Result<Srs, String> {
        if bytes.len() < 12 || &bytes[0..4] != b"ptau" {
            return Err("not a ptau file".into());
        }
        let n_sections = u32le(bytes, 8) as usize;
        let (mut header, mut tau_g1, mut tau_g2) = (None, None, None);
        let mut off = 12;
        for _ in 0..n_sections {
            if off + 12 > bytes.len() {
                return Err("truncated section header".into());
            }
            let ty = u32le(bytes, off);
            let size = u64::from_le_bytes(bytes[off + 4..off + 12].try_into().unwrap()) as usize;
            let start = off + 12;
            if start + size > bytes.len() {
                return Err("truncated section".into());
            }
            let data = &bytes[start..start + size];
            match ty {
                1 => header = Some(data),
                2 => tau_g1 = Some(data),
                3 => tau_g2 = Some(data),
                _ => {}
            }
            off = start + size;
        }
        let header = header.ok_or("missing header section")?;
        if u32le(header, 0) != 32 || header.len() < 4 + 32 + 8 {
            return Err("unexpected field size".into());
        }
        if header[4..36] != Fq::MODULUS.to_bytes_le()[..] {
            return Err("ptau is not over BN254".into());
        }
        let tau_g1 = tau_g1.ok_or("missing tauG1 section")?;
        let tau_g2 = tau_g2.ok_or("missing tauG2 section")?;
        if tau_g1.len() < count * 64 || tau_g2.len() < 2 * 128 {
            return Err("ptau too small for this circuit".into());
        }
        let g1s = (0..count)
            .map(|i| {
                let p = &tau_g1[i * 64..(i + 1) * 64];
                g1(fq_montgomery(&p[..32]), fq_montgomery(&p[32..]))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let c = &tau_g2[128..256];
        let g2_tau = g2(std::array::from_fn(|i| fq_montgomery(&c[i * 32..(i + 1) * 32])))?;
        let srs = Srs { g1: g1s, g2_tau };
        srs.check()?;
        Ok(srs)
    }

    /// g1[0] is the generator and every g1[i+1] is τ·g1[i] for the τ of `g2_tau`:
    /// e(Σ r_i·g1[i+1], G2) = e(Σ r_i·g1[i], τ·G2) for coefficients r_i derived from the points.
    pub fn check(&self) -> Result<(), String> {
        if self.g1.len() < 2 || self.g1[0] != G1Affine::generator() {
            return Err("SRS does not start at the G1 generator".into());
        }
        let mut h = Blake2b512::new();
        h.update(b"sh20/srs-check");
        for p in &self.g1 {
            h.update(fq_bytes(&p.x));
            h.update(fq_bytes(&p.y));
        }
        let seed = h.finalize();
        let n = self.g1.len() - 1;
        let r: Vec<Fr> = (0..n as u64)
            .map(|i| {
                let mut hi = Blake2b512::new();
                hi.update(seed);
                hi.update(i.to_le_bytes());
                Fr::from_le_bytes_mod_order(&hi.finalize())
            })
            .collect();
        let lo = G1Projective::msm_unchecked(&self.g1[..n], &r).into_affine();
        let hi = G1Projective::msm_unchecked(&self.g1[1..], &r).into_affine();
        let ok = Bn254::multi_pairing([hi, (-lo.into_group()).into_affine()], [G2Affine::generator(), self.g2_tau]).is_zero();
        if !ok {
            return Err("SRS powers are not consistent".into());
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.g1.len() * 64 + 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.g1.len() as u32).to_le_bytes());
        for p in &self.g1 {
            out.extend_from_slice(&fq_bytes(&p.x));
            out.extend_from_slice(&fq_bytes(&p.y));
        }
        for c in [self.g2_tau.x.c0, self.g2_tau.x.c1, self.g2_tau.y.c0, self.g2_tau.y.c1] {
            out.extend_from_slice(&fq_bytes(&c));
        }
        out
    }

    /// Parses the compact file. Points are checked to be on the curve; `check` verifies the powers.
    pub fn from_bytes(b: &[u8]) -> Result<Srs, String> {
        if b.len() < 12 || &b[..8] != MAGIC {
            return Err("not an SH-20 SRS file".into());
        }
        let count = u32le(b, 8) as usize;
        if b.len() != 12 + count * 64 + 128 {
            return Err("SRS file has the wrong length".into());
        }
        let g1s = (0..count)
            .map(|i| {
                let p = &b[12 + i * 64..12 + (i + 1) * 64];
                g1(fq_canonical(&p[..32])?, fq_canonical(&p[32..])?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let c = &b[12 + count * 64..];
        let mut cs = [Fq::zero(); 4];
        for (i, slot) in cs.iter_mut().enumerate() {
            *slot = fq_canonical(&c[i * 32..(i + 1) * 32])?;
        }
        Ok(Srs { g1: g1s, g2_tau: g2(cs)? })
    }
}

pub fn blake2b_hex(data: &[u8]) -> String {
    hex::encode(Blake2b512::digest(data))
}
