//! PLONK with KZG commitments over BN254, as specified in "PLONK: Permutations over Lagrange-bases
//! for Oecumenical Noninteractive arguments of Knowledge" (Gabizon, Williamson, Ciobotaru, ePrint
//! 2019/953, section 8): three wires, the five standard selectors, no custom gates, no lookups.
//!
//! The Fiat-Shamir transcript (Keccak-256 over big-endian encodings, see `transcript`) and the
//! verifying-key fields are those of snarkjs' PLONK, so a proof made here verifies with
//! `snarkjs plonk verify` and the other way round. That gives the standard a second, independent
//! verifier to test against.
//!
//! A proof is 9 G1 points and 6 scalars: 480 bytes in the wire encoding of `Proof::to_bytes`.

pub mod json;
pub mod keys;
pub mod prover;
pub mod srs;
pub mod transcript;
pub mod verifier;

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{BigInteger, Field, PrimeField, Zero};

pub use keys::{setup, setup_with_vk, ProvingKey, VerifyingKey};
pub use prover::{prove, prove_timed, Timings};
pub use srs::Srs;
pub use verifier::verify;

/// Bytes of a proof on the wire.
pub const PROOF_BYTES: usize = 480;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G1Affine,
    pub c: G1Affine,
    pub z: G1Affine,
    pub t1: G1Affine,
    pub t2: G1Affine,
    pub t3: G1Affine,
    pub wxi: G1Affine,
    pub wxiw: G1Affine,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_s1: Fr,
    pub eval_s2: Fr,
    pub eval_zw: Fr,
}

/// 32 bytes: x little-endian, bit 255 set when y is the larger of the two roots (y > q − y).
/// The point at infinity has no encoding.
pub fn g1_to_bytes(p: &G1Affine) -> Option<[u8; 32]> {
    if p.infinity {
        return None;
    }
    let mut b: [u8; 32] = p.x.into_bigint().to_bytes_le().try_into().unwrap();
    if p.y > -p.y {
        b[31] |= 0x80;
    }
    Some(b)
}

/// Strict inverse of `g1_to_bytes`: x below the field modulus, x on the curve.
pub fn g1_from_bytes(b: &[u8]) -> Option<G1Affine> {
    let mut x: [u8; 32] = b.try_into().ok()?;
    let larger = x[31] & 0x80 != 0;
    x[31] &= 0x7f;
    let x = fq_from_le(&x)?;
    let y = (x.square() * x + Fq::from(3u64)).sqrt()?;
    let y = if (y > -y) == larger { y } else { -y };
    if y.is_zero() {
        return None;
    }
    // BN254 G1 has cofactor 1: every point of the curve is in the group
    Some(G1Affine::new_unchecked(x, y))
}

fn fq_from_le(b: &[u8; 32]) -> Option<Fq> {
    let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    Fq::from_bigint(ark_ff::BigInt::new(limbs))
}

/// 32 bytes little-endian.
pub fn fr_to_bytes(x: &Fr) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().unwrap()
}
/// Strict: the value must be below the group order.
pub fn fr_from_bytes(b: &[u8]) -> Option<Fr> {
    let b: [u8; 32] = b.try_into().ok()?;
    let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()));
    Fr::from_bigint(ark_ff::BigInt::new(limbs))
}

impl Proof {
    fn points(&self) -> [&G1Affine; 9] {
        [&self.a, &self.b, &self.c, &self.z, &self.t1, &self.t2, &self.t3, &self.wxi, &self.wxiw]
    }
    fn scalars(&self) -> [&Fr; 6] {
        [&self.eval_a, &self.eval_b, &self.eval_c, &self.eval_s1, &self.eval_s2, &self.eval_zw]
    }

    /// A ‖ B ‖ C ‖ Z ‖ T1 ‖ T2 ‖ T3 ‖ Wxi ‖ Wxiw ‖ a ‖ b ‖ c ‖ s1 ‖ s2 ‖ zw, 32 bytes each.
    /// `None` if a commitment is the point at infinity (an honest prover never produces one).
    pub fn to_bytes(&self) -> Option<[u8; PROOF_BYTES]> {
        let mut out = [0u8; PROOF_BYTES];
        for (i, p) in self.points().into_iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(&g1_to_bytes(p)?);
        }
        for (i, s) in self.scalars().into_iter().enumerate() {
            out[(9 + i) * 32..(10 + i) * 32].copy_from_slice(&fr_to_bytes(s));
        }
        Some(out)
    }

    /// Strict parse: exactly 480 bytes, canonical field elements, points on the curve.
    pub fn from_bytes(b: &[u8]) -> Option<Proof> {
        if b.len() != PROOF_BYTES {
            return None;
        }
        let p = |i: usize| g1_from_bytes(&b[i * 32..(i + 1) * 32]);
        let s = |i: usize| fr_from_bytes(&b[(9 + i) * 32..(10 + i) * 32]);
        Some(Proof {
            a: p(0)?,
            b: p(1)?,
            c: p(2)?,
            z: p(3)?,
            t1: p(4)?,
            t2: p(5)?,
            t3: p(6)?,
            wxi: p(7)?,
            wxiw: p(8)?,
            eval_a: s(0)?,
            eval_b: s(1)?,
            eval_c: s(2)?,
            eval_s1: s(3)?,
            eval_s2: s(4)?,
            eval_zw: s(5)?,
        })
    }
}
