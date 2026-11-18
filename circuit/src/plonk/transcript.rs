//! Fiat-Shamir transcript, byte-compatible with snarkjs' PLONK: each challenge is Keccak-256 of the
//! concatenated items of its round, read as a big-endian integer and reduced modulo the group order.
//! A G1 point is x ‖ y, 32 bytes big-endian each (64 zero bytes for the point at infinity); a scalar
//! is 32 bytes big-endian.

use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

#[derive(Default)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn point(&mut self, p: &G1Affine) -> &mut Self {
        if p.infinity {
            self.buf.extend_from_slice(&[0u8; 64]);
        } else {
            self.buf.extend_from_slice(&p.x.into_bigint().to_bytes_be());
            self.buf.extend_from_slice(&p.y.into_bigint().to_bytes_be());
        }
        self
    }
    pub fn scalar(&mut self, x: &Fr) -> &mut Self {
        self.buf.extend_from_slice(&x.into_bigint().to_bytes_be());
        self
    }
    /// Hashes the items added since the last challenge, and starts a new round.
    pub fn challenge(&mut self) -> Fr {
        let h = Keccak256::digest(&self.buf);
        self.buf.clear();
        Fr::from_be_bytes_mod_order(&h)
    }
}

use super::keys::VerifyingKey;

/// β and γ: the verifying key, the public inputs and the wire commitments.
pub fn beta_gamma(vk: &VerifyingKey, publics: &[Fr], a: &G1Affine, b: &G1Affine, c: &G1Affine) -> (Fr, Fr) {
    let mut t = Transcript::new();
    for p in [&vk.qm, &vk.ql, &vk.qr, &vk.qo, &vk.qc, &vk.s1, &vk.s2, &vk.s3] {
        t.point(p);
    }
    for x in publics {
        t.scalar(x);
    }
    t.point(a).point(b).point(c);
    let beta = t.challenge();
    let gamma = t.scalar(&beta).challenge();
    (beta, gamma)
}

pub fn alpha(beta: &Fr, gamma: &Fr, z: &G1Affine) -> Fr {
    Transcript::new().scalar(beta).scalar(gamma).point(z).challenge()
}

pub fn xi(alpha: &Fr, t1: &G1Affine, t2: &G1Affine, t3: &G1Affine) -> Fr {
    Transcript::new().scalar(alpha).point(t1).point(t2).point(t3).challenge()
}

/// v, from ξ and the evaluations a, b, c, s1, s2, zω in that order.
pub fn v(xi: &Fr, evals: [&Fr; 6]) -> Fr {
    let mut t = Transcript::new();
    t.scalar(xi);
    for e in evals {
        t.scalar(e);
    }
    t.challenge()
}

pub fn u(wxi: &G1Affine, wxiw: &G1Affine) -> Fr {
    Transcript::new().point(wxi).point(wxiw).challenge()
}
