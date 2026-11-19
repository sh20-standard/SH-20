//! Proof verification as an interface (SPEC-WIRE §4, "Verifier inputs").
//!
//! The state machine hands every spend to a `SpendVerifier`. This crate ships two:
//! `RejectAll` (the safe default: no spend is accepted without a real verifier) and
//! `TestVerifier` (the rule of `indexer/vectors/v0.3.json`). A PLONK verifier for the pinned
//! key plugs in here without touching the rules.

use crate::envelope::PROOF_LEN;
use ark_bn254::Fr;

/// The public inputs of the spend circuit, in the order of the spec:
/// `R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub root: Fr,
    pub nf: [Fr; 2],
    pub leaves: [Fr; 3],
    pub body_hash: Fr,
    pub v_pub: u64,
    pub t_pub: u32,
}

impl PublicInputs {
    /// The nine inputs as field elements, in order.
    pub fn as_fields(&self) -> [Fr; 9] {
        [
            self.root,
            self.nf[0],
            self.nf[1],
            self.leaves[0],
            self.leaves[1],
            self.leaves[2],
            self.body_hash,
            Fr::from(self.v_pub),
            Fr::from(self.t_pub),
        ]
    }
}

pub trait SpendVerifier {
    /// `proof` is the 480 bytes of the spend section.
    fn verify_spend(&self, inputs: &PublicInputs, proof: &[u8]) -> bool;
}

/// Rejects every spend.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAll;

impl SpendVerifier for RejectAll {
    fn verify_spend(&self, _: &PublicInputs, _: &[u8]) -> bool {
        false
    }
}

/// The test rule of the vectors: accepts exactly one 480-byte proof,
/// `"valid-proof"` padded with zeros, whatever the public inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestVerifier;

impl TestVerifier {
    pub fn valid_proof() -> Vec<u8> {
        let mut p = b"valid-proof".to_vec();
        p.resize(PROOF_LEN, 0);
        p
    }
}

impl SpendVerifier for TestVerifier {
    fn verify_spend(&self, _: &PublicInputs, proof: &[u8]) -> bool {
        proof == Self::valid_proof().as_slice()
    }
}
