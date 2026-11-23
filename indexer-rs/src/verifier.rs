//! Proof verification as an interface (SPEC-WIRE §4, "Verifier inputs").
//!
//! The state machine hands every spend to a `SpendVerifier`. This crate ships three:
//! `RejectAll` (the default: no spend is accepted), `TestVerifier` (the rule of
//! `indexer/vectors/v0.3.json`) and `PlonkVerifier`, the real one.
//!
//! `PlonkVerifier` is not written here. It is the verifier of `circuit/`, the one the reference
//! indexer runs as WebAssembly, called through the interface `circuit/README.md` gives ("The
//! verifier as a library"). What this crate decides alone is what goes in: the nine public
//! inputs, from its own reading of the chain, and the key, pinned by the digest of the spec.

use crate::envelope::PROOF_LEN;
use crate::field::{fr_to_le, hex};
use ark_bn254::Fr;

/// `SHA256("sh20/v0/vk" ‖ key)` of the verifying key, as SPEC-WIRE §4 pins it.
pub const VK_DIGEST: &str = "f48b551776188b652259ac42ff3d064ea61e9dd0d4b48addb825085ab1237745";

/// The verifying key `circuit/` ships, built into the binary.
pub const VERIFYING_KEY: &[u8] = include_bytes!("../../circuit/artifacts/spend.vk");

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

/// The PLONK verifier of `circuit/`, under the pinned key (SPEC-WIRE §4, "The proof").
pub struct PlonkVerifier {
    key: sh20_circuit::VerifyingKey,
}

impl PlonkVerifier {
    /// The name `/status` gives this verifier (`docs/API.md`).
    pub const NAME: &'static str = "plonk-bn254-hermez";

    /// With the key built into the binary.
    pub fn pinned() -> Result<PlonkVerifier, String> {
        PlonkVerifier::with_key(VERIFYING_KEY)
    }

    /// With `key`, 712 bytes, which must be the pinned one: any other key is refused, so a
    /// verifier that exists accepts what the spec's key accepts and nothing else.
    pub fn with_key(key: &[u8]) -> Result<PlonkVerifier, String> {
        let key = sh20_circuit::VerifyingKey::from_bytes(key).map_err(|e| format!("verifying key: {e}"))?;
        let digest = hex(&key.digest());
        if digest != VK_DIGEST {
            return Err(format!("verifying key: its digest is {digest}, and SPEC-WIRE §4 pins {VK_DIGEST}"));
        }
        Ok(PlonkVerifier { key })
    }
}

impl SpendVerifier for PlonkVerifier {
    fn verify_spend(&self, inputs: &PublicInputs, proof: &[u8]) -> bool {
        let mut publics = [sh20_circuit::Fr::from(0u64); sh20_circuit::N_PUBLIC];
        for (to, from) in publics.iter_mut().zip(inputs.as_fields()) {
            // as on the wire: 32 bytes, little-endian, below r
            match sh20_circuit::plonk::fr_from_bytes(&fr_to_le(&from)) {
                Some(x) => *to = x,
                None => return false,
            }
        }
        sh20_circuit::verify(&self.key, &publics, proof)
    }
}

impl SpendVerifier for TestVerifier {
    fn verify_spend(&self, _: &PublicInputs, proof: &[u8]) -> bool {
        proof == Self::valid_proof().as_slice()
    }
}
