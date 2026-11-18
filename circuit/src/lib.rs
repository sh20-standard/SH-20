//! SH-20 spend circuit (docs/SPEC-WIRE.md §4): PLONK over BN254 with KZG commitments on the public
//! Hermez powers of tau. Proofs are 480 bytes; keys are derived deterministically from the circuit and
//! the SRS, so there is no project-run setup.
//!
//! ```text
//! let pk = keygen(&srs)?;                         // once; anyone gets the same keys
//! let proof = prove(&pk, &witness, &mut rng)?;    // 480 bytes
//! assert!(verify(&pk.vk, &witness.publics(), &proof));
//! ```

pub mod cs;
pub mod ffi;
pub mod fixture;
pub mod gadgets;
pub mod model;
pub mod plonk;
pub mod poseidon;
pub mod spend;
pub mod wire;

pub use ark_bn254::Fr;
pub use model::{SpendWitness, N_PUBLIC};
pub use plonk::{ProvingKey, Srs, VerifyingKey, PROOF_BYTES};

use ark_std::rand::RngCore;

/// SHA-256("sh20/v0/vk" ‖ verifying key) of the spend circuit on the Hermez SRS: the value
/// docs/SPEC-WIRE.md pins. `keygen` on the SRS extracted from the pinned ptau reproduces it.
pub const VK_DIGEST: &str = "da847145dbc5aa847af92ce5696fbd60bd57e6fbdf0e077cc1b62a0ba302492d";
/// SHA-256 of the SRS file `sh20-circuit srs` extracts from Hermez powersOfTau28_hez_final_18.ptau.
pub const SRS_SHA256: &str = "e97b92f39a4371b2c137883e72400d0906a49d6f35511443572f478c3852a238";

/// SRS powers the spend circuit needs.
pub fn srs_size() -> usize {
    plonk::keys::rows_for(spend::synthesize(&SpendWitness::default()).n_gates()) + plonk::keys::SRS_EXTRA
}

/// Proving and verifying keys of the spend circuit. Deterministic in the SRS.
pub fn keygen(srs: &Srs) -> Result<ProvingKey, String> {
    plonk::setup(&spend::synthesize(&SpendWitness::default()), srs)
}

/// Proves a spend. Fails, naming the violated rule, if the witness does not satisfy the relation.
pub fn prove(pk: &ProvingKey, w: &SpendWitness, rng: &mut impl RngCore) -> Result<[u8; PROOF_BYTES], String> {
    let cs = spend::synthesize(w);
    if let Some((gate, tag)) = cs.unsatisfied() {
        return Err(format!("witness rejected: {tag} (gate {gate})"));
    }
    let proof = plonk::prove(pk, cs.values(), rng)?;
    proof.to_bytes().ok_or_else(|| "degenerate proof".to_string())
}

/// Verifies a spend proof against the nine public inputs
/// (root, nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub).
pub fn verify(vk: &VerifyingKey, publics: &[Fr; N_PUBLIC], proof: &[u8]) -> bool {
    match plonk::Proof::from_bytes(proof) {
        Some(p) => plonk::verify(vk, publics, &p),
        None => false,
    }
}
