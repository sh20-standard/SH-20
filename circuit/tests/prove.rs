//! Proofs of the spend relation end to end, with the shipped proving key (artifacts/spend.pk).

use ark_bn254::Fr;
use ark_ff::One;
use rand_core::OsRng;
use sh20_circuit::{fixture, keygen, load_key, plonk, prove, spend, srs_size, verify, ProvingKey, SpendWitness, PK_SHA256, PROOF_BYTES, VK_DIGEST};
use std::sync::OnceLock;

fn shipped() -> Vec<u8> {
    std::fs::read(format!("{}/artifacts/spend.pk", env!("CARGO_MANIFEST_DIR"))).expect("artifacts/spend.pk")
}

fn keys() -> &'static ProvingKey {
    static K: OnceLock<ProvingKey> = OnceLock::new();
    K.get_or_init(|| load_key(&shipped()).unwrap())
}

/// The shipped key is exactly what key generation computes from its SRS, and its SRS is a
/// consistent sequence of powers. (That the powers are the Hermez ones is checked by rebuilding the
/// file from the pinned ptau: `sh20-circuit srs`, then `sh20-circuit pk`.)
#[test]
fn shipped_key_is_reproducible() {
    let bytes = shipped();
    assert_eq!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)), PK_SHA256);
    let pk = keys();
    assert_eq!(hex::encode(pk.vk.digest()), VK_DIGEST);
    assert_eq!(pk.vk.to_bytes(), std::fs::read(format!("{}/artifacts/spend.vk", env!("CARGO_MANIFEST_DIR"))).unwrap());

    let srs = pk.srs();
    assert_eq!(srs.g1.len(), srs_size());
    srs.check().unwrap();
    let fresh = keygen(&srs).unwrap();
    assert_eq!(fresh.vk, pk.vk);
    assert_eq!(fresh.to_bytes(), bytes);
}

#[test]
fn a_key_file_that_is_not_the_pinned_one_is_refused() {
    let mut bytes = shipped();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(load_key(&bytes).is_err());
    assert!(load_key(&bytes[..bytes.len() - 64]).is_err());
    assert!(load_key(b"SH20PK01").is_err());
}

#[test]
fn transfer_burn_and_dummies_prove_and_verify() {
    let pk = keys();
    let rng = &mut OsRng;
    let cases = [
        fixture::transfer(rng),
        fixture::spend(rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2),
        fixture::spend(rng, fixture::gene(), [1000, 0], [999, 1, 0], 0, 0, 3),
    ];
    for w in &cases {
        let proof = prove(pk, w, rng).unwrap();
        assert_eq!(proof.len(), PROOF_BYTES);
        let publics = w.publics();
        assert!(verify(&pk.vk, &publics, &proof));

        // each public input is bound
        for i in 0..publics.len() {
            let mut bad = publics;
            bad[i] += Fr::one();
            assert!(!verify(&pk.vk, &bad, &proof), "public input {i} not bound");
        }
        // a proof is bound to its own statement
        let other = fixture::transfer(rng);
        assert!(!verify(&pk.vk, &other.publics(), &proof));
        // malformed or altered proofs
        assert!(!verify(&pk.vk, &publics, &proof[..PROOF_BYTES - 1]));
        assert!(!verify(&pk.vk, &publics, &[proof.as_slice(), &[0u8]].concat()));
        assert!(!verify(&pk.vk, &publics, &[0u8; PROOF_BYTES]));
        for at in [0usize, 31, 32 * 4 + 7, 32 * 8 + 1, 32 * 9, 32 * 14 + 31, PROOF_BYTES - 1] {
            let mut bad = proof;
            bad[at] ^= 0x04;
            assert!(!verify(&pk.vk, &publics, &bad), "byte {at} not bound");
        }
    }
}

#[test]
fn rejected_witnesses_have_no_proof() {
    let pk = keys();
    let rng = &mut OsRng;
    let good = fixture::transfer(rng);
    let mut inflated = good.clone();
    inflated.out_v[0] += Fr::one();
    inflated.out_leaf[0] = sh20_circuit::model::note_leaf(&inflated.t, &inflated.out_v[0], &inflated.out_npk[0], &inflated.out_rho[0]);
    let err = prove(pk, &inflated, rng).unwrap_err();
    assert!(err.contains("conservation"), "{err}");
    let mut unsigned = good.clone();
    unsigned.sig_s[1] += Fr::one();
    assert!(prove(pk, &unsigned, rng).unwrap_err().contains("in1 signature"));

    // even when the prover skips its own check, the proof system refuses the assignment
    let cs = spend::synthesize(&inflated);
    assert!(plonk::prove(pk, cs.values(), rng).is_err());
}

#[test]
fn witness_serialization_round_trips() {
    let w = fixture::transfer(&mut OsRng);
    let bytes = w.to_bytes();
    assert_eq!(bytes.len(), sh20_circuit::model::WITNESS_BYTES);
    assert_eq!(SpendWitness::from_bytes(&bytes).unwrap(), w);
    assert!(SpendWitness::from_bytes(&bytes[1..]).is_none());
    let mut bad = bytes.clone();
    bad[..32].copy_from_slice(&[0xff; 32]); // not below the field modulus
    assert!(SpendWitness::from_bytes(&bad).is_none());
}

#[test]
fn field_helpers() {
    // 2^128 splits the modulus as the canonical-bits gadget assumes
    let p = sh20_circuit::model::p_big();
    assert!(p.bits() == 254 && (&p >> 128usize).bits() <= 126);
}
