//! The proof system on small circuits: completeness, soundness on tampered inputs, encodings.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, UniformRand, Zero};
use rand_core::OsRng;
use sh20_circuit::cs::Cs;
use sh20_circuit::plonk::{self, Proof, Srs};

/// A throwaway SRS with a known τ. Tests only: the standard uses the Hermez setup.
pub fn test_srs(count: usize) -> Srs {
    let tau = Fr::from(0x5348_3230_7465_7374u64);
    let mut g1 = Vec::with_capacity(count);
    let mut acc = G1Projective::from(G1Affine::generator());
    for _ in 0..count {
        g1.push(acc);
        acc *= tau;
    }
    Srs { g1: G1Projective::normalize_batch(&g1), g2_tau: (G2Affine::generator() * tau).into_affine() }
}

/// x³ + x + 5 = y with y public, plus a chain of `extra` multiplications to vary the size.
fn cubic(x: u64, y: Fr, extra: usize) -> Cs {
    let mut cs = Cs::new();
    let out = cs.public_input(y);
    let xv = cs.alloc(Fr::from(x));
    let x2 = cs.mul(xv, xv);
    let x3 = cs.mul(x2, xv);
    let sum = cs.lin2(Fr::one(), x3, Fr::one(), xv, Fr::from(5u64));
    cs.assert_eq(sum, out);
    let mut acc = xv;
    for _ in 0..extra {
        acc = cs.mul(acc, xv);
    }
    cs
}

#[test]
fn prove_and_verify() {
    for extra in [0usize, 3, 40] {
        let y = Fr::from(3u64 * 3 * 3 + 3 + 5);
        let cs = cubic(3, y, extra);
        assert!(cs.is_satisfied());
        let srs = test_srs(plonk::keys::rows_for(cs.n_gates()) + plonk::keys::SRS_EXTRA);
        srs.check().unwrap();
        let pk = plonk::setup(&cs, &srs).unwrap();
        let proof = plonk::prove(&pk, &cs_values(&cs), &mut OsRng).unwrap();
        assert!(plonk::verify(&pk.vk, &[y], &proof));
        assert!(!plonk::verify(&pk.vk, &[y + Fr::one()], &proof));
        assert!(!plonk::verify(&pk.vk, &[], &proof));

        // every field of the proof is bound
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(bytes.len(), plonk::PROOF_BYTES);
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        for i in 0..15 {
            let mut bad = bytes;
            bad[i * 32] ^= 1;
            match Proof::from_bytes(&bad) {
                Some(p) => assert!(!plonk::verify(&pk.vk, &[y], &p), "field {i}"),
                None => {}
            }
        }
        // the verifying key round-trips and its digest is stable
        let vk2 = plonk::VerifyingKey::from_bytes(&pk.vk.to_bytes()).unwrap();
        assert_eq!(vk2, pk.vk);
        assert_eq!(vk2.digest(), pk.vk.digest());
    }
}

fn cs_values(cs: &Cs) -> Vec<Fr> {
    (0..cs.n_vars() as u32).map(|i| cs.value(sh20_circuit::cs::Var::from_index(i))).collect()
}

#[test]
fn unsatisfied_assignment_is_not_provable() {
    let y = Fr::from(41u64);
    let cs = cubic(3, y, 2); // 3³ + 3 + 5 = 35, not 41
    assert!(!cs.is_satisfied());
    let srs = test_srs(plonk::keys::rows_for(cs.n_gates()) + plonk::keys::SRS_EXTRA);
    let pk = plonk::setup(&cs, &srs).unwrap();
    assert!(plonk::prove(&pk, &cs_values(&cs), &mut OsRng).is_err());
}

#[test]
fn proofs_are_randomized() {
    let y = Fr::from(35u64);
    let cs = cubic(3, y, 0);
    let srs = test_srs(plonk::keys::rows_for(cs.n_gates()) + plonk::keys::SRS_EXTRA);
    let pk = plonk::setup(&cs, &srs).unwrap();
    let a = plonk::prove(&pk, &cs_values(&cs), &mut OsRng).unwrap();
    let b = plonk::prove(&pk, &cs_values(&cs), &mut OsRng).unwrap();
    assert_ne!(a.to_bytes().unwrap(), b.to_bytes().unwrap());
    assert!(plonk::verify(&pk.vk, &[y], &a) && plonk::verify(&pk.vk, &[y], &b));
    let _ = (Fr::zero(), Fr::rand(&mut OsRng).square());
}

/// The verifier against a proof it did not make: snarkjs' PLONK prover on circom/cubic.circom
/// (3³ + 3 + 5 = 35), kept in tests/fixtures/snarkjs/ and rewritten by bench/cross-check.sh.
#[test]
fn a_proof_made_by_snarkjs_is_accepted() {
    let read = |name: &str| std::fs::read_to_string(format!("{}/tests/fixtures/snarkjs/cubic.{name}.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let vk = plonk::json::vk_from_json(&read("vk")).unwrap();
    let proof = plonk::json::proof_from_json(&read("proof")).unwrap();
    let publics = plonk::json::publics_from_json(&read("public")).unwrap();
    assert_eq!(publics, vec![Fr::from(35u64)]);
    assert!(plonk::verify(&vk, &publics, &proof));
    assert!(!plonk::verify(&vk, &[Fr::from(36u64)], &proof));

    // through the wire encoding, and with each of its 15 fields altered
    let bytes = proof.to_bytes().unwrap();
    assert!(plonk::verify(&vk, &publics, &Proof::from_bytes(&bytes).unwrap()));
    for i in 0..15 {
        let mut bad = bytes;
        bad[i * 32 + 1] ^= 1;
        if let Some(p) = Proof::from_bytes(&bad) {
            assert!(!plonk::verify(&vk, &publics, &p), "field {i}");
        }
    }
    // the JSON forms round-trip
    assert_eq!(plonk::json::proof_from_json(&plonk::json::proof_json(&proof)).unwrap(), proof);
    assert_eq!(plonk::json::vk_from_json(&plonk::json::vk_json(&vk)).unwrap(), vk);
}
