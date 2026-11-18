//! Proofs of the spend relation end to end. These use the Hermez SRS when it has been extracted
//! (`sh20-circuit srs <ptau> build/hermez-pot18-2p17.srs`, or SH20_SRS=<file>), and then also check
//! the pinned verifying-key digest; otherwise a throwaway SRS with a known τ.

use ark_bn254::{Fr, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, ScalarMul};
use ark_ff::{One, Zero};
use rand_core::OsRng;
use sh20_circuit::{fixture, keygen, plonk, prove, spend, srs_size, verify, ProvingKey, Srs, SpendWitness, PROOF_BYTES, SRS_SHA256, VK_DIGEST};
use std::sync::OnceLock;

fn hermez_srs() -> Option<Srs> {
    let path = std::env::var("SH20_SRS").unwrap_or_else(|_| format!("{}/build/hermez-pot18-2p17.srs", env!("CARGO_MANIFEST_DIR")));
    let bytes = std::fs::read(path).ok()?;
    assert_eq!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)), SRS_SHA256, "not the pinned SRS");
    Some(Srs::from_bytes(&bytes).expect("SRS file"))
}

fn throwaway_srs(count: usize) -> Srs {
    let tau = Fr::from(0x5348_3230_7465_7374u64);
    let mut powers = Vec::with_capacity(count);
    let mut acc = Fr::one();
    for _ in 0..count {
        powers.push(acc);
        acc *= tau;
    }
    Srs { g1: G1Projective::generator().batch_mul(&powers), g2_tau: (G2Affine::generator() * tau).into_affine() }
}

/// (keys, whether they come from the Hermez SRS)
fn keys() -> &'static (ProvingKey, bool) {
    static K: OnceLock<(ProvingKey, bool)> = OnceLock::new();
    K.get_or_init(|| match hermez_srs() {
        Some(srs) => (keygen(&srs).unwrap(), true),
        None => (keygen(&throwaway_srs(srs_size())).unwrap(), false),
    })
}

#[test]
fn pinned_verifying_key() {
    let (pk, hermez) = keys();
    if !*hermez {
        eprintln!("skipped: extract the Hermez SRS to check the pinned verifying-key digest");
        return;
    }
    assert_eq!(hex::encode(pk.vk.digest()), VK_DIGEST);
    // key generation is deterministic
    assert_eq!(keygen(&hermez_srs().unwrap()).unwrap().vk, pk.vk);
}

#[test]
fn transfer_burn_and_dummies_prove_and_verify() {
    let (pk, _) = keys();
    let rng = &mut OsRng;
    let cases = [fixture::transfer(rng), fixture::spend(rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2), fixture::spend(rng, fixture::gene(), [1000, 0], [999, 1, 0], 0, 0, 3)];
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
    let (pk, _) = keys();
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

/// Every variable of the assignment is pinned by at least one gate: changing any single value breaks
/// a gate. (Variable 0 only fills unused wire slots.)
#[test]
fn no_variable_is_free() {
    let cs = spend::synthesize(&fixture::transfer(&mut OsRng));
    assert!(cs.is_satisfied());
    let gates = cs.gates();
    let mut uses: Vec<Vec<u32>> = vec![Vec::new(); cs.n_vars()];
    for (i, g) in gates.iter().enumerate() {
        for w in g.w {
            if uses[w as usize].last() != Some(&(i as u32)) {
                uses[w as usize].push(i as u32);
            }
        }
    }
    let value = |v: u32| cs.values()[v as usize];
    let mut free = Vec::new();
    for v in 1..cs.n_vars() as u32 {
        let bumped = value(v) + Fr::one();
        let at = |w: u32| if w == v { bumped } else { value(w) };
        let broken = uses[v as usize].iter().any(|&gi| {
            let g = &gates[gi as usize];
            let [a, b, c] = g.w.map(at);
            let mut e = g.q[0] * a + g.q[1] * b + g.q[2] * c + g.q[3] * a * b + g.q[4];
            if (gi as usize) < cs.n_public() {
                e -= value(g.w[0]); // the public input row compares against the original value
            }
            !e.is_zero()
        });
        if !broken {
            free.push(v);
        }
    }
    assert!(free.is_empty(), "{} unconstrained variables, first {:?}", free.len(), &free[..free.len().min(5)]);
}

#[test]
fn field_helpers() {
    // 2^128 splits the modulus as the canonical-bits gadget assumes
    let p = sh20_circuit::model::p_big();
    assert!(p.bits() == 254 && (&p >> 128usize).bits() <= 126);
}
