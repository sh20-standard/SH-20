//! The vectors that tie the three implementations together: circomlibjs (the reference Poseidon),
//! this crate's model (what the circuit constrains) and the wallet reference in js/.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use num_bigint::BigUint;
use sh20_circuit::{model, poseidon, vectors};
use std::str::FromStr;

fn repo(path: &str) -> String {
    std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The decimal strings of a JSON array of strings.
fn strings(array: &str) -> Vec<String> {
    array.split('"').skip(1).step_by(2).map(str::to_string).collect()
}

/// js/vectors.json is exactly what the model writes today: the wallet reference cannot drift from
/// the circuit without this failing. Rewrite it with `cargo run --release --example vectors -- js/vectors.json`.
#[test]
fn the_wallet_vectors_are_the_ones_the_model_writes() {
    assert_eq!(repo("js/vectors.json"), vectors::reference_vectors());
    // and writing them is deterministic
    assert_eq!(vectors::reference_vectors(), vectors::reference_vectors());
}

/// Poseidon for 2 to 5 inputs against circomlibjs (indexer/test/fixtures/poseidon-circomlibjs.json,
/// written by bench/poseidon-vectors.mjs). The constants here come from the Grain LFSR, not from a table.
#[test]
fn poseidon_matches_circomlibjs_for_every_width() {
    let doc = repo("../indexer/test/fixtures/poseidon-circomlibjs.json");
    let mut seen = [false; 6];
    let mut count = 0;
    for entry in doc.split("\"inputs\"").skip(1) {
        let (inputs, rest) = entry.split_once(']').expect("inputs array");
        let inputs: Vec<Fr> = strings(inputs).iter().map(|s| Fr::from_str(s).expect("field element")).collect();
        let hash = strings(rest.split_once("\"hash\"").expect("hash").1).remove(0);
        assert_eq!(poseidon::hash(&inputs), Fr::from_str(&hash).unwrap(), "{} inputs", inputs.len());
        seen[inputs.len()] = true;
        count += 1;
    }
    assert!(count >= 12 && seen[2] && seen[3] && seen[4] && seen[5], "vectors for 2, 3, 4 and 5 inputs");
}

/// The model's signature check is the circuit's: a small-order key is refused even though the group
/// equation holds for it.
#[test]
fn small_order_keys_do_not_verify() {
    let m = Fr::from(99u64);
    let s = BigUint::from(3u8);
    let sig = model::Sig { r8: model::mul_b8(&s), s: model::fr(&s) };
    for weak in [[Fr::zero(), Fr::one()], [Fr::zero(), -Fr::one()]] {
        assert!(model::on_curve(&weak));
        // S·B8 = R8 + h·8·A holds because 8·A is the identity
        assert_eq!(model::mul(&weak, &BigUint::from(8u8)), model::identity());
        assert!(!model::verify_sig(&weak, &m, &sig));
    }
    let keys = model::note_keys(&BigUint::from(5u8), &BigUint::from(7u8));
    assert!(model::verify_sig(&keys.ak, &m, &model::sign(&keys.sk, &m)));
}
