//! The spend relation: the model against the reference indexer's vectors, the circuit against the
//! model, and adversarial witnesses against the circuit. No proofs here (see tests/prove.rs).

use ark_bn254::Fr;
use ark_ff::One;
use rand_core::OsRng;
use sh20_circuit::model::{self, SpendWitness};
use sh20_circuit::{fixture, spend};
use std::str::FromStr;

fn rejected(w: &SpendWitness) -> Option<String> {
    spend::synthesize(w).unsatisfied().map(|(_, tag)| tag)
}

#[test]
fn leaf_tag_matches_the_indexer() {
    // indexer/src/constants.js DOMAIN.LEAF
    let want = Fr::from_str("3964790311269703051632412659544446401452490375142520467617899154258410484374").unwrap();
    assert_eq!(model::tag_leaf(), want);
}

#[test]
fn ticker_ids_match_the_indexer() {
    // indexer/src/notes.js tickerT: the 4 ASCII bytes as a big-endian u32
    assert_eq!(model::ticker_t(b"GENE"), Some(0x4745_4e45));
    assert_eq!(model::ticker_t(b"0000"), Some(0x3030_3030));
    for bad in [&b"gene"[..], b"GEN", b"GENES", b"GE E", b"\0\0\0\0"] {
        assert_eq!(model::ticker_t(bad), None);
    }
}

#[test]
fn signatures() {
    let keys = fixture::random_keys(&mut OsRng);
    let m = Fr::from(123456789u64);
    let sig = model::sign(&keys.sk, &m);
    assert!(model::verify_sig(&keys.ak, &m, &sig));
    assert!(!model::verify_sig(&keys.ak, &(m + Fr::one()), &sig));
    assert!(model::on_curve(&keys.ak) && model::on_curve(&model::base8()));
    // Base8 has order l
    assert_eq!(model::mul(&model::base8(), model::l_big()), model::identity());
}

#[test]
fn valid_spends_satisfy_the_circuit() {
    let cases = fixture::valid(&mut OsRng);
    assert_eq!(cases.len(), 5);
    for (name, w) in &cases {
        assert_eq!(rejected(w), None, "refused: {name}");
    }
}

#[test]
fn the_gates_do_not_depend_on_the_witness() {
    let a = spend::synthesize(&SpendWitness::default());
    let b = spend::synthesize(&fixture::transfer(&mut OsRng));
    assert_eq!(a.n_gates(), b.n_gates());
    assert_eq!(a.n_vars(), b.n_vars());
    assert!(a.same_gates(&b));
    println!("spend circuit: {} gates, {} variables", a.n_gates(), a.n_vars());
}

/// The witnesses of `fixture::adversarial`: 29 on a transfer (7 inflation, 2 ticker, 9 membership and
/// nullifiers, 7 authorisation, 2 outputs, 2 points off the curve), 3 on a burn, 3 on a dummy input.
/// bench/cross-check.sh gives the same list to circom's statement of the relation.
#[test]
fn adversarial_witnesses_are_rejected() {
    let cases = fixture::adversarial(&mut OsRng);
    assert_eq!(cases.len(), 35);
    let mut names: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), cases.len(), "two cases share a name");
    for (name, w) in &cases {
        assert!(rejected(w).is_some(), "accepted: {name}");
    }
    println!("{} adversarial witnesses rejected", cases.len());

    // where the circuit stops, for the cases that break one rule only
    let tag = |name: &str| rejected(&cases.iter().find(|(n, _)| *n == name).expect(name).1);
    assert_eq!(tag("burn under another public ticker").as_deref(), Some("public value"));
    assert_eq!(tag("dummy input with another nullifier").as_deref(), Some("in1 nullifier"));
    assert_eq!(tag("dummy input with a bad signature").as_deref(), Some("in1 signature"));
    assert_eq!(tag("signature R off the curve").as_deref(), Some("in0 signature"));
    assert_eq!(tag("output worth more than the inputs").as_deref(), Some("out0 leaf"));
    assert_eq!(tag("value taken out without a public amount").as_deref(), Some("public value"));
    assert_eq!(tag("one note as both inputs, counted twice").as_deref(), Some("nullifiers distinct"));
}
