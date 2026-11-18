//! The spend relation: the model against the reference indexer's vectors, the circuit against the
//! model, and adversarial witnesses against the circuit. No proofs here (see tests/prove.rs).

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use num_bigint::BigUint;
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
    let rng = &mut OsRng;
    let cases = [
        fixture::transfer(rng),
        // one dummy input, one dummy output
        fixture::spend(rng, fixture::gene(), [1000, 0], [999, 1, 0], 0, 0, 3),
        // burn: value leaves under the public ticker
        fixture::spend(rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2),
        // both inputs dummies: nothing moves
        fixture::spend(rng, model::ticker_t(b"ZZ99").unwrap(), [0, 0], [0, 0, 0], 0, 0, 1),
        // largest amounts
        fixture::spend(rng, model::ticker_t(b"0000").unwrap(), [u64::MAX, 0], [u64::MAX - 5, 5, 0], 0, 0, 1),
    ];
    for (i, w) in cases.iter().enumerate() {
        assert_eq!(rejected(w), None, "case {i}");
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

#[test]
fn adversarial_witnesses_are_rejected() {
    let rng = &mut OsRng;
    let good = fixture::transfer(rng);
    assert_eq!(rejected(&good), None);
    let p_minus_1 = -Fr::one();

    let mut cases: Vec<(&str, SpendWitness)> = Vec::new();
    let mut case = |name: &'static str, f: &dyn Fn(&mut SpendWitness)| {
        let mut w = good.clone();
        f(&mut w);
        cases.push((name, w));
    };

    // inflation
    case("output worth more than the inputs", &|w| w.out_v[0] += Fr::one());
    case("output value changed, leaf recomputed", &|w| {
        w.out_v[0] += Fr::one();
        w.out_leaf[0] = model::note_leaf(&w.t, &w.out_v[0], &w.out_npk[0], &w.out_rho[0]);
    });
    case("negative output balancing a larger one", &|w| {
        // out0 = v + 1000, out2 = out2 − 1000 (wraps below zero)
        w.out_v[0] += Fr::from(1000u64);
        w.out_v[2] -= Fr::from(1000u64);
        for k in [0, 2] {
            w.out_leaf[k] = model::note_leaf(&w.t, &w.out_v[k], &w.out_npk[k], &w.out_rho[k]);
        }
    });
    case("output of 2^64", &|w| {
        w.out_v[1] = Fr::from(2u64).pow([64u64]);
        w.out_leaf[1] = model::note_leaf(&w.t, &w.out_v[1], &w.out_npk[1], &w.out_rho[1]);
    });
    case("output of p − 1", &|w| {
        w.out_v[1] = p_minus_1;
        w.out_leaf[1] = model::note_leaf(&w.t, &w.out_v[1], &w.out_npk[1], &w.out_rho[1]);
    });
    case("input value raised", &|w| w.in_v[0] += Fr::one());
    case("value taken out without a public amount", &|w| w.v_pub = Fr::from(5u64));

    // ticker
    case("outputs under another ticker", &|w| {
        let t2 = w.t + Fr::one();
        for k in 0..3 {
            w.out_leaf[k] = model::note_leaf(&t2, &w.out_v[k], &w.out_npk[k], &w.out_rho[k]);
        }
    });
    case("private ticker changed", &|w| w.t += Fr::one());

    // membership and nullifiers
    case("wrong root", &|w| w.root += Fr::one());
    case("wrong sibling", &|w| w.in_path[0][3] += Fr::one());
    case("wrong position", &|w| w.in_index[0] += Fr::one());
    case("nullifier not derived from the note", &|w| w.nf[0] += Fr::one());
    case("second nullifier for the same note (other position)", &|w| {
        let leaf = model::note_leaf(&w.t, &w.in_v[0], &model::npk_of(&w.in_ak[0], &model::mul_b8(&model::to_big(&w.in_nk[0]))), &w.in_rho[0]);
        w.in_index[0] += Fr::one();
        w.nf[0] = sh20_circuit::poseidon::hash(&[w.in_nk[0], leaf, w.in_index[0]]);
    });
    case("nullifier key shifted by the group order", &|w| {
        // nk + l is the same point nk·B8, but would give a second nullifier
        w.in_nk[0] += model::fr(model::l_big());
        let nk_pub = model::mul_b8(&(model::to_big(&w.in_nk[0]) % model::l_big()));
        let leaf = model::note_leaf(&w.t, &w.in_v[0], &model::npk_of(&w.in_ak[0], &nk_pub), &w.in_rho[0]);
        w.nf[0] = sh20_circuit::poseidon::hash(&[w.in_nk[0], leaf, w.in_index[0]]);
    });
    case("another nullifier key", &|w| w.in_nk[1] += Fr::one());
    case("rho changed", &|w| w.in_rho[0] += Fr::one());

    // authorization
    case("signature S changed", &|w| w.sig_s[0] += Fr::one());
    case("signature S shifted by the group order", &|w| w.sig_s[0] += model::fr(model::l_big()));
    case("signature R changed", &|w| w.sig_r8[1] = model::add(&w.sig_r8[1], &model::base8()));
    case("signature over another body", &|w| w.body_hash += Fr::one());
    case("signature by another key", &|w| {
        let other = fixture::random_keys(&mut OsRng);
        let sig = model::sign(&other.sk, &w.body_hash);
        w.sig_r8[0] = sig.r8;
        w.sig_s[0] = sig.s;
    });
    case("spend key swapped for the signer's", &|w| {
        let other = fixture::random_keys(&mut OsRng);
        let sig = model::sign(&other.sk, &w.body_hash);
        w.in_ak[0] = other.ak;
        w.sig_r8[0] = sig.r8;
        w.sig_s[0] = sig.s;
    });
    case("signatures swapped between the inputs", &|w| {
        w.sig_r8.swap(0, 1);
        w.sig_s.swap(0, 1);
    });

    // outputs
    case("output leaf not a note", &|w| w.out_leaf[2] += Fr::one());
    case("output key changed", &|w| w.out_npk[0] += Fr::one());

    for (name, w) in &cases {
        assert!(rejected(w).is_some(), "accepted: {name}");
    }
    println!("{} adversarial witnesses rejected", cases.len());

    // value may only leave under the public ticker
    let burn = fixture::spend(rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2);
    assert_eq!(rejected(&burn), None);
    let mut wrong = burn.clone();
    wrong.t_pub = Fr::from(model::ticker_t(b"GENF").unwrap() as u64);
    assert_eq!(rejected(&wrong).as_deref(), Some("public value"));
    let mut unbalanced = burn.clone();
    unbalanced.v_pub = Fr::from(901u64);
    assert!(rejected(&unbalanced).is_some());
    let mut huge = burn.clone();
    huge.v_pub = p_minus_1;
    assert!(rejected(&huge).is_some());

    // a dummy input skips membership only: it still needs its nullifier and its signature
    let dummy = fixture::spend(rng, fixture::gene(), [1000, 0], [999, 1, 0], 0, 0, 3);
    let mut d = dummy.clone();
    d.nf[1] += Fr::one();
    assert_eq!(rejected(&d).as_deref(), Some("in1 nullifier"));
    let mut d = dummy.clone();
    d.sig_s[1] += Fr::one();
    assert_eq!(rejected(&d).as_deref(), Some("in1 signature"));
    // and a note with value cannot pass as a dummy
    let mut d = dummy.clone();
    d.in_v[1] = Fr::from(10u64);
    assert!(rejected(&d).is_some());
    let _ = (BigUint::from(0u8), Fr::zero());
}
