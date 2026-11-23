//! Tests written by the audit of 2026-11-23 (`docs/audit/2026-11-23-circuit.md`): properties of the
//! relation its report relies on, checked on witnesses the existing cases do not build. No proofs here.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use rand_core::OsRng;
use sh20_circuit::model::{self, InputNote, OutputNote, SpendWitness, Tree, TREE_DEPTH};
use sh20_circuit::{fixture, poseidon, spend};

fn rejected(w: &SpendWitness) -> Option<String> {
    spend::synthesize(w).unsatisfied().map(|(_, tag)| tag)
}

fn out(v: u64) -> OutputNote {
    OutputNote { npk: fixture::random_keys(&mut OsRng).npk, v, rho: Fr::from(7u64) }
}

/// circuit-1: the relation accepts one note as both inputs, counted twice, with nf0 = nf1. Only the
/// indexers' rule that a spend's two nullifiers differ (SPEC-WIRE §5, "distinct") refuses it.
#[test]
fn audit_one_note_as_both_inputs_satisfies_the_relation_with_equal_nullifiers() {
    let t = fixture::gene();
    let keys = fixture::random_keys(&mut OsRng);
    let rho = Fr::from(11u64);
    let leaf = model::note_leaf(&Fr::from(t as u64), &Fr::from(500u64), &keys.npk, &rho);
    let tree = Tree::new(&[Fr::from(1u64), leaf, Fr::from(2u64)]);
    let note = InputNote { keys, v: 500, rho, index: 1, path: tree.path(1) };
    let w = model::build_spend(t, tree.root, &[note.clone(), note], &[out(1000), out(0), out(0)], 0, 0, model::body_hash(b"audit"));
    assert_eq!(rejected(&w), None, "the relation does not refuse a note spent as both inputs");
    assert_eq!(w.nf[0], w.nf[1], "so the indexer's nf0 != nf1 is what keeps the value from doubling");
}

/// A position shifted by 2^32 would give the note a second nullifier; the 32-bit decomposition of
/// the index refuses it.
#[test]
fn audit_a_position_shifted_by_2_32_is_refused() {
    let mut w = fixture::transfer(&mut OsRng);
    let shift = Fr::from(2u64).pow([32u64]);
    let leaf = model::note_leaf(&w.t, &w.in_v[0], &model::npk_of(&w.in_ak[0], &model::mul_b8(&model::to_big(&w.in_nk[0]))), &w.in_rho[0]);
    w.in_index[0] += shift;
    w.nf[0] = poseidon::hash(&[w.in_nk[0], leaf, w.in_index[0]]);
    assert_eq!(rejected(&w).as_deref(), Some("in0 membership"));
}

/// circuit-3: a spend of two dummies creates notes of value 0 under any asset id, including t = 0
/// (reserved for BTC) and tickers never deployed. Nothing of value moves.
#[test]
fn audit_two_dummies_make_zero_notes_of_any_asset() {
    for t in [0u32, u32::MAX] {
        let dummy = || InputNote { keys: fixture::random_keys(&mut OsRng), v: 0, rho: Fr::from(3u64), index: 0, path: [Fr::zero(); TREE_DEPTH] };
        let w = model::build_spend(t, Fr::from(99u64), &[dummy(), dummy()], &[out(0), out(0), out(0)], 0, 0, model::body_hash(b"audit"));
        assert_eq!(rejected(&w), None, "t = {t}");
        let mut more = w.clone();
        more.out_v[0] = Fr::from(1u64);
        more.out_leaf[0] = model::note_leaf(&more.t, &more.out_v[0], &more.out_npk[0], &more.out_rho[0]);
        assert!(rejected(&more).is_some(), "t = {t}: a dummy-only spend made value");
    }
}
