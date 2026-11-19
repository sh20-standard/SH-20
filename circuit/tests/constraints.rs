//! Is any variable of the spend circuit free? Every variable of an honest assignment is moved, one
//! at a time, to several other values, and the gates must notice.
//!
//! The documented exceptions, and there must be no other:
//!
//!   * variable 0, which only fills unused wire slots, always with a zero selector;
//!   * for a dummy input (v = 0), the inverse witness of the test "v = 0": `is_zero` computes
//!     out = 1 − v·inv and v·out = 0, and with v = 0 both hold for any inv;
//!   * for a dummy input, once dependent variables are recomputed, its 32 Merkle siblings: a dummy
//!     skips membership, which is exactly what docs/SPEC-WIRE.md §4 says and nothing more. Its
//!     position, its nullifier key, its keys and its signature are not free: the nullifier and the
//!     signature still bind them.
//!
//! See tests/common/mod.rs for the two ways a change is judged.

mod common;

use ark_bn254::Fr;
use ark_ff::Zero;
use common::{mutations, Probe};
use rand_core::OsRng;
use sh20_circuit::model::{SpendWitness, N_IN, TREE_DEPTH};
use sh20_circuit::{fixture, spend};

fn dummies(w: &SpendWitness) -> Vec<usize> {
    (0..N_IN).filter(|&i| w.in_v[i].is_zero()).collect()
}

/// With everything else left as it is, any change to any variable breaks a gate.
#[test]
fn every_variable_alone_is_pinned() {
    for (name, w) in fixture::valid(&mut OsRng) {
        let cs = spend::synthesize(&w);
        let probe = Probe::new(&cs);
        let mut free: Vec<u32> = Vec::new();
        let mut tried = 0usize;
        for v in 1..cs.n_vars() as u32 {
            for to in mutations(probe.value(v)) {
                tried += 1;
                if !probe.breaks_alone(v, to) && free.last() != Some(&v) {
                    free.push(v);
                }
            }
        }
        // one per dummy input: the inverse witness of "v = 0", in that input's membership gates
        let want: Vec<String> = dummies(&w).iter().map(|i| format!("in{i} membership")).collect();
        let got: Vec<String> = free.iter().map(|&v| cs.tag_of(probe.first_use(v)).to_string()).collect();
        assert_eq!(got, want, "{name}: free variables {free:?}");
        for &v in &free {
            // the gate out = 1 − x·inv with x = 0, and nothing else
            assert_eq!(probe.uses(v).len(), 1, "{name}");
            let g = &cs.gates()[probe.first_use(v)];
            assert!(g.w[1] == v && probe.value(g.w[0]).is_zero(), "{name}: variable {v} is free and is not the inverse of a zero");
        }
        println!("{name}: {tried} changes to {} variables, {} free", cs.n_vars() - 1, free.len());
    }
}

/// The stronger test: change one of the prover's own choices, recompute everything that follows
/// from it, and some check must still fail.
#[test]
fn every_choice_of_the_prover_reaches_a_check() {
    for (name, w) in fixture::valid(&mut OsRng) {
        let cs = spend::synthesize(&w);
        let mut probe = Probe::new(&cs);
        let sources: Vec<u32> = (1..cs.n_vars() as u32).filter(|&v| probe.is_source(v)).collect();
        let mut free: Vec<u32> = Vec::new();
        let mut tried = 0usize;
        for &v in &sources {
            for to in mutations(probe.value(v)) {
                tried += 1;
                if probe.first_break(v, to).is_none() && free.last() != Some(&v) {
                    free.push(v);
                }
            }
        }
        // per dummy input: 32 siblings and the inverse witness, all in that input's membership gates
        let mut want: Vec<String> = Vec::new();
        for i in dummies(&w) {
            want.extend(std::iter::repeat(format!("in{i} membership")).take(TREE_DEPTH + 1));
        }
        let got: Vec<String> = free.iter().map(|&v| cs.tag_of(probe.first_use(v)).to_string()).collect();
        assert_eq!(got, want, "{name}: free choices {free:?}");
        // a free choice is free for every value tried, never for some only
        for &v in &free {
            for to in mutations(probe.value(v)) {
                assert_eq!(probe.first_break(v, to), None, "{name}: variable {v}");
            }
        }
        println!("{name}: {tried} changes to {} choices of the prover (of {} variables), {} free", sources.len(), cs.n_vars() - 1, free.len());
    }
}

/// The probe itself: it sees a gate that is missing. A circuit that computes a product and forgets
/// to compare it with anything leaves its inputs free under the second test, not under the first.
#[test]
fn the_probe_sees_a_missing_check() {
    use sh20_circuit::cs::Cs;
    let build = |checked: bool| {
        let mut cs = Cs::new();
        let out = cs.public_input(Fr::from(12u64));
        let (x, y) = (cs.alloc(Fr::from(3u64)), cs.alloc(Fr::from(4u64)));
        let product = cs.mul(x, y);
        if checked {
            cs.assert_eq(product, out);
        }
        (cs, x.index())
    };
    let (cs, x) = build(true);
    let mut probe = Probe::new(&cs);
    assert!(probe.is_source(x) && probe.breaks_alone(x, Fr::from(5u64)) && probe.first_break(x, Fr::from(5u64)).is_some());
    let (cs, x) = build(false);
    let mut probe = Probe::new(&cs);
    assert!(probe.breaks_alone(x, Fr::from(5u64)), "alone, the product gate notices");
    assert_eq!(probe.first_break(x, Fr::from(5u64)), None, "recomputed, nothing does");
}
