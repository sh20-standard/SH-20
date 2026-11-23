//! Sample spends for tests and benchmarks: a small tree, two notes of one wallet, three outputs.

use crate::model::{self, InputNote, NoteKeys, OutputNote, SpendWitness, Tree, N_IN, N_OUT, TREE_DEPTH};
use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_std::rand::RngCore;
use num_bigint::BigUint;

pub fn random_keys(rng: &mut impl RngCore) -> NoteKeys {
    let mut scalar = || {
        let mut b = [0u8; 40];
        rng.fill_bytes(&mut b);
        BigUint::from_bytes_le(&b) % (model::l_big() - 1u8) + 1u8
    };
    let (sk, nk) = (scalar(), scalar());
    model::note_keys(&sk, &nk)
}

/// A spend of asset `t` (`model::ticker_t`): inputs `in_v` (a 0 is a dummy outside the tree), outputs `out_v`, with
/// `filler` unrelated leaves on each side of the real ones.
pub fn spend(rng: &mut impl RngCore, t: u32, in_v: [u64; N_IN], out_v: [u64; N_OUT], v_pub: u64, t_pub: u32, filler: usize) -> SpendWitness {
    let tf = Fr::from(t as u64);
    let mut leaves: Vec<Fr> = (0..filler).map(|_| Fr::rand(rng)).collect();
    let mut notes: Vec<(NoteKeys, u64, Fr, Option<usize>)> = Vec::new();
    for v in in_v {
        let keys = random_keys(rng);
        let rho = Fr::rand(rng);
        let at = if v == 0 {
            None
        } else {
            leaves.push(model::note_leaf(&tf, &Fr::from(v), &keys.npk, &rho));
            Some(leaves.len() - 1)
        };
        notes.push((keys, v, rho, at));
    }
    leaves.extend((0..filler).map(|_| Fr::rand(rng)));
    let tree = Tree::new(&leaves);

    let inputs: [InputNote; N_IN] = std::array::from_fn(|i| {
        let (keys, v, rho, at) = notes[i].clone();
        match at {
            Some(index) => InputNote { keys, v, rho, index: index as u64, path: tree.path(index) },
            None => InputNote { keys, v, rho, index: 0, path: [Fr::zero(); TREE_DEPTH] },
        }
    });
    let outputs: [OutputNote; N_OUT] = std::array::from_fn(|k| OutputNote { npk: random_keys(rng).npk, v: out_v[k], rho: Fr::rand(rng) });
    let mut body = [0u8; 64];
    rng.fill_bytes(&mut body);
    model::build_spend(t, tree.root, &inputs, &outputs, v_pub, t_pub, model::body_hash(&body))
}

/// The asset id of the sample ticker "GENE".
pub fn gene() -> u32 {
    model::ticker_t(b"GENE").expect("ticker")
}

/// A private transfer of "GENE": 600 + 400 → 700 + 250 + 50.
pub fn transfer(rng: &mut impl RngCore) -> SpendWitness {
    spend(rng, gene(), [600, 400], [700, 250, 50], 0, 0, 5)
}

/// Honest spends of every shape, by name: what the relation must accept.
pub fn valid(rng: &mut impl RngCore) -> Vec<(&'static str, SpendWitness)> {
    let ticker = |name: &[u8; 4]| model::ticker_t(name).expect("ticker");
    vec![
        ("transfer", transfer(rng)),
        ("one dummy input, one dummy output", spend(rng, gene(), [1000, 0], [999, 1, 0], 0, 0, 3)),
        ("burn: value leaves under the public ticker", spend(rng, gene(), [600, 400], [100, 0, 0], 900, gene(), 2)),
        ("both inputs dummies: nothing moves", spend(rng, ticker(b"ZZ99"), [0, 0], [0, 0, 0], 0, 0, 1)),
        ("largest amounts", spend(rng, ticker(b"0000"), [u64::MAX, 0], [u64::MAX - 5, 5, 0], 0, 0, 1)),
    ]
}

/// Witnesses the relation must refuse, by name: an honest spend with one thing changed, and whatever
/// an attacker would recompute to hide it. The same list is given to the Rust circuit
/// (tests/spend.rs) and to the circom statement of the relation (bench/cross-check.sh).
///
/// Each one is refused for the rule its name says, and often for others that follow from it: these
/// are altered inputs run through the honest synthesis, not hand-made assignments. tests/constraints.rs
/// and tests/gadgets.rs are the tests that touch single variables.
pub fn adversarial(rng: &mut impl RngCore) -> Vec<(&'static str, SpendWitness)> {
    let good = transfer(rng);
    let p_minus_1 = -Fr::one();
    let leaf_of = |w: &SpendWitness, k: usize| model::note_leaf(&w.t, &w.out_v[k], &w.out_npk[k], &w.out_rho[k]);
    let mut cases: Vec<(&'static str, SpendWitness)> = Vec::new();
    let mut on = |base: &SpendWitness, name: &'static str, f: &dyn Fn(&mut SpendWitness)| {
        let mut w = base.clone();
        f(&mut w);
        cases.push((name, w));
    };

    // inflation
    on(&good, "output worth more than the inputs", &|w| w.out_v[0] += Fr::one());
    on(&good, "output value changed, leaf recomputed", &|w| {
        w.out_v[0] += Fr::one();
        w.out_leaf[0] = leaf_of(w, 0);
    });
    on(&good, "negative output balancing a larger one", &|w| {
        // out0 = v + 1000, out2 = out2 − 1000 (wraps below zero)
        w.out_v[0] += Fr::from(1000u64);
        w.out_v[2] -= Fr::from(1000u64);
        for k in [0, 2] {
            w.out_leaf[k] = leaf_of(w, k);
        }
    });
    on(&good, "output of 2^64", &|w| {
        w.out_v[1] = Fr::from(2u64).pow([64u64]);
        w.out_leaf[1] = leaf_of(w, 1);
    });
    on(&good, "output of p − 1", &|w| {
        w.out_v[1] = p_minus_1;
        w.out_leaf[1] = leaf_of(w, 1);
    });
    on(&good, "input value raised", &|w| w.in_v[0] += Fr::one());
    on(&good, "value taken out without a public amount", &|w| w.v_pub = Fr::from(5u64));

    // ticker
    on(&good, "outputs under another ticker", &|w| {
        let t2 = w.t + Fr::one();
        for k in 0..N_OUT {
            w.out_leaf[k] = model::note_leaf(&t2, &w.out_v[k], &w.out_npk[k], &w.out_rho[k]);
        }
    });
    on(&good, "private ticker changed", &|w| w.t += Fr::one());

    // membership and nullifiers
    on(&good, "wrong root", &|w| w.root += Fr::one());
    on(&good, "wrong sibling", &|w| w.in_path[0][3] += Fr::one());
    on(&good, "wrong position", &|w| w.in_index[0] += Fr::one());
    on(&good, "nullifier not derived from the note", &|w| w.nf[0] += Fr::one());
    on(&good, "second nullifier for the same note (other position)", &|w| {
        let leaf = model::note_leaf(&w.t, &w.in_v[0], &model::npk_of(&w.in_ak[0], &model::mul_b8(&model::to_big(&w.in_nk[0]))), &w.in_rho[0]);
        w.in_index[0] += Fr::one();
        w.nf[0] = crate::poseidon::hash(&[w.in_nk[0], leaf, w.in_index[0]]);
    });
    on(&good, "nullifier key shifted by the group order", &|w| {
        // nk + l is the same point nk·B8, but would give a second nullifier
        w.in_nk[0] += model::fr(model::l_big());
        let nk_pub = model::mul_b8(&(model::to_big(&w.in_nk[0]) % model::l_big()));
        let leaf = model::note_leaf(&w.t, &w.in_v[0], &model::npk_of(&w.in_ak[0], &nk_pub), &w.in_rho[0]);
        w.nf[0] = crate::poseidon::hash(&[w.in_nk[0], leaf, w.in_index[0]]);
    });
    on(&good, "another nullifier key", &|w| w.in_nk[1] += Fr::one());
    on(&good, "rho changed", &|w| w.in_rho[0] += Fr::one());
    on(&good, "one note as both inputs, counted twice", &|w| {
        // input 1 becomes input 0 (600 + 600), and an output takes the 200 this makes
        w.in_v[1] = w.in_v[0];
        w.in_rho[1] = w.in_rho[0];
        w.in_nk[1] = w.in_nk[0];
        w.in_ak[1] = w.in_ak[0];
        w.in_index[1] = w.in_index[0];
        w.in_path[1] = w.in_path[0];
        w.sig_r8[1] = w.sig_r8[0];
        w.sig_s[1] = w.sig_s[0];
        w.nf[1] = w.nf[0];
        w.out_v[0] += Fr::from(200u64);
        w.out_leaf[0] = leaf_of(w, 0);
    });

    // authorization
    on(&good, "signature S changed", &|w| w.sig_s[0] += Fr::one());
    on(&good, "signature S shifted by the group order", &|w| w.sig_s[0] += model::fr(model::l_big()));
    on(&good, "signature R changed", &|w| w.sig_r8[1] = model::add(&w.sig_r8[1], &model::base8()));
    on(&good, "signature over another body", &|w| w.body_hash += Fr::one());
    let other = random_keys(rng);
    on(&good, "signature by another key", &|w| {
        let sig = model::sign(&other.sk, &w.body_hash);
        w.sig_r8[0] = sig.r8;
        w.sig_s[0] = sig.s;
    });
    on(&good, "spend key swapped for the signer's", &|w| {
        let sig = model::sign(&other.sk, &w.body_hash);
        w.in_ak[0] = other.ak;
        w.sig_r8[0] = sig.r8;
        w.sig_s[0] = sig.s;
    });
    on(&good, "signatures swapped between the inputs", &|w| {
        w.sig_r8.swap(0, 1);
        w.sig_s.swap(0, 1);
    });

    // outputs
    on(&good, "output leaf not a note", &|w| w.out_leaf[2] += Fr::one());
    on(&good, "output key changed", &|w| w.out_npk[0] += Fr::one());

    // points off the curve
    on(&good, "signature R off the curve", &|w| w.sig_r8[0][1] += Fr::one());
    on(&good, "spend key off the curve", &|w| w.in_ak[1][0] += Fr::one());

    // value may only leave under the public ticker
    let burn = spend(rng, gene(), [600, 400], [100, 0, 0], 900, gene(), 2);
    on(&burn, "burn under another public ticker", &|w| w.t_pub = Fr::from(model::ticker_t(b"GENF").expect("ticker") as u64));
    on(&burn, "burn of more than the notes hold", &|w| w.v_pub = Fr::from(901u64));
    on(&burn, "burn of p − 1", &|w| w.v_pub = p_minus_1);

    // a dummy input skips membership only: it still needs its nullifier and its signature
    let dummy = spend(rng, gene(), [1000, 0], [999, 1, 0], 0, 0, 3);
    on(&dummy, "dummy input with another nullifier", &|w| w.nf[1] += Fr::one());
    on(&dummy, "dummy input with a bad signature", &|w| w.sig_s[1] += Fr::one());
    on(&dummy, "note with value passed off as a dummy", &|w| w.in_v[1] = Fr::from(10u64));

    cases
}
