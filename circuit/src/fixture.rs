//! Sample spends for tests and benchmarks: a small tree, two notes of one wallet, three outputs.

use crate::model::{self, InputNote, NoteKeys, OutputNote, SpendWitness, Tree, N_IN, N_OUT, TREE_DEPTH};
use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
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
