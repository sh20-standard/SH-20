//! The SH-20 spend relation (docs/SPEC-WIRE.md §4) as PLONK gates: two input notes, three output
//! notes, one private ticker.
//!
//! Derived from Tacit's Bitcoin shielded pool spend relation (dapp/circuits/btc-pool/spend.circom and
//! its Halo2 port), MIT License, Copyright (c) 2026 ross. Changes for SH-20: the ticker is private
//! (one t for the five notes, tied to tPub only when value leaves the pool), the SH-20 note leaf, the
//! public inputs and their order, and no transparent boundary (no exit or deposit commitments, no
//! empty slots). `circom/spend.circom` states the same relation with circomlib and is used to
//! cross-check this file.
//!
//! Public inputs, in order: root, nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub.
//!
//! What a proof shows, for private t, notes and keys:
//!   * each input note is `leaf_i = H(H(H(TAG_LEAF, t), v_i), H(npk_i, rho_i))` with
//!     `npk_i = Poseidon(Ak_i, nk_i·B8)`, and unless v_i = 0 it sits in the tree under `root` at `index_i`;
//!   * `nf_i = Poseidon(nk_i, leaf_i, index_i)` with 0 ≤ nk_i < l, so a note has one nullifier;
//!   * Ak_i is a point of the curve and its owner signed `bodyHash` (EdDSA-Poseidon, with R8 on the curve);
//!   * each output leaf is a note of the same t;
//!   * every amount and vPub is below 2^64 and Σ v_in = Σ v_out + vPub;
//!   * vPub·(t − tPub) = 0.

use crate::cs::{Cs, Var};
use crate::gadgets::{self, Lane};
use crate::model::{self, SpendWitness, N_IN, N_OUT, TREE_DEPTH};
use ark_bn254::Fr;
use ark_ff::{One, Zero};

/// leaf = H(H(head, v), H(npk, rho)).
fn note_leaf(cs: &mut Cs, head: Var, v: Var, npk: Var, rho: Var) -> Var {
    let hv = gadgets::poseidon_vars(cs, &[head, v]);
    let hk = gadgets::poseidon_vars(cs, &[npk, rho]);
    gadgets::poseidon_vars(cs, &[hv, hk])
}

/// Emits the gates of the relation and assigns them from `w`. The gates do not depend on `w`.
pub fn synthesize(w: &SpendWitness) -> Cs {
    let mut system = Cs::new();
    let cs = &mut system;

    cs.at("public");
    let root = cs.public_input(w.root);
    let nf: [Var; N_IN] = std::array::from_fn(|i| cs.public_input(w.nf[i]));
    let out_leaf: [Var; N_OUT] = std::array::from_fn(|k| cs.public_input(w.out_leaf[k]));
    let body = cs.public_input(w.body_hash);
    let v_pub = cs.public_input(w.v_pub);
    let t_pub = cs.public_input(w.t_pub);

    cs.at("ticker");
    let t = cs.alloc(w.t);
    let head = gadgets::poseidon(cs, &[Lane::Const(model::tag_leaf()), Lane::Var(t)]);

    let mut in_v = Vec::with_capacity(N_IN);
    for (i, &nf_i) in nf.iter().enumerate() {
        cs.at(format!("in{i} value"));
        let v = cs.alloc(w.in_v[i]);
        gadgets::range(cs, v, 64);

        cs.at(format!("in{i} nullifier key"));
        let nk = cs.alloc(w.in_nk[i]);
        let nk_bits = gadgets::scalar_bits(cs, nk);
        let nk_pub = gadgets::fixed_mul(cs, &nk_bits, &model::base8());

        cs.at(format!("in{i} note"));
        let ak = [cs.alloc(w.in_ak[i][0]), cs.alloc(w.in_ak[i][1])];
        let npk = gadgets::poseidon_vars(cs, &[ak[0], ak[1], nk_pub[0], nk_pub[1]]);
        let rho = cs.alloc(w.in_rho[i]);
        let leaf = note_leaf(cs, head, v, npk, rho);

        cs.at(format!("in{i} membership"));
        let index = cs.alloc(w.in_index[i]);
        let index_bits = gadgets::to_bits(cs, index, TREE_DEPTH);
        let path: Vec<Var> = w.in_path[i].iter().map(|s| cs.alloc(*s)).collect();
        let reached = gadgets::merkle_root(cs, leaf, &index_bits, &path);
        // (reached − root)·(1 − [v = 0]) = 0
        let dummy = cs.is_zero(v);
        let diff = cs.sub(reached, root);
        cs.gate(diff, dummy, Var::from_index(0), [Fr::one(), Fr::zero(), Fr::zero(), -Fr::one(), Fr::zero()]);

        cs.at(format!("in{i} nullifier"));
        let nfh = gadgets::poseidon_vars(cs, &[nk, leaf, index]);
        cs.assert_eq(nfh, nf_i);

        cs.at(format!("in{i} signature"));
        let r8 = [cs.alloc(w.sig_r8[i][0]), cs.alloc(w.sig_r8[i][1])];
        let s = cs.alloc(w.sig_s[i]);
        gadgets::eddsa_verify(cs, ak, r8, s, body);

        in_v.push(v);
    }

    let mut out_v = Vec::with_capacity(N_OUT);
    for (k, &out_leaf_k) in out_leaf.iter().enumerate() {
        cs.at(format!("out{k} value"));
        let v = cs.alloc(w.out_v[k]);
        gadgets::range(cs, v, 64);
        cs.at(format!("out{k} leaf"));
        let npk = cs.alloc(w.out_npk[k]);
        let rho = cs.alloc(w.out_rho[k]);
        let leaf = note_leaf(cs, head, v, npk, rho);
        cs.assert_eq(leaf, out_leaf_k);
        out_v.push(v);
    }

    cs.at("public value");
    gadgets::range(cs, v_pub, 64);
    // value leaves the pool only under the public ticker
    let dt = cs.sub(t, t_pub);
    cs.assert_mul_zero(v_pub, dt);

    cs.at("conservation");
    let sum_in = cs.add(in_v[0], in_v[1]);
    let sum_out = cs.lc(&[(Fr::one(), out_v[0]), (Fr::one(), out_v[1]), (Fr::one(), out_v[2]), (Fr::one(), v_pub)], Fr::zero());
    cs.assert_eq(sum_in, sum_out);

    system
}
