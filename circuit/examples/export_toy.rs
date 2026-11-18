//! Writes a toy proof, its verifying key and public signals as snarkjs JSON:
//!   cargo run --release --example export_toy -- <dir>
//! bench/cross-verify.mjs then checks them with snarkjs' own PLONK verifier.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use rand_core::OsRng;
use sh20_circuit::{cs::Cs, plonk};

fn main() {
    let dir = std::env::args().nth(1).expect("output directory");
    let tau = Fr::from(0x5348_3230_7465_7374u64);
    for (name, extra) in [("toy8", 0usize), ("toy64", 40)] {
        let mut cs = Cs::new();
        let y = Fr::from(35u64);
        let out = cs.public_input(y);
        let two = cs.public_input(Fr::from(2u64));
        let x = cs.alloc(Fr::from(3u64));
        let x2 = cs.mul(x, x);
        let x3 = cs.mul(x2, x);
        let sum = cs.lin2(Fr::one(), x3, Fr::one(), x, Fr::from(5u64));
        cs.assert_eq(sum, out);
        let t = cs.lin1(Fr::one(), x, -Fr::one());
        cs.assert_eq(t, two);
        let mut acc = x;
        for _ in 0..extra {
            acc = cs.mul(acc, x);
        }
        assert!(cs.is_satisfied());

        let count = plonk::keys::rows_for(cs.n_gates()) + plonk::keys::SRS_EXTRA;
        let mut g1 = Vec::with_capacity(count);
        let mut p = G1Projective::from(G1Affine::generator());
        for _ in 0..count {
            g1.push(p);
            p *= tau;
        }
        let srs = plonk::Srs { g1: G1Projective::normalize_batch(&g1), g2_tau: (G2Affine::generator() * tau).into_affine() };
        let pk = plonk::setup(&cs, &srs).unwrap();
        let proof = plonk::prove(&pk, cs.values(), &mut OsRng).unwrap();
        let publics = cs.public_values();
        assert!(plonk::verify(&pk.vk, &publics, &proof));
        std::fs::write(format!("{dir}/{name}.vk.json"), plonk::json::vk_json(&pk.vk)).unwrap();
        std::fs::write(format!("{dir}/{name}.proof.json"), plonk::json::proof_json(&proof)).unwrap();
        std::fs::write(format!("{dir}/{name}.public.json"), plonk::json::publics_json(&publics)).unwrap();
        println!("{name}: {} gates, power {}", cs.n_gates(), pk.vk.power);
    }
}
