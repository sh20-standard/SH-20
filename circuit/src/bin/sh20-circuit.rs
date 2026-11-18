//! Command line for the spend circuit.
//!
//!   sh20-circuit srs <hermez.ptau> <out.srs>     extract the SRS from the pinned Hermez pot18
//!   sh20-circuit keygen <srs> <out.vk>           derive the keys, write the verifying key, print its digest
//!   sh20-circuit info                            size of the circuit
//!   sh20-circuit sample <out.json>               a sample witness as circom input signals
//!   sh20-circuit prove-sample <srs> <dir>        prove a sample spend; write proof, key and publics (binary and snarkjs JSON)
//!   sh20-circuit verify <vk> <proof-hex> <public>×9 (decimal)
//!   sh20-circuit bench <srs> [runs]              keygen, prove and verify timings (RAYON_NUM_THREADS=1 for one thread)
//!   sh20-circuit scenario <srs> <out.json>       two mints, a TRANSFER and a BURN with real proofs, for the indexer's end-to-end test

use rand_core::OsRng;
use sh20_circuit::{fixture, keygen, model, plonk, prove, spend, srs_size, verify, Fr, SpendWitness, Srs, VerifyingKey, N_PUBLIC};
use std::time::Instant;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")))
}
fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}
fn load_srs(path: &str) -> Srs {
    Srs::from_bytes(&read(path)).unwrap_or_else(|e| fail(&e))
}

/// The witness as the input signals of circom/spend.circom.
fn circom_input(w: &SpendWitness) -> String {
    let d = plonk::json::dr;
    let list = |xs: &[Fr]| format!("[{}]", xs.iter().map(|x| format!("\"{}\"", d(x))).collect::<Vec<_>>().join(","));
    let pts = |ps: &[model::Pt]| format!("[{}]", ps.iter().map(|p| list(p)).collect::<Vec<_>>().join(","));
    format!(
        r#"{{"root":"{}","nf":{},"outLeaf":{},"bodyHash":"{}","vPub":"{}","tPub":"{}","t":"{}","inV":{},"inRho":{},"inNk":{},"inAk":{},"inIndex":{},"inPath":[{},{}],"sigR8":{},"sigS":{},"outV":{},"outNpk":{},"outRho":{}}}"#,
        d(&w.root),
        list(&w.nf),
        list(&w.out_leaf),
        d(&w.body_hash),
        d(&w.v_pub),
        d(&w.t_pub),
        d(&w.t),
        list(&w.in_v),
        list(&w.in_rho),
        list(&w.in_nk),
        pts(&w.in_ak),
        list(&w.in_index),
        list(&w.in_path[0]),
        list(&w.in_path[1]),
        pts(&w.sig_r8),
        list(&w.sig_s),
        list(&w.out_v),
        list(&w.out_npk),
        list(&w.out_rho),
    )
}

/// A chain an indexer can replay: block 2 mints two notes of 1,000 units of token 1 (leaves 0 and 1);
/// block 3 transfers them into 1,500 + 400 + 100 (anchor 2); block 4 burns 900 out of the 1,500 and
/// the 400 (anchor 3). Field elements are decimal strings, bytes are hex.
fn scenario(pk: &sh20_circuit::ProvingKey) -> String {
    use ark_ff::UniformRand;
    use rand_core::RngCore;
    use sh20_circuit::model::{InputNote, OutputNote, Tree};
    use sh20_circuit::wire::{self, Output};

    let rng = &mut OsRng;
    let t = 1u32;
    let tf = Fr::from(t as u64);
    let d = plonk::json::dr;
    let sealed = |leaf: Fr| {
        let (mut pk_eph, mut ct) = ([0u8; 33], [0u8; 28]);
        OsRng.fill_bytes(&mut pk_eph[1..]);
        OsRng.fill_bytes(&mut ct);
        pk_eph[0] = 0x02;
        Output { leaf, pk_eph, ct }
    };
    let leaf_of = |o: &OutputNote| model::note_leaf(&tf, &Fr::from(o.v), &o.npk, &o.rho);

    // block 2: two public mints of 1,000 units
    let minted: Vec<(model::NoteKeys, Fr)> = (0..2).map(|_| (fixture::random_keys(rng), Fr::rand(rng))).collect();
    let mut leaves: Vec<Fr> = minted.iter().map(|(k, rho)| model::note_leaf(&tf, &Fr::from(1000u64), &k.npk, rho)).collect();

    // block 3: TRANSFER 1,000 + 1,000 → 1,500 + 400 + 100, anchored at block 2
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: minted[i].0.clone(), v: 1000, rho: minted[i].1, index: i as u64, path: tree.path(i) });
    let owners: Vec<model::NoteKeys> = (0..3).map(|_| fixture::random_keys(rng)).collect();
    let amounts = [1500u64, 400, 100];
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: owners[k].npk, v: amounts[k], rho: Fr::rand(rng) });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[i], i as u64));
    let body = wire::transfer_body(2, &nf, &outputs.map(|o| sealed(leaf_of(&o))));
    let w = model::build_spend(t, tree.root, &inputs, &outputs, 0, 0, model::body_hash(&body));
    assert_eq!(w.nf, nf);
    let transfer = wire::envelope(body, &prove(pk, &w, rng).unwrap_or_else(|e| fail(&e)));
    leaves.extend(outputs.iter().map(leaf_of));

    // block 4: BURN 900 out of the 1,500 and the 400, anchored at block 3
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: owners[i].clone(), v: amounts[i], rho: outputs[i].rho, index: 2 + i as u64, path: tree.path(2 + i) });
    let change: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: fixture::random_keys(rng).npk, v: if k == 0 { 1000 } else { 0 }, rho: Fr::rand(rng) });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[2 + i], 2 + i as u64));
    let body = wire::burn_body(t, 900, 3, &nf, &change.map(|o| sealed(leaf_of(&o))));
    let w = model::build_spend(t, tree.root, &inputs, &change, 900, t, model::body_hash(&body));
    let burn = wire::envelope(body, &prove(pk, &w, rng).unwrap_or_else(|e| fail(&e)));

    format!(
        r#"{{"vkDigest":"{}","vk":"{}","mints":[{}],"transfer":"{}","burn":"{}"}}"#,
        hex::encode(pk.vk.digest()),
        hex::encode(pk.vk.to_bytes()),
        minted.iter().map(|(k, rho)| format!(r#"{{"npk":"{}","rho":"{}"}}"#, d(&k.npk), d(rho))).collect::<Vec<_>>().join(","),
        hex::encode(transfer),
        hex::encode(burn),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or_else(|| fail("missing argument (see the header of src/bin/sh20-circuit.rs)"));
    match arg(0) {
        "srs" => {
            let bytes = read(arg(1));
            if plonk::srs::blake2b_hex(&bytes) != plonk::srs::POT18_BLAKE2B {
                fail("the ptau file is not the pinned Hermez powersOfTau28_hez_final_18.ptau");
            }
            let srs = Srs::from_ptau(&bytes, srs_size()).unwrap_or_else(|e| fail(&e));
            let out = srs.to_bytes();
            std::fs::write(arg(2), &out).unwrap_or_else(|e| fail(&e.to_string()));
            println!("{} powers, {} bytes, sha256 {}", srs.g1.len(), out.len(), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&out)));
        }
        "info" => {
            let cs = spend::synthesize(&SpendWitness::default());
            let rows = plonk::keys::rows_for(cs.n_gates());
            println!("{} gates, {} variables, {} public inputs, domain 2^{} = {} rows, SRS {} powers", cs.n_gates(), cs.n_vars(), cs.n_public(), rows.trailing_zeros(), rows, srs_size());
        }
        "keygen" => {
            let srs = load_srs(arg(1));
            srs.check().unwrap_or_else(|e| fail(&e));
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            std::fs::write(arg(2), pk.vk.to_bytes()).unwrap_or_else(|e| fail(&e.to_string()));
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        "sample" => {
            std::fs::write(arg(1), circom_input(&fixture::transfer(&mut OsRng))).unwrap_or_else(|e| fail(&e.to_string()));
        }
        "prove-sample" => {
            let srs = load_srs(arg(1));
            let dir = arg(2);
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            let w = fixture::transfer(&mut OsRng);
            let proof = prove(&pk, &w, &mut OsRng).unwrap_or_else(|e| fail(&e));
            let publics = w.publics();
            assert!(verify(&pk.vk, &publics, &proof));
            let parsed = plonk::Proof::from_bytes(&proof).unwrap();
            let put = |name: &str, data: &[u8]| std::fs::write(format!("{dir}/{name}"), data).unwrap_or_else(|e| fail(&e.to_string()));
            put("spend.proof", &proof);
            put("spend.vk", &pk.vk.to_bytes());
            put("spend.input.json", circom_input(&w).as_bytes());
            put("spend.vk.json", plonk::json::vk_json(&pk.vk).as_bytes());
            put("spend.proof.json", plonk::json::proof_json(&parsed).as_bytes());
            put("spend.public.json", plonk::json::publics_json(&publics).as_bytes());
            println!("proof {} bytes, vk digest {}", proof.len(), hex::encode(pk.vk.digest()));
        }
        "verify" => {
            let vk = VerifyingKey::from_bytes(&read(arg(1))).unwrap_or_else(|e| fail(&e));
            let proof = hex::decode(arg(2)).unwrap_or_else(|_| fail("proof: bad hex"));
            if args.len() != 3 + N_PUBLIC {
                fail("expected nine public inputs");
            }
            let mut publics = [Fr::from(0u64); N_PUBLIC];
            for (i, slot) in publics.iter_mut().enumerate() {
                let s = arg(3 + i);
                if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                    fail("public input: not a decimal");
                }
                let v = model::big(s);
                if v >= model::p_big() {
                    fail("public input: not in the field");
                }
                *slot = model::fr(&v);
            }
            let ok = verify(&vk, &publics, &proof);
            println!("{}", if ok { "valid" } else { "invalid" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        "bench" => {
            let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
            #[cfg(feature = "parallel")]
            let threads = rayon::current_num_threads();
            #[cfg(not(feature = "parallel"))]
            let threads = 1;
            let t = Instant::now();
            let srs = load_srs(arg(1));
            let t_srs = t.elapsed();
            let t = Instant::now();
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            let t_keygen = t.elapsed();
            let w = fixture::transfer(&mut OsRng);
            let t = Instant::now();
            let cs = spend::synthesize(&w);
            let t_witness = t.elapsed();
            let mut times = Vec::new();
            let mut proof = [0u8; sh20_circuit::PROOF_BYTES];
            for _ in 0..runs {
                let t = Instant::now();
                proof = prove(&pk, &w, &mut OsRng).unwrap_or_else(|e| fail(&e));
                times.push(t.elapsed().as_secs_f64());
            }
            let publics = w.publics();
            let n_ver = 50;
            let t = Instant::now();
            for _ in 0..n_ver {
                assert!(verify(&pk.vk, &publics, &proof));
            }
            let t_verify = t.elapsed().as_secs_f64() / n_ver as f64;
            let mut sorted = times.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!("{} gates, domain 2^{}, proof {} bytes, vk {} bytes", cs.n_gates(), pk.vk.power, proof.len(), pk.vk.to_bytes().len());
            println!(
                "threads {threads}: prove min {:.2} s, median {:.2} s over {runs} ({}); includes witness synthesis {:.3} s",
                sorted[0],
                sorted[sorted.len() / 2],
                times.iter().map(|x| format!("{x:.2}")).collect::<Vec<_>>().join(" / "),
                t_witness.as_secs_f64()
            );
            println!("verify {:.2} ms; SRS load {:.2} s; keygen {:.2} s", t_verify * 1e3, t_srs.as_secs_f64(), t_keygen.as_secs_f64());
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        "scenario" => {
            let srs = load_srs(arg(1));
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            std::fs::write(arg(2), scenario(&pk)).unwrap_or_else(|e| fail(&e.to_string()));
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        _ => fail("unknown command (see the header of src/bin/sh20-circuit.rs)"),
    }
}
