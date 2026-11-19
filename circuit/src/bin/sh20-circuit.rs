//! Command line for the spend circuit.
//!
//!   sh20-circuit srs <hermez.ptau> <out.srs>     extract the SRS from the pinned Hermez pot18
//!   sh20-circuit keygen <srs> <out.vk>           derive the keys, write the verifying key, print its digest
//!   sh20-circuit pk <srs> <out.pk>               derive the keys, write the proving key file, print its SHA-256
//!   sh20-circuit info                            size of the circuit, and the gates of each part of the relation
//!   sh20-circuit sample <out.json>               a sample witness as circom input signals
//!   sh20-circuit prove-sample <pk> <dir>         prove a sample spend; write proof, key and publics (binary and snarkjs JSON)
//!   sh20-circuit verify <vk> <proof-hex> <public>×9 (decimal)
//!   sh20-circuit verify-snarkjs <vk.json> <proof.json> <public.json>   check a PLONK proof made by snarkjs (any circuit)
//!   sh20-circuit bench <pk> [runs]               key loading, key generation, prove and verify timings (RAYON_NUM_THREADS=1 for one thread)
//!   sh20-circuit scenario <pk> <out.json>        two mints, a TRANSFER and a BURN with real proofs, for the indexer's end-to-end test
//!
//! <pk> is artifacts/spend.pk, the shipped proving key; <srs> is the file `srs` writes.

use rand_core::OsRng;
use sh20_circuit::{fixture, keygen, load_key, model, plonk, prove, spend, srs_size, verify, Fr, ProvingKey, SpendWitness, Srs, VerifyingKey, N_PUBLIC};
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
fn load_pk(path: &str) -> ProvingKey {
    load_key(&read(path)).unwrap_or_else(|e| fail(&e))
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

/// A chain an indexer can replay, made the way wallets make it (docs/SPEC-NOTES.md): in block 2 a
/// payer mints two public notes of 1,000 "GENE" (leaves 0 and 1, opening npk alone, rho = 0); in block 3 it transfers them as
/// 1,500 and 400 to a recipient and 100 back to itself (anchor 2); in block 4 the recipient, having
/// found its two notes by scanning, burns 900 of them and keeps 1,000 (anchor 3). Field elements
/// are decimal strings, bytes are hex.
fn scenario(pk: &sh20_circuit::ProvingKey) -> String {
    use rand_core::RngCore;
    use sh20_circuit::model::{InputNote, OutputNote, Tree};
    use sh20_circuit::notes::{self, Sealed};
    use sh20_circuit::wire;

    let rng = &mut OsRng;
    let ticker = b"GENE";
    let t = model::ticker_t(ticker).expect("ticker");
    let tf = Fr::from(t as u64);
    let d = plonk::json::dr;
    let fresh = || {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b
    };
    let wallet = || notes::wallet_keys(&fresh()).expect("keys");
    let (payer, recipient) = (wallet(), wallet());

    // block 2: the payer's public notes 0 and 1, of 1,000 units each
    let minted: Vec<_> = (0..2).map(|i| notes::public_opening(&payer.ivk, &payer.address, i).expect("opening")).collect();
    let mut leaves: Vec<Fr> = minted.iter().map(|(npk, sec)| model::note_leaf(&tf, &Fr::from(1000u64), npk, &sec.rho)).collect();

    // block 3: TRANSFER 1,000 + 1,000 → 1,500 and 400 to the recipient, 100 of change, anchored at block 2
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: notes::spend_keys(&payer, &minted[i].1).expect("keys"), v: 1000, rho: minted[i].1.rho, index: i as u64, path: tree.path(i) });
    let pay = [(&recipient.address, 1500u64), (&recipient.address, 400), (&payer.address, 100)];
    let sealed: Vec<(Sealed, notes::NoteSecrets, Fr)> = pay.iter().map(|(to, v)| notes::seal(to, ticker, *v, &fresh()).unwrap_or_else(|e| fail(&e))).collect();
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: sealed[k].2, v: pay[k].1, rho: sealed[k].1.rho });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[i], i as u64));
    let body = wire::transfer_body(2, &nf, &std::array::from_fn(|k| sealed[k].0.into()));
    let w = model::build_spend(t, tree.root, &inputs, &outputs, 0, 0, model::body_hash(&body));
    assert_eq!(w.nf, nf);
    let transfer = wire::envelope(body, &prove(pk, &w, rng).unwrap_or_else(|e| fail(&e)));
    leaves.extend(sealed.iter().map(|o| o.0.leaf));

    // block 4: the recipient scans, finds leaves 2 and 3, and burns 900 of them, anchored at block 3
    let found: Vec<(usize, notes::Opened)> = (2..5).filter_map(|pos| notes::scan(&recipient.ivk, &recipient.address, &sealed[pos - 2].0).map(|o| (pos, o))).collect();
    assert_eq!(found.iter().map(|(pos, o)| (*pos, o.v)).collect::<Vec<_>>(), vec![(2, 1500), (3, 400)], "the recipient finds its two notes and not the change");
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| {
        let (pos, o) = &found[i];
        InputNote { keys: notes::spend_keys(&recipient, &o.secrets).expect("keys"), v: o.v, rho: o.secrets.rho, index: *pos as u64, path: tree.path(*pos) }
    });
    // 1,000 kept; the two unused outputs are notes of 0 sealed to the recipient itself
    let keep = [1000u64, 0, 0];
    let sealed: Vec<(Sealed, notes::NoteSecrets, Fr)> = keep.iter().map(|v| notes::seal(&recipient.address, ticker, *v, &fresh()).unwrap_or_else(|e| fail(&e))).collect();
    let change: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: sealed[k].2, v: keep[k], rho: sealed[k].1.rho });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[found[i].0], found[i].0 as u64));
    let body = wire::burn_body(ticker, 900, 3, &nf, &std::array::from_fn(|k| sealed[k].0.into()));
    let w = model::build_spend(t, tree.root, &inputs, &change, 900, t, model::body_hash(&body));
    let burn = wire::envelope(body, &prove(pk, &w, rng).unwrap_or_else(|e| fail(&e)));

    format!(
        r#"{{"ticker":"GENE","vkDigest":"{}","vk":"{}","mints":[{}],"transfer":"{}","burn":"{}"}}"#,
        hex::encode(pk.vk.digest()),
        hex::encode(pk.vk.to_bytes()),
        minted.iter().map(|(npk, _)| format!(r#"{{"npk":"{}"}}"#, d(npk))).collect::<Vec<_>>().join(","),
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
            for (tag, gates) in cs.gate_counts() {
                println!("{gates:>7}  {tag}");
            }
        }
        "keygen" => {
            let srs = load_srs(arg(1));
            srs.check().unwrap_or_else(|e| fail(&e));
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            std::fs::write(arg(2), pk.vk.to_bytes()).unwrap_or_else(|e| fail(&e.to_string()));
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        "pk" => {
            let srs = load_srs(arg(1));
            srs.check().unwrap_or_else(|e| fail(&e));
            let pk = keygen(&srs).unwrap_or_else(|e| fail(&e));
            let out = pk.to_bytes();
            std::fs::write(arg(2), &out).unwrap_or_else(|e| fail(&e.to_string()));
            println!("{} bytes, sha256 {}, vk digest {}", out.len(), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&out)), hex::encode(pk.vk.digest()));
        }
        "sample" => {
            std::fs::write(arg(1), circom_input(&fixture::transfer(&mut OsRng))).unwrap_or_else(|e| fail(&e.to_string()));
        }
        "prove-sample" => {
            let dir = arg(2);
            let pk = load_pk(arg(1));
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
        "verify-snarkjs" => {
            let text = |i: usize| String::from_utf8(read(arg(i))).unwrap_or_else(|_| fail("not UTF-8"));
            let vk = plonk::json::vk_from_json(&text(1)).unwrap_or_else(|e| fail(&e));
            let proof = plonk::json::proof_from_json(&text(2)).unwrap_or_else(|e| fail(&e));
            let publics = plonk::json::publics_from_json(&text(3)).unwrap_or_else(|e| fail(&e));
            let ok = plonk::verify(&vk, &publics, &proof);
            println!("{}", if ok { "valid" } else { "invalid" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        "bench" => {
            let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
            #[cfg(feature = "parallel")]
            let threads = rayon::current_num_threads();
            #[cfg(not(feature = "parallel"))]
            let threads = 1;
            let bytes = read(arg(1));
            let t = Instant::now();
            let pk = load_key(&bytes).unwrap_or_else(|e| fail(&e));
            let t_load = t.elapsed();
            let t = Instant::now();
            let fresh = keygen(&pk.srs()).unwrap_or_else(|e| fail(&e));
            let t_keygen = t.elapsed();
            assert!(fresh.vk == pk.vk, "the shipped key is not what key generation computes");
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
            println!("verify {:.2} ms; loading the shipped key {:.2} s; key generation from the SRS {:.2} s", t_verify * 1e3, t_load.as_secs_f64(), t_keygen.as_secs_f64());
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        "scenario" => {
            let pk = load_pk(arg(1));
            std::fs::write(arg(2), scenario(&pk)).unwrap_or_else(|e| fail(&e.to_string()));
            println!("vk digest {}", hex::encode(pk.vk.digest()));
        }
        _ => fail("unknown command (see the header of src/bin/sh20-circuit.rs)"),
    }
}
