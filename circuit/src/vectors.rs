//! Reference vectors of what a wallet computes for a spend: ticker ids, note keys and `npk`, note
//! leaves, nullifiers, body hashes, EdDSA-Poseidon signatures, and one whole transfer. Everything
//! is produced by the model the circuit constrains (`model`), from fixed seeds, so the file is the
//! same on every run.
//!
//!   cargo run --release --example vectors -- js/vectors.json
//!
//! `circuit/js` reproduces every value (its tests read the file), and `tests/vectors.rs` checks that
//! the file in the repository is the one this module writes.

use crate::model::{self, InputNote, NoteKeys, OutputNote, Pt, Tree, TREE_DEPTH};
use crate::plonk::json::dr;
use crate::{poseidon, wire, Fr};
use ark_ff::{PrimeField, Zero};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const SEED_TAG: &str = "sh20/test-vectors/";

/// A scalar in [1, l) from a label.
fn scalar(label: &str) -> BigUint {
    model::hash_to_scalar(SEED_TAG, &[label.as_bytes()])
}
/// A field element from a label.
fn field(label: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&Sha256::digest(format!("{SEED_TAG}{label}")))
}
fn bytes(label: &str, n: usize) -> Vec<u8> {
    (0u32..).flat_map(|i| Sha256::digest(format!("{SEED_TAG}{label}/{i}")).to_vec()).take(n).collect()
}

fn q(s: &str) -> String {
    format!("\"{s}\"")
}
fn pt(p: &Pt) -> String {
    format!("[{},{}]", q(&dr(&p[0])), q(&dr(&p[1])))
}
fn list(items: Vec<String>) -> String {
    format!("[\n    {}\n  ]", items.join(",\n    "))
}

fn keys_json(k: &NoteKeys) -> String {
    format!(r#"{{"sk":"{}","nk":"{}","ak":{},"nkPub":{},"npk":"{}"}}"#, k.sk, k.nk, pt(&k.ak), pt(&k.nk_pub), dr(&k.npk))
}

/// The vectors, as the JSON document kept in `js/vectors.json`.
pub fn reference_vectors() -> String {
    let l = model::l_big().clone();
    let one = BigUint::from(1u8);

    let poseidon_inputs: Vec<Vec<Fr>> = (2..=5u64).map(|n| (1..=n).map(Fr::from).collect()).collect();
    let poseidon_json = list(poseidon_inputs.iter().map(|xs| format!(r#"{{"inputs":[{}],"hash":"{}"}}"#, xs.iter().map(|x| q(&dr(x))).collect::<Vec<_>>().join(","), dr(&poseidon::hash(xs)))).collect());

    let tickers = ["GENE", "0000", "ZZ99", "A1B2"];
    let tickers_json = list(tickers.iter().map(|t| format!(r#"{{"ticker":"{t}","t":"{}"}}"#, model::ticker_t(t.as_bytes()).expect("ticker"))).collect());

    // note keys: seeded ones, and the ends of the scalar range
    let key_sets: Vec<NoteKeys> = vec![
        model::note_keys(&scalar("keys/0/sk"), &scalar("keys/0/nk")),
        model::note_keys(&scalar("keys/1/sk"), &scalar("keys/1/nk")),
        model::note_keys(&one, &one),
        model::note_keys(&(&l - &one), &(&l - &one)),
    ];
    let keys_json_all = list(key_sets.iter().map(keys_json).collect());

    // leaves
    let gene = Fr::from(model::ticker_t(b"GENE").unwrap() as u64);
    let leaf_cases: Vec<(&str, u64, Fr, Fr)> = vec![
        ("GENE", 1000, key_sets[0].npk, field("leaf/0/rho")),
        ("GENE", 0, key_sets[1].npk, field("leaf/1/rho")),
        ("ZZ99", u64::MAX, key_sets[2].npk, field("leaf/2/rho")),
    ];
    let leaf_of = |(ticker, v, npk, rho): &(&str, u64, Fr, Fr)| model::note_leaf(&Fr::from(model::ticker_t(ticker.as_bytes()).unwrap() as u64), &Fr::from(*v), npk, rho);
    let leaves_json = list(
        leaf_cases
            .iter()
            .map(|c| format!(r#"{{"ticker":"{}","v":"{}","npk":"{}","rho":"{}","leaf":"{}"}}"#, c.0, c.1, dr(&c.2), dr(&c.3), dr(&leaf_of(c))))
            .collect(),
    );

    // nullifiers: the first and the last position of the tree
    let nf_cases: Vec<(&BigUint, Fr, u64)> = vec![
        (&key_sets[0].nk, leaf_of(&leaf_cases[0]), 0),
        (&key_sets[1].nk, leaf_of(&leaf_cases[1]), 5),
        (&key_sets[3].nk, leaf_of(&leaf_cases[2]), (1u64 << TREE_DEPTH) - 1),
    ];
    let nullifiers_json = list(nf_cases.iter().map(|(nk, leaf, index)| format!(r#"{{"nk":"{nk}","leaf":"{}","index":"{index}","nf":"{}"}}"#, dr(leaf), dr(&model::nullifier(nk, leaf, *index)))).collect());

    // body hashes
    let bodies: Vec<Vec<u8>> = vec![Vec::new(), b"SH20".to_vec(), bytes("body/2", 355)];
    let bodies_json = list(bodies.iter().map(|b| format!(r#"{{"body":"{}","bodyHash":"{}"}}"#, hex::encode(b), dr(&model::body_hash(b)))).collect());

    // signatures
    let sig_cases: Vec<(&NoteKeys, Fr)> = vec![(&key_sets[0], model::body_hash(&bodies[2])), (&key_sets[1], Fr::zero()), (&key_sets[2], -Fr::from(1u64)), (&key_sets[3], field("signature/3/message"))];
    let signatures_json = list(
        sig_cases
            .iter()
            .map(|(k, m)| {
                let sig = model::sign(&k.sk, m);
                assert!(model::verify_sig(&k.ak, m, &sig));
                format!(r#"{{"sk":"{}","ak":{},"message":"{}","r8":{},"s":"{}"}}"#, k.sk, pt(&k.ak), dr(m), pt(&sig.r8), dr(&sig.s))
            })
            .collect(),
    );

    // one whole transfer of GENE: 600 + 400 → 700 + 250 + 50, anchored at height 7
    let owners = [model::note_keys(&scalar("spend/in0/sk"), &scalar("spend/in0/nk")), model::note_keys(&scalar("spend/in1/sk"), &scalar("spend/in1/nk"))];
    let in_v = [600u64, 400];
    let in_rho = [field("spend/in0/rho"), field("spend/in1/rho")];
    let mut tree_leaves: Vec<Fr> = (0..3).map(|i| field(&format!("spend/filler/{i}"))).collect();
    let mut index = [0u64; 2];
    for i in 0..2 {
        index[i] = tree_leaves.len() as u64;
        tree_leaves.push(model::note_leaf(&gene, &Fr::from(in_v[i]), &owners[i].npk, &in_rho[i]));
        tree_leaves.push(field(&format!("spend/filler/after{i}")));
    }
    let tree = Tree::new(&tree_leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: owners[i].clone(), v: in_v[i], rho: in_rho[i], index: index[i], path: tree.path(index[i] as usize) });
    let out_v = [700u64, 250, 50];
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: model::note_keys(&scalar(&format!("spend/out{k}/sk")), &scalar(&format!("spend/out{k}/nk"))).npk, v: out_v[k], rho: field(&format!("spend/out{k}/rho")) });
    let out_leaf: [Fr; 3] = std::array::from_fn(|k| model::note_leaf(&gene, &Fr::from(outputs[k].v), &outputs[k].npk, &outputs[k].rho));
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&owners[i].nk, &tree_leaves[index[i] as usize], index[i]));
    let sealed: [wire::Output; 3] = std::array::from_fn(|k| {
        let mut pk_eph = [0u8; 33];
        pk_eph[0] = 0x02;
        pk_eph[1..].copy_from_slice(&bytes(&format!("spend/out{k}/pk_eph"), 32));
        wire::Output { leaf: out_leaf[k], pk_eph, ct: bytes(&format!("spend/out{k}/ct"), 28).try_into().unwrap() }
    });
    let body = wire::transfer_body(7, &nf, &sealed);
    let w = model::build_spend(model::ticker_t(b"GENE").unwrap(), tree.root, &inputs, &outputs, 0, 0, model::body_hash(&body));
    assert_eq!((w.nf, w.out_leaf), (nf, out_leaf));
    assert!(crate::spend::synthesize(&w).is_satisfied(), "the transfer vector must satisfy the circuit");
    let spend_json = format!(
        r#"{{
    "ticker":"GENE","anchorHeight":7,"vPub":"0","tPub":"0",
    "treeLeaves":[{}],
    "inputs":[{}],
    "outputs":[{}],
    "body":"{}",
    "root":"{}","nf":[{}],"outLeaf":[{}],"bodyHash":"{}",
    "signatures":[{}],
    "publics":[{}]
  }}"#,
        tree_leaves.iter().map(|x| q(&dr(x))).collect::<Vec<_>>().join(","),
        (0..2).map(|i| format!(r#"{{"sk":"{}","nk":"{}","v":"{}","rho":"{}","index":"{}"}}"#, owners[i].sk, owners[i].nk, in_v[i], dr(&in_rho[i]), index[i])).collect::<Vec<_>>().join(","),
        outputs.iter().map(|o| format!(r#"{{"npk":"{}","v":"{}","rho":"{}"}}"#, dr(&o.npk), o.v, dr(&o.rho))).collect::<Vec<_>>().join(","),
        hex::encode(&body),
        dr(&w.root),
        nf.iter().map(|x| q(&dr(x))).collect::<Vec<_>>().join(","),
        out_leaf.iter().map(|x| q(&dr(x))).collect::<Vec<_>>().join(","),
        dr(&w.body_hash),
        (0..2).map(|i| format!(r#"{{"r8":{},"s":"{}"}}"#, pt(&w.sig_r8[i]), dr(&w.sig_s[i]))).collect::<Vec<_>>().join(","),
        w.publics().iter().map(|x| q(&dr(x))).collect::<Vec<_>>().join(","),
    );

    format!(
        r#"{{
  "about": "SH-20 spend witness reference vectors, written by circuit/src/vectors.rs (cargo run --release --example vectors -- js/vectors.json). Field elements and scalars are decimal strings, bytes are hex.",
  "constants": {{"l":"{l}","base8":{},"tagLeaf":"{}","nonceTag":"{}"}},
  "poseidon": {poseidon_json},
  "tickers": {tickers_json},
  "keys": {keys_json_all},
  "leaves": {leaves_json},
  "nullifiers": {nullifiers_json},
  "bodies": {bodies_json},
  "signatures": {signatures_json},
  "spend": {spend_json}
}}
"#,
        pt(&model::base8()),
        dr(&model::tag_leaf()),
        model::TAG_NONCE,
    )
}
