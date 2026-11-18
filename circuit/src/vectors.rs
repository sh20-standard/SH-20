//! Reference vectors of what a wallet computes: ticker ids, note keys and `npk`, note leaves,
//! nullifiers, body hashes, EdDSA-Poseidon signatures; and of docs/SPEC-NOTES.md: wallet keys,
//! addresses, sealed outputs, public notes, and one whole transfer between three wallets.
//! Everything is produced by the models the circuit constrains (`model`, `notes`), from fixed
//! seeds, so the file is the same on every run.
//!
//!   cargo run --release --example vectors -- js/vectors.json
//!
//! `circuit/js` reproduces every value (its tests read the file), and `tests/vectors.rs` checks that
//! the file in the repository is the one this module writes.

use crate::model::{self, InputNote, NoteKeys, OutputNote, Pt, Tree, TREE_DEPTH};
use crate::notes::{self, WalletKeys};
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

    // ── docs/SPEC-NOTES.md ──

    // three wallets, each from a 64-byte BIP39 seed
    let names = ["payer", "recipient", "relayer"];
    let seeds: Vec<Vec<u8>> = names.iter().map(|n| bytes(&format!("wallet/{n}/bip39-seed"), 64)).collect();
    let masters: Vec<[u8; 32]> = seeds.iter().map(|seed| notes::master_secret(seed)).collect();
    let wallets: Vec<WalletKeys> = masters.iter().map(|m| notes::wallet_keys(m).expect("keys")).collect();
    let wallets_json = list(
        (0..3)
            .map(|i| {
                let (w, a) = (&wallets[i], &wallets[i].address);
                format!(
                    r#"{{"name":"{}","bip39Seed":"{}","m":"{}","ask":"{}","nsk":"{}","ivk":"{}","IVK":"{}","A":{},"N":{},"packA":"{}","packN":"{}","address":"{}","addressTest":"{}"}}"#,
                    names[i],
                    hex::encode(&seeds[i]),
                    hex::encode(masters[i]),
                    w.ask,
                    w.nsk,
                    hex::encode(w.ivk),
                    hex::encode(a.ivk_pub),
                    pt(&a.a),
                    pt(&a.n),
                    hex::encode(notes::pack_point(&a.a)),
                    hex::encode(notes::pack_point(&a.n)),
                    notes::encode_address("sh20", a),
                    notes::encode_address("tsh20", a),
                )
            })
            .collect(),
    );

    // addresses a wallet must refuse, each with one defect
    let good = wallets[1].address;
    let raw = |version: u8, ivk: [u8; 32], a: [u8; 32], n: [u8; 32]| [&[version][..], &ivk, &a, &n].concat();
    let (pa, pn) = (notes::pack_point(&good.a), notes::pack_point(&good.n));
    let valid = notes::encode_address("sh20", &good);
    let mut wrong_checksum = valid.clone().into_bytes();
    let last = wrong_checksum.len() - 1;
    wrong_checksum[last] = if wrong_checksum[last] == b'q' { b'p' } else { b'q' };
    let mut mixed_case = valid.clone().into_bytes();
    let at = mixed_case.iter().rposition(|c| c.is_ascii_lowercase()).unwrap();
    mixed_case[at] = mixed_case[at].to_ascii_uppercase();
    // the point of order 2, the identity, a y that is not a field element, and a y with no x
    let order2 = notes::pack_point(&[Fr::zero(), -Fr::from(1u64)]);
    let identity = notes::pack_point(&model::identity());
    let torsion = notes::pack_point(&model::add(&good.a, &[Fr::zero(), -Fr::from(1u64)]));
    let not_reduced = [0xffu8; 32].map(|b| b).iter().enumerate().map(|(i, b)| if i == 31 { 0x7f } else { *b }).collect::<Vec<u8>>();
    let no_x = (2u64..).map(|y| notes::fr_le(&Fr::from(y))).find(|b| notes::unpack_point(b).is_none()).unwrap();
    let mut negative_zero = identity;
    negative_zero[31] |= 0x80;
    let invalid: Vec<(String, &str)> = vec![
        (String::from_utf8(wrong_checksum).unwrap(), "wrong checksum"),
        (String::from_utf8(mixed_case).unwrap(), "mixed case"),
        (notes::encode_address("bc", &good), "another network"),
        (notes::bech32m_encode("sh20", &raw(1, good.ivk_pub, pa, pn)), "unknown version"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, pa, pn)[..96]), "wrong length"),
        (notes::bech32m_encode("sh20", &raw(0, [0u8; 32], pa, pn)), "IVK is a low-order point (zero)"),
        (notes::bech32m_encode("sh20", &raw(0, { let mut one = [0u8; 32]; one[0] = 1; one }, pa, pn)), "IVK is a low-order point (one)"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, identity, pn)), "A is the identity"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, order2, pn)), "A has order 2"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, torsion, pn)), "A is outside the prime-order subgroup"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, pa, not_reduced.clone().try_into().unwrap())), "N: y is not below r"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, pa, no_x)), "N is not on the curve"),
        (notes::bech32m_encode("sh20", &raw(0, good.ivk_pub, negative_zero, pn)), "A: second encoding of x = 0"),
    ];
    for (addr, why) in &invalid {
        assert!(notes::decode_address("sh20", addr).is_err(), "accepted: {why}");
    }
    assert_eq!(notes::decode_address("sh20", &valid), Ok(good));
    let invalid_json = list(invalid.iter().map(|(addr, why)| format!(r#"{{"address":"{addr}","why":"{why}"}}"#)).collect());

    // sealed outputs, each with a fixed ephemeral key
    let seal_cases: Vec<(usize, &[u8; 4], u64)> = vec![(1, b"GENE", 1000), (1, b"GENE", 0), (2, b"ZZ99", u64::MAX), (0, b"0000", 1)];
    let sealed_json = list(
        seal_cases
            .iter()
            .enumerate()
            .map(|(k, (to, ticker, v))| {
                let e: [u8; 32] = bytes(&format!("sealed/{k}/e"), 32).try_into().unwrap();
                let (out, sec, npk) = notes::seal(&wallets[*to].address, ticker, *v, &e).expect("seal");
                let opened = notes::scan(&wallets[*to].ivk, &wallets[*to].address, &out).expect("the recipient opens it");
                assert_eq!((opened.v, opened.ticker, &opened.secrets), (*v, **ticker, &sec));
                for other in (0..3).filter(|w| w != to) {
                    assert!(notes::scan(&wallets[other].ivk, &wallets[other].address, &out).is_none());
                }
                format!(
                    r#"{{"to":"{}","ticker":"{}","v":"{v}","e":"{}","pkEph":"{}","tauA":"{}","tauN":"{}","rho":"{}","npk":"{}","leaf":"{}","ct":"{}"}}"#,
                    names[*to],
                    std::str::from_utf8(*ticker).unwrap(),
                    hex::encode(e),
                    hex::encode(out.pk_eph),
                    sec.tau_a,
                    sec.tau_n,
                    dr(&sec.rho),
                    dr(&npk),
                    dr(&out.leaf),
                    hex::encode(out.ct),
                )
            })
            .collect(),
    );

    // public notes of the payer
    let public_json = list(
        [0u32, 1, 2, 49]
            .iter()
            .map(|i| {
                let s_i = notes::self_secret(&wallets[0].ivk, *i);
                let (npk, sec) = notes::public_opening(&wallets[0].ivk, &wallets[0].address, *i).expect("opening");
                assert!(sec.rho.is_zero(), "public notes have rho = 0");
                let leaf = model::note_leaf(&gene, &Fr::from(1000u64), &npk, &sec.rho);
                format!(r#"{{"wallet":"payer","i":{i},"s":"{}","tauA":"{}","tauN":"{}","npk":"{}","leafOf1000Gene":"{}"}}"#, hex::encode(s_i), sec.tau_a, sec.tau_n, dr(&npk), dr(&leaf))
            })
            .collect(),
    );

    // one whole transfer of GENE, anchored at height 7: the payer spends its public notes 0 and 1
    // (600 and 400) and pays 700 to the recipient, 250 back to itself and 50 to the relayer
    let ticker = b"GENE";
    let payer = &wallets[0];
    let in_v = [600u64, 400];
    let opened: Vec<_> = (0..2).map(|i| notes::public_opening(&payer.ivk, &payer.address, i).expect("opening")).collect();
    let owners: Vec<NoteKeys> = opened.iter().map(|o| notes::spend_keys(payer, &o.1).expect("keys")).collect();
    let mut tree_leaves: Vec<Fr> = (0..3).map(|i| field(&format!("spend/filler/{i}"))).collect();
    let mut index = [0u64; 2];
    for i in 0..2 {
        index[i] = tree_leaves.len() as u64;
        tree_leaves.push(model::note_leaf(&gene, &Fr::from(in_v[i]), &opened[i].0, &opened[i].1.rho));
        tree_leaves.push(field(&format!("spend/filler/after{i}")));
    }
    let tree = Tree::new(&tree_leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: owners[i].clone(), v: in_v[i], rho: opened[i].1.rho, index: index[i], path: tree.path(index[i] as usize) });
    let pay: [(usize, u64); 3] = [(1, 700), (0, 250), (2, 50)];
    let es: Vec<[u8; 32]> = (0..3).map(|k| bytes(&format!("spend/out{k}/e"), 32).try_into().unwrap()).collect();
    let sealed: Vec<_> = (0..3).map(|k| notes::seal(&wallets[pay[k].0].address, ticker, pay[k].1, &es[k]).expect("seal")).collect();
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: sealed[k].2, v: pay[k].1, rho: sealed[k].1.rho });
    let out_leaf: [Fr; 3] = std::array::from_fn(|k| sealed[k].0.leaf);
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&owners[i].nk, &tree_leaves[index[i] as usize], index[i]));
    let body = wire::transfer_body(7, &nf, &std::array::from_fn(|k| sealed[k].0.into()));
    let w = model::build_spend(model::ticker_t(ticker).unwrap(), tree.root, &inputs, &outputs, 0, 0, model::body_hash(&body));
    assert_eq!((w.nf, w.out_leaf), (nf, out_leaf));
    assert!(crate::spend::synthesize(&w).is_satisfied(), "the transfer vector must satisfy the circuit");
    // each wallet finds exactly its own output
    for (k, (to, v)) in pay.iter().enumerate() {
        for (wi, wallet) in wallets.iter().enumerate() {
            let found = notes::scan(&wallet.ivk, &wallet.address, &sealed[k].0).map(|o| o.v);
            assert_eq!(found, (wi == *to).then_some(*v));
        }
    }
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
        (0..2).map(|i| format!(r#"{{"wallet":"payer","publicNote":{i},"sk":"{}","nk":"{}","v":"{}","rho":"{}","index":"{}"}}"#, owners[i].sk, owners[i].nk, in_v[i], dr(&opened[i].1.rho), index[i])).collect::<Vec<_>>().join(","),
        (0..3)
            .map(|k| format!(r#"{{"to":"{}","v":"{}","e":"{}","npk":"{}","rho":"{}","pkEph":"{}","ct":"{}"}}"#, names[pay[k].0], pay[k].1, hex::encode(es[k]), dr(&outputs[k].npk), dr(&outputs[k].rho), hex::encode(sealed[k].0.pk_eph), hex::encode(sealed[k].0.ct)))
            .collect::<Vec<_>>()
            .join(","),
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
  "about": "SH-20 wallet reference vectors (docs/SPEC-WIRE.md §4, docs/SPEC-NOTES.md), written by circuit/src/vectors.rs (cargo run --release --example vectors -- js/vectors.json). Field elements and scalars are decimal strings, bytes are hex.",
  "constants": {{"l":"{l}","base8":{},"tagLeaf":"{}","nonceTag":"{}"}},
  "poseidon": {poseidon_json},
  "tickers": {tickers_json},
  "keys": {keys_json_all},
  "leaves": {leaves_json},
  "nullifiers": {nullifiers_json},
  "bodies": {bodies_json},
  "signatures": {signatures_json},
  "wallets": {wallets_json},
  "invalidAddresses": {invalid_json},
  "sealed": {sealed_json},
  "publicNotes": {public_json},
  "spend": {spend_json}
}}
"#,
        pt(&model::base8()),
        dr(&model::tag_leaf()),
        model::TAG_NONCE,
    )
}
