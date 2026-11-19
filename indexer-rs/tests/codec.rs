//! The encoding of every envelope and of the note leaf, against the vectors and the sizes of
//! SPEC-WIRE §4, and what the strict decoder refuses.

mod common;

use common::*;
use serde_json::Value;
use sh20_indexer::envelope::{body_hash_of, DecodeError, Deploy, Envelope, Ticker, HEADER_LEN, PROOF_LEN, SPEND_LEN};
use sh20_indexer::field::{body_hash, fr_from_le, fr_to_be, fr_to_le, hex, public_leaf, unhex, unhex32};
use sh20_indexer::verifier::TestVerifier;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn vector_envelope(v: &Value, name: &str) -> (Vec<u8>, Envelope) {
    let e = &v["envelopes"][name];
    let bytes = unhex(e["hex"].as_str().unwrap()).unwrap();
    assert_eq!(bytes.len() as u64, e["bytes"].as_u64().unwrap(), "{name}: length");
    let env = Envelope::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(env.encode(), bytes, "{name}: re-serialising gives the same bytes");
    (bytes, env)
}

fn rejected(bytes: &[u8]) -> bool {
    matches!(Envelope::decode(bytes), Err(DecodeError::Rejected(_)))
}

/// 2^256 − 1 is not a field element; neither is `r` itself.
const R_LE: &str = "010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430";

#[test]
fn every_vector_envelope_round_trips() {
    let v = vectors();
    let names: Vec<&String> = v["envelopes"].as_object().unwrap().keys().collect();
    assert_eq!(names.len(), 22);
    for name in names {
        vector_envelope(&v, name);
    }
}

#[test]
fn vector_envelopes_decode_to_the_expected_fields() {
    let v = vectors();
    let valid_proof = TestVerifier::valid_proof();

    let (_, env) = vector_envelope(&v, "mintGenesis");
    let Envelope::Mint { ticker, opening, k } = env else { panic!() };
    assert_eq!((ticker, k), (Ticker::SH20, None));
    // its opening is the npk of the noteLeaf vector, little-endian on the wire
    let mut npk = unhex32(v["noteLeaf"]["npk"].as_str().unwrap()).unwrap();
    npk.reverse();
    assert_eq!(opening, npk);

    let (_, env) = vector_envelope(&v, "mintGenesisBatch");
    assert!(matches!(env, Envelope::Mint { ticker: Ticker::SH20, k: Some(2), .. }));
    let (_, env) = vector_envelope(&v, "mintPaid");
    assert!(matches!(env, Envelope::Mint { k: None, ticker, .. } if ticker == tk("GENE")));
    let (_, env) = vector_envelope(&v, "mintBatch");
    assert!(matches!(env, Envelope::Mint { k: Some(3), ticker, .. } if ticker == tk("GENE")));

    let (bytes, env) = vector_envelope(&v, "transfer");
    let Envelope::Transfer { spend } = env else { panic!() };
    assert_eq!(bytes.len(), HEADER_LEN + SPEND_LEN);
    assert_eq!(spend.anchor_height, 1);
    assert_eq!(spend.proof, valid_proof);

    let (bytes, env) = vector_envelope(&v, "list");
    let Envelope::List { ticker, amount, price, lock_vout, lock_key, pay_script, spend } = env else { panic!() };
    assert_eq!((ticker, amount, price, lock_vout), (Ticker::SH20, 1000, 5000, 0));
    assert_eq!(hex(&lock_key), "abdc60eb9a25f0d97db71b0fc34b8f9fdb6bed43d241e4b2dffad16bf8d07311");
    assert_eq!(hex(&pay_script), "00149350872d712a127c494d7dc35e46b0bc9e62e288");
    assert_eq!(bytes.len(), 884 + pay_script.len());
    assert_eq!(spend.anchor_height, 1);

    let (bytes, env) = vector_envelope(&v, "take");
    assert!(matches!(env, Envelope::Take { .. }));
    assert_eq!(bytes.len(), 38);

    let (bytes, env) = vector_envelope(&v, "deployWithTeam");
    let Envelope::Deploy(d) = env else { panic!() };
    assert_eq!(bytes.len(), 88 + SPEND_LEN);
    assert_eq!(d.ticker, tk("GENE"));
    assert_eq!((d.max, d.lim, d.pre), (21_000_000, 1_000, 1_000_000));
    assert_eq!((d.start, d.end, d.unlock), (5, 0, 6));
    assert_eq!((d.price, d.pay_mode), (1_000, 1));
    assert!(d.pay_script.is_empty());
    assert!(d.team_opening.is_some());
    assert_eq!(d.spend.as_ref().unwrap().anchor_height, 3);

    let (bytes, env) = vector_envelope(&v, "deployNoTeam");
    let Envelope::Deploy(d) = env else { panic!() };
    assert_eq!(bytes.len(), 88 - 32 + SPEND_LEN);
    assert_eq!(d.ticker, tk("SEC2"));
    assert_eq!((d.pre, d.start, d.unlock), (0, 7, 7));
    assert!(d.team_opening.is_none());

    let (bytes, env) = vector_envelope(&v, "burn");
    let Envelope::Burn { ticker, v_pub, spend } = env else { panic!() };
    assert_eq!(bytes.len(), 842);
    assert_eq!((ticker, v_pub, spend.anchor_height), (Ticker::SH20, 10, 5));

    let (_, env) = vector_envelope(&v, "overBurn");
    assert!(matches!(env, Envelope::Burn { v_pub: 991, .. }));
}

/// The sizes of the table in §4, for envelopes built here (CLAIM is not in the vectors).
#[test]
fn sizes_of_the_table() {
    let size = |e: Envelope| {
        let bytes = e.encode();
        assert_eq!(Envelope::decode(&bytes), Ok(e));
        bytes.len()
    };
    let mut d = deploy("ABCD", 10);
    assert_eq!(size(Envelope::Deploy(d.clone())), 56);
    d.pre = 1_000;
    d.team_opening = Some(fe(1));
    assert_eq!(size(Envelope::Deploy(d.clone())), 88);
    d.spend = Some(spend(3, 1));
    assert_eq!(size(Envelope::Deploy(d.clone())), 88 + 824);
    d.pay_mode = 2;
    d.price = 5;
    d.pay_script = vec![0x51; 34];
    assert_eq!(size(Envelope::Deploy(d)), 88 + 824 + 34);

    assert_eq!(size(Envelope::Mint { ticker: tk("ABCD"), opening: fe(2), k: None }), 42);
    assert_eq!(size(Envelope::Mint { ticker: tk("ABCD"), opening: fe(2), k: Some(10) }), 43);
    assert_eq!(size(Envelope::Transfer { spend: spend(1, 2) }), 830);
    assert_eq!(size(Envelope::Burn { ticker: tk("ABCD"), v_pub: 7, spend: spend(1, 3) }), 842);
    let list = |ps: usize| Envelope::List {
        ticker: tk("ABCD"),
        amount: 1,
        price: 1,
        lock_vout: 255,
        lock_key: [0xff; 32],
        pay_script: vec![0xab; ps],
        spend: spend(1, 4),
    };
    assert_eq!(size(list(1)), 884 + 1);
    assert_eq!(size(list(34)), 884 + 34);
    assert_eq!(size(Envelope::Take { opening: fe(5) }), 38);
    assert_eq!(size(Envelope::Claim { list_txid: [0xff; 32], opening: fe(6), sig: [0xff; 64] }), 134);
    assert_eq!(SPEND_LEN, 824);
}

#[test]
fn claim_layout() {
    let list_txid = txid(1);
    let opening = fe(2);
    let sig = [0x5a; 64];
    let bytes = Envelope::Claim { list_txid, opening, sig }.encode();
    assert_eq!(&bytes[..6], b"SH20\x00\x07");
    assert_eq!(&bytes[6..38], &list_txid);
    assert_eq!(&bytes[38..70], &opening);
    assert_eq!(&bytes[70..], &sig);
}

/// `ticker(4) amount(8) price(8) lockVout(1) lockKey(32) psLen(1) payScript spend`: the lock key
/// sits before the proof, so it is inside `body` and the spend's signature covers it.
#[test]
fn list_layout() {
    let lock_key = fe(7);
    let s = spend(9, 1);
    let env = Envelope::List {
        ticker: tk("ABCD"),
        amount: 0x0102_0304_0506_0708,
        price: 0x1112_1314_1516_1718,
        lock_vout: 2,
        lock_key,
        pay_script: vec![0xa1, 0xa2, 0xa3],
        spend: s.clone(),
    };
    let bytes = env.encode();
    assert_eq!(&bytes[..6], b"SH20\x00\x05");
    assert_eq!(&bytes[6..10], b"ABCD");
    assert_eq!(bytes[10..18], 0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(bytes[18..26], 0x1112_1314_1516_1718u64.to_le_bytes());
    assert_eq!(bytes[26], 2);
    assert_eq!(bytes[27..59], lock_key);
    assert_eq!(bytes[59], 3);
    assert_eq!(bytes[60..63], [0xa1, 0xa2, 0xa3]);
    assert_eq!(bytes[63..67], 9u32.to_le_bytes());
    assert_eq!(bytes[67..99], s.nf[0]);
    assert_eq!(bytes.len(), 884 + 3);
    assert_eq!(Envelope::decode(&bytes), Ok(env));

    // another lock key is another body, hence another bodyHash: the signature does not carry over
    let mut other = bytes.clone();
    other[27] ^= 1;
    assert_ne!(body_hash_of(&other), body_hash_of(&bytes));
    // the key is opaque to the decoder: any 32 bytes
    other[27..59].copy_from_slice(&[0xff; 32]);
    assert!(Envelope::decode(&other).is_ok());
    // a LIST of the earlier layout (no lockKey) is 32 bytes short
    let mut old = bytes[..27].to_vec();
    old.extend_from_slice(&bytes[59..]);
    assert!(rejected(&old));
}

#[test]
fn note_leaf_of_the_first_mint() {
    let v = vectors();
    let n = &v["noteLeaf"];
    let (_, env) = vector_envelope(&v, "mintGenesis");
    let Envelope::Mint { ticker, opening, .. } = env else { panic!() };
    let leaf = public_leaf(ticker.t(), 1000, &fr_from_le(&opening).unwrap());
    assert_eq!(hex(&fr_to_be(&leaf)), n["leaf"].as_str().unwrap());
    // on the wire a leaf is the same value, little-endian
    let mut le = fr_to_le(&leaf);
    le.reverse();
    assert_eq!(hex(&le), n["leaf"].as_str().unwrap());
    // any change to t, v or npk changes the leaf
    assert_ne!(public_leaf(ticker.t() + 1, 1000, &fr_from_le(&opening).unwrap()), leaf);
    assert_ne!(public_leaf(ticker.t(), 1001, &fr_from_le(&opening).unwrap()), leaf);
    assert_ne!(public_leaf(ticker.t(), 1000, &fr_from_le(&fe(9)).unwrap()), leaf);
}

#[test]
fn ticker_rules() {
    assert_eq!(tk("GENE").t(), 0x47454e45);
    assert_eq!(tk("0000").t(), 0x30303030);
    for bad in ["gene", "GEN ", "GEN-", "GÉN", "GEN", "GENES", "GE\0E", "ABC@", "ABC[", "AB/C", "AB:C"] {
        assert!(Ticker::parse(bad).is_none(), "{bad:?}");
    }
    for bad in [*b"abcd", *b"AB d", [0, 0, 0, 0], *b"AB\xffD"] {
        let mut bytes = mint("ABCD", 1, None);
        bytes[6..10].copy_from_slice(&bad);
        assert!(rejected(&bytes));
        let mut bytes = Envelope::Burn { ticker: tk("ABCD"), v_pub: 1, spend: spend(1, 1) }.encode();
        bytes[6..10].copy_from_slice(&bad);
        assert!(rejected(&bytes));
    }
}

#[test]
fn header_rules() {
    let good = mint("ABCD", 1, None);
    assert!(Envelope::decode(&good).is_ok());
    assert_eq!(Envelope::decode(b"SH21\x00\x02"), Err(DecodeError::NotSh20));
    assert_eq!(Envelope::decode(b"SH2"), Err(DecodeError::NotSh20));
    // unknown version: ignored
    let mut other = good.clone();
    other[4] = 1;
    assert_eq!(Envelope::decode(&other), Err(DecodeError::UnknownVersion(1)));
    assert_eq!(Envelope::decode(b"SH20\x07"), Err(DecodeError::UnknownVersion(7)));
    // unknown type: rejected, the reserved ones included
    for t in [0x00u8, 0x08, 0x0f, 0x10, 0x80, 0xff] {
        let mut other = good.clone();
        other[5] = t;
        assert!(rejected(&other), "type {t:#x}");
    }
    assert!(rejected(b"SH20"));
    assert!(rejected(b"SH20\x00"));
    assert!(rejected(b"SH20\x00\x02"));
}

#[test]
fn trailing_and_missing_bytes() {
    let all: Vec<Vec<u8>> = vec![
        mint("ABCD", 1, None),
        mint("ABCD", 1, Some(2)),
        transfer(1, 1),
        Envelope::Burn { ticker: tk("ABCD"), v_pub: 1, spend: spend(1, 1) }.encode(),
        Envelope::List {
            ticker: tk("ABCD"),
            amount: 1,
            price: 1,
            lock_vout: 0,
            lock_key: [3; 32],
            pay_script: vec![1, 2],
            spend: spend(1, 1),
        }
        .encode(),
        Envelope::Take { opening: fe(1) }.encode(),
        Envelope::Claim { list_txid: [1; 32], opening: fe(1), sig: [2; 64] }.encode(),
        Envelope::Deploy(deploy("ABCD", 5)).encode(),
        Envelope::Deploy(Deploy { spend: Some(spend(1, 1)), ..deploy("ABCD", 5) }).encode(),
    ];
    for bytes in all {
        assert!(Envelope::decode(&bytes).is_ok());
        let mut longer = bytes.clone();
        longer.push(0);
        // one more byte on a single MINT is a `k` of 0: rejected all the same
        assert!(rejected(&longer), "trailing byte on type {}", bytes[5]);
        // every strict prefix is refused, except the single MINT inside a batch MINT
        for cut in HEADER_LEN..bytes.len() {
            let is_single_mint = bytes[5] == 2 && bytes.len() == 43 && cut == 42;
            let is_deploy_without_spend = bytes[5] == 1 && cut == 56;
            if !is_single_mint && !is_deploy_without_spend {
                assert!(rejected(&bytes[..cut]), "type {} cut at {cut}", bytes[5]);
            }
        }
    }
}

#[test]
fn mint_count() {
    for k in 2..=10u8 {
        assert!(Envelope::decode(&mint("ABCD", 1, Some(k))).is_ok());
    }
    for k in [0u8, 1, 11, 255] {
        let mut bytes = mint("ABCD", 1, None);
        bytes.push(k);
        assert!(rejected(&bytes), "k = {k}");
    }
}

#[test]
fn field_elements_must_be_below_r() {
    let r = unhex32(R_LE).unwrap();
    assert!(fr_from_le(&r).is_none());
    let mut r_minus_1 = r;
    r_minus_1[0] -= 1;
    assert!(fr_from_le(&r_minus_1).is_some());

    for bad in [r, [0xff; 32]] {
        // openings
        let mut b = mint("ABCD", 1, None);
        b[10..42].copy_from_slice(&bad);
        assert!(rejected(&b));
        let mut b = Envelope::Take { opening: fe(1) }.encode();
        b[6..38].copy_from_slice(&bad);
        assert!(rejected(&b));
        let mut b = Envelope::Claim { list_txid: [1; 32], opening: fe(1), sig: [2; 64] }.encode();
        b[38..70].copy_from_slice(&bad);
        assert!(rejected(&b));
        let mut b = Envelope::Deploy(Deploy { pre: 1000, team_opening: Some(fe(1)), ..deploy("ABCD", 5) }).encode();
        let n = b.len();
        b[n - 32..].copy_from_slice(&bad);
        assert!(rejected(&b));
        // nullifiers and output leaves of a spend
        for at in [6 + 4, 6 + 36, 6 + 68, 6 + 68 + 92, 6 + 68 + 184] {
            let mut b = transfer(1, 1);
            b[at..at + 32].copy_from_slice(&bad);
            assert!(rejected(&b), "field at {at}");
        }
    }
    // the largest element is accepted, and so is any pk_eph, ct, listTxid or proof
    let mut b = mint("ABCD", 1, None);
    b[10..42].copy_from_slice(&r_minus_1);
    assert!(Envelope::decode(&b).is_ok());
    let mut b = transfer(1, 1);
    for at in [6 + 68 + 32, 6 + 68 + 92 + 32, 6 + 68 + 184 + 32] {
        b[at..at + 60].copy_from_slice(&[0xff; 60]);
    }
    let n = b.len();
    b[n - PROOF_LEN..].copy_from_slice(&[0xff; PROOF_LEN]);
    assert!(Envelope::decode(&b).is_ok());
    assert!(
        Envelope::decode(&Envelope::Claim { list_txid: [0xff; 32], opening: fe(1), sig: [0xff; 64] }.encode()).is_ok()
    );
}

#[test]
fn deploy_layout_rules() {
    let ok = |d: &Deploy| Envelope::decode(&Envelope::Deploy(d.clone()).encode()).is_ok();
    let base = deploy("ABCD", 5);
    assert!(ok(&base));
    // payMode
    assert!(!ok(&Deploy { pay_mode: 3, ..base.clone() }));
    assert!(!ok(&Deploy { pay_mode: 255, ..base.clone() }));
    // payScript: 1 to 34 bytes, required with payMode 2 and absent otherwise
    assert!(ok(&Deploy { pay_mode: 2, pay_script: vec![1; 34], ..base.clone() }));
    assert!(ok(&Deploy { pay_mode: 2, pay_script: vec![1], ..base.clone() }));
    assert!(!ok(&Deploy { pay_mode: 2, pay_script: Vec::new(), ..base.clone() }));
    assert!(!ok(&Deploy { pay_mode: 2, pay_script: vec![1; 35], ..base.clone() }));
    assert!(!ok(&Deploy { pay_mode: 1, pay_script: vec![1; 22], ..base.clone() }));
    assert!(!ok(&Deploy { pay_mode: 0, pay_script: vec![1], ..base.clone() }));
    // a team opening exactly when pre > 0: these byte strings read as something else and fail
    let no_opening = Envelope::Deploy(Deploy { pre: 1000, team_opening: None, ..base.clone() }).encode();
    assert!(rejected(&no_opening));
    let stray_opening = Envelope::Deploy(Deploy { pre: 0, team_opening: Some(fe(1)), ..base.clone() }).encode();
    assert!(rejected(&stray_opening));
    // a LIST payScript is bounded the same way
    let list = |n: usize| {
        Envelope::List {
            ticker: tk("ABCD"),
            amount: 1,
            price: 1,
            lock_vout: 0,
            lock_key: [3; 32],
            pay_script: vec![1; n],
            spend: spend(1, 1),
        }
        .encode()
    };
    assert!(Envelope::decode(&list(34)).is_ok());
    assert!(Envelope::decode(&list(1)).is_ok());
    assert!(rejected(&list(0)));
    assert!(rejected(&list(35)));
}

#[test]
fn body_is_everything_before_the_proof() {
    for bytes in [
        transfer(1, 1),
        Envelope::Burn { ticker: tk("ABCD"), v_pub: 1, spend: spend(1, 1) }.encode(),
        Envelope::Deploy(Deploy { spend: Some(spend(1, 1)), ..deploy("ABCD", 5) }).encode(),
    ] {
        let body = &bytes[..bytes.len() - PROOF_LEN];
        assert_eq!(body_hash_of(&bytes), body_hash(body));
        assert_eq!(&bytes[bytes.len() - PROOF_LEN..], TestVerifier::valid_proof().as_slice());
        // the proof is outside the body, every byte before it is inside
        let mut other = bytes.clone();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(body_hash_of(&other), body_hash_of(&bytes));
        let mut other = bytes.clone();
        other[5] ^= 1;
        assert_ne!(body_hash_of(&other), body_hash_of(&bytes));
        let at = bytes.len() - PROOF_LEN - 1;
        let mut other = bytes.clone();
        other[at] ^= 1;
        assert_ne!(body_hash_of(&other), body_hash_of(&bytes));
    }
}
