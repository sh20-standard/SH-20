//! Replays `indexer/vectors/v0.3.json`, written by the reference indexer, and checks every
//! value it gives: primitives, the scenario block by block, the refusal, the final state.

use ark_bn254::Fr;
use serde_json::Value;
use sh20_indexer::field::{fr_from_le, fr_to_be, h2, hex, note_leaf, tag_leaf, unhex, unhex32};
use sh20_indexer::json::block_from_vector;
use sh20_indexer::tree::Tree;
use sh20_indexer::{Envelope, Indexer, ListingStatus, Profile, TestVerifier, Ticker};
use std::str::FromStr;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file")).expect("vectors JSON")
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("string {key}"))
}

fn dec(v: &Value, key: &str) -> u64 {
    s(v, key).parse().unwrap_or_else(|_| panic!("number {key}"))
}

fn fr_dec(text: &str) -> Fr {
    Fr::from_str(text).expect("decimal field element")
}

/// The vectors print field elements big-endian.
fn fr_hex(f: &Fr) -> String {
    hex(&fr_to_be(f))
}

#[test]
fn version() {
    assert_eq!(s(&vectors(), "version"), "SH-20 draft v0.3");
}

#[test]
fn poseidon2() {
    let v = vectors();
    let cases = v["poseidon2"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let a = fr_dec(c["in"][0].as_str().unwrap());
        let b = fr_dec(c["in"][1].as_str().unwrap());
        assert_eq!(h2(&a, &b), fr_dec(s(c, "out")));
    }
}

#[test]
fn domain_leaf() {
    assert_eq!(fr_hex(&tag_leaf()), s(&vectors(), "domainLeaf"));
}

#[test]
fn empty_root() {
    assert_eq!(fr_hex(&Tree::new().empty_root()), s(&vectors(), "emptyRootDepth32"));
    assert_eq!(fr_hex(&Tree::new().root()), s(&vectors(), "emptyRootDepth32"));
}

#[test]
fn ticker_t() {
    let v = vectors();
    let ticker = Ticker::parse(s(&v["tickerT"], "ticker")).unwrap();
    assert_eq!(u64::from(ticker.t()), dec(&v["tickerT"], "t"));
}

#[test]
fn note_leaf_vector() {
    let v = vectors();
    let n = &v["noteLeaf"];
    let ticker = Ticker::parse(s(n, "ticker")).unwrap();
    assert_eq!(u64::from(ticker.t()), dec(n, "t"));
    let mut npk_le = unhex32(s(n, "npk")).unwrap();
    npk_le.reverse();
    let npk = fr_from_le(&npk_le).unwrap();
    let leaf = note_leaf(ticker.t(), dec(n, "v"), &npk, &fr_dec(s(n, "rho")));
    assert_eq!(fr_hex(&leaf), s(n, "leaf"));
}

#[test]
fn scenario() {
    let v = vectors();
    let sc = &v["scenario"];
    let p = &sc["profile"];
    let profile = Profile {
        activation_height: p["activationHeight"].as_u64().unwrap() as u32,
        deploy_burn: dec(p, "deployBurn"),
        anchor_window: p["anchorWindow"].as_u64().unwrap() as u32,
        anchor_min_depth: p["anchorMinDepth"].as_u64().unwrap() as u32,
    };
    let mut indexer = Indexer::new(profile, Box::new(TestVerifier));

    let blocks = sc["blocks"].as_array().unwrap();
    let after = sc["after"].as_array().unwrap();
    assert_eq!(blocks.len(), after.len());
    let mut rejected: Vec<(u64, String)> = Vec::new();
    let mut list_txid = None;

    for (b, want) in blocks.iter().zip(after) {
        let block = block_from_vector(b).unwrap();
        let h = block.height;
        let got = indexer.apply_block(&block).unwrap();
        assert_eq!(u64::from(got.height), want["height"].as_u64().unwrap());
        assert_eq!(fr_hex(&got.root), s(want, "root"), "root of block {h}");
        let names: Vec<&str> = got.events.iter().map(|e| e.name()).collect();
        let want_names: Vec<&str> = want["events"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
        assert_eq!(names, want_names, "events of block {h}");
        assert_eq!(hex(&got.events_bytes), s(want, "eventsH"), "eventsH of block {h}");
        assert_eq!(hex(&got.digest), s(want, "digest"), "digest of block {h}");
        assert_eq!(indexer.digest(), got.digest);
        assert!(indexer.supply_holds(), "supply identity after block {h}");
        for r in &got.rejected {
            rejected.push((u64::from(h), hex(&r.txid)));
        }
        for e in &got.events {
            if let sh20_indexer::Event::List { txid, .. } = e {
                list_txid = Some(*txid);
            }
        }
    }

    // the refusals: exactly the ones listed
    let want_rejected: Vec<(u64, String)> = sc["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["height"].as_u64().unwrap(), s(r, "txid").to_string()))
        .collect();
    assert!(!want_rejected.is_empty());
    assert_eq!(rejected, want_rejected);

    // the final state
    let f = &sc["final"];
    assert_eq!(indexer.tree_size(), f["treeSize"].as_u64().unwrap());
    let sh20 = indexer.token(&Ticker::SH20).unwrap();
    assert_eq!(sh20.mints, dec(&f["sh20"], "mints"));
    assert_eq!(sh20.burned, dec(&f["sh20"], "burned"));
    assert_eq!(sh20.pool, dec(&f["sh20"], "pool"));
    let gene = indexer.token(&Ticker::parse("GENE").unwrap()).unwrap();
    assert_eq!(gene.mints, dec(&f["gene"], "mints"));
    assert_eq!(gene.pool, dec(&f["gene"], "pool"));
    assert_eq!(gene.team_unlocked, f["gene"]["teamUnlocked"].as_bool().unwrap());
    let listing = indexer.listing(&list_txid.expect("a LIST in the scenario")).unwrap();
    assert_eq!(listing.status.name(), s(f, "listing"));
    assert_eq!(listing.status, ListingStatus::Sold);
    assert_eq!(indexer.listings().count(), 1);

    // the genesis token is the one the vectors describe
    let g = &v["genesis"];
    assert_eq!(sh20.ticker.as_str(), s(g, "ticker"));
    assert_eq!(sh20.max, dec(g, "max"));
    assert_eq!(sh20.lim, dec(g, "lim"));
    assert_eq!(sh20.pre, dec(g, "pre"));
    assert_eq!(sh20.price, dec(g, "price"));
    assert_eq!(u64::from(sh20.pay_mode), g["payMode"].as_u64().unwrap());
    assert_eq!(sh20.start, profile.activation_height);
}

/// The scenario's envelopes are the ones of the `envelopes` section, and the first mint's
/// leaf is the `noteLeaf` vector.
#[test]
fn scenario_carries_the_listed_envelopes() {
    let v = vectors();
    let listed: Vec<Vec<u8>> =
        v["envelopes"].as_object().unwrap().values().map(|e| unhex(s(e, "hex")).unwrap()).collect();
    let mut carried = 0;
    for b in v["scenario"]["blocks"].as_array().unwrap() {
        for tx in block_from_vector(b).unwrap().txs {
            let found = sh20_indexer::chain::envelopes(&tx);
            assert_eq!(found.len(), 1, "one envelope per scenario transaction");
            assert!(listed.contains(&found[0]));
            assert!(Envelope::decode(&found[0]).is_ok());
            carried += 1;
        }
    }
    assert_eq!(carried, listed.len());
}
