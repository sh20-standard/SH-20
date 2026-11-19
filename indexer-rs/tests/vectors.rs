//! Replays `indexer/vectors/v0.3.json`, written by the reference indexer, and checks every
//! value it gives: primitives, the scenario block by block, the refusal, the final state.

use ark_bn254::Fr;
use serde_json::Value;
use sh20_indexer::chain::{counted_envelopes, envelopes, Carrier};
use sh20_indexer::envelope::body_hash_of;
use sh20_indexer::field::{fr_from_le, fr_to_be, h2, hex, note_leaf, tag_leaf, unhex, unhex32};
use sh20_indexer::json::{block_from_vector, tx_from_vector};
use sh20_indexer::state::bip340_verify;
use sh20_indexer::tree::Tree;
use sh20_indexer::verifier::{PublicInputs, SpendVerifier};
use sh20_indexer::{Envelope, Indexer, ListingStatus, Profile, TestVerifier, Ticker};
use std::cell::RefCell;
use std::rc::Rc;
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

/// The vectors' test verifier, which also keeps the inputs of every call it gets.
struct Recording(Rc<RefCell<Vec<PublicInputs>>>);

impl SpendVerifier for Recording {
    fn verify_spend(&self, inputs: &PublicInputs, proof: &[u8]) -> bool {
        self.0.borrow_mut().push(inputs.clone());
        TestVerifier.verify_spend(inputs, proof)
    }
}

fn scenario_profile(sc: &Value) -> Profile {
    let p = &sc["profile"];
    Profile {
        activation_height: p["activationHeight"].as_u64().unwrap() as u32,
        deploy_burn: dec(p, "deployBurn"),
        anchor_window: p["anchorWindow"].as_u64().unwrap() as u32,
        anchor_min_depth: p["anchorMinDepth"].as_u64().unwrap() as u32,
        deploy_maturity: p["deployMaturity"].as_u64().unwrap() as u32,
    }
}

/// The whole scenario: for every block the root, the events, `eventsH` and the digest; then the
/// refusals, the inputs of every verifier call, and the final state.
#[test]
fn scenario() {
    let v = vectors();
    let sc = &v["scenario"];
    let profile = scenario_profile(sc);
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(profile, Box::new(Recording(asked.clone())));

    let blocks = sc["blocks"].as_array().unwrap();
    let after = sc["after"].as_array().unwrap();
    assert_eq!(blocks.len(), 13);
    assert_eq!(blocks.len(), after.len());
    let mut rejected: Vec<(u64, String)> = Vec::new();
    let mut accepted_spends = 0;
    // (height, the nine inputs) of every call the verifier got, in order
    let mut calls: Vec<(u64, Vec<String>)> = Vec::new();

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
        accepted_spends += got
            .events
            .iter()
            .filter(|e| {
                use sh20_indexer::Event::*;
                matches!(e, Transfer { .. } | Burn { .. } | List { .. } | Deploy { burn: Some(_), .. })
            })
            .count();
        for inputs in asked.borrow_mut().drain(..) {
            calls.push((u64::from(h), inputs.as_fields().iter().map(fr_hex).collect()));
        }
    }

    // the refusals: exactly the ones listed
    let want_rejected: Vec<(u64, String)> = sc["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["height"].as_u64().unwrap(), s(r, "txid").to_string()))
        .collect();
    assert_eq!(want_rejected.len(), 7);
    assert_eq!(rejected, want_rejected);

    // the verifier: the same calls, in the same order, each with the same nine inputs
    let want_calls = sc["verifierCalls"].as_array().unwrap();
    assert_eq!(want_calls.len(), 11);
    assert_eq!(calls.len(), want_calls.len(), "number of verifier calls");
    // the proof is checked last and every proof of the scenario is the valid one: the calls
    // are the accepted spends, no more
    assert_eq!(calls.len(), accepted_spends);
    for ((height, inputs), want) in calls.iter().zip(want_calls) {
        let want_inputs: Vec<&str> =
            want["publicInputs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(want_inputs.len(), 9);
        assert_eq!(*height, want["height"].as_u64().unwrap(), "height of the call for {}", s(want, "txid"));
        assert_eq!(inputs, &want_inputs, "inputs of the call for {}", s(want, "txid"));
        // the call belongs to the transaction the vectors name: its spend has this nf0
        let block = blocks.iter().find(|b| b["height"].as_u64() == Some(*height)).unwrap();
        let tx = block_from_vector(block).unwrap().txs.into_iter().find(|t| hex(&t.txid) == s(want, "txid")).unwrap();
        let env = Envelope::decode(&envelopes(&tx)[0]).unwrap();
        let mut nf0 = env.spend().unwrap().nf[0];
        nf0.reverse();
        assert_eq!(hex(&nf0), want_inputs[1]);
    }

    // the digest of the last block, as announced with the maturity rule
    assert!(hex(&indexer.digest()).starts_with("58ee8a6c"));
    assert_eq!(hex(&indexer.digest()), s(after.last().unwrap(), "digest"));

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
    let mut listings: Vec<(String, &str)> = indexer.listings().map(|(id, l)| (hex(id), l.status.name())).collect();
    listings.sort();
    let mut want_listings: Vec<(String, &str)> =
        f["listings"].as_object().unwrap().iter().map(|(id, st)| (id.clone(), st.as_str().unwrap())).collect();
    want_listings.sort();
    assert_eq!(want_listings.len(), 7);
    assert_eq!(listings, want_listings);
    for (status, count) in [
        (ListingStatus::Sold, 2),
        (ListingStatus::Claimed, 1),
        (ListingStatus::Cancelled, 1),
        (ListingStatus::Closed, 3),
        (ListingStatus::Active, 0),
    ] {
        assert_eq!(indexer.listings().filter(|(_, l)| l.status == status).count(), count, "{}", status.name());
    }

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

/// Every envelope of the scenario is in the `envelopes` section, and every envelope of that
/// section is carried by the scenario. A transaction carries one envelope, none (block 10 has
/// a lock spent with no envelope) or two (block 13).
#[test]
fn scenario_carries_the_listed_envelopes() {
    let v = vectors();
    let listed: Vec<Vec<u8>> =
        v["envelopes"].as_object().unwrap().values().map(|e| unhex(s(e, "hex")).unwrap()).collect();
    let mut carried: Vec<Vec<u8>> = Vec::new();
    let (mut bare, mut several) = (0, 0);
    let mut deploys_in_op_return = 0;
    for b in v["scenario"]["blocks"].as_array().unwrap() {
        for tx in block_from_vector(b).unwrap().txs {
            let found = counted_envelopes(&tx);
            assert_eq!(found, envelopes(&tx), "no envelope of another version in the scenario");
            // a height is given for input 0 of every DEPLOY in a witness, and nowhere else
            let witness_deploy = matches!(sh20_indexer::chain::counted(&tx).as_slice(), [one]
                if one.carrier == Carrier::Witness && matches!(Envelope::decode(&one.bytes), Ok(Envelope::Deploy(_))));
            assert_eq!(tx.vin[0].prev_height.is_some(), witness_deploy);
            assert!(tx.vin[1..].iter().all(|i| i.prev_height.is_none()));
            deploys_in_op_return += sh20_indexer::chain::counted(&tx)
                .iter()
                .filter(|c| {
                    c.carrier == Carrier::OpReturn && matches!(Envelope::decode(&c.bytes), Ok(Envelope::Deploy(_)))
                })
                .count();
            match found.len() {
                0 => bare += 1,
                1 => {}
                _ => several += 1,
            }
            for env in found {
                assert!(listed.contains(&env));
                assert!(Envelope::decode(&env).is_ok());
                carried.push(env);
            }
        }
    }
    assert_eq!((bare, several), (1, 1));
    assert_eq!(deploys_in_op_return, 1);
    assert!(listed.iter().all(|e| carried.contains(e)));
}

/// `bodyHash` of every envelope that has a spend: `SHA256("sh20/v0/body" ‖ body) mod r`, with
/// `body` the envelope from its first byte up to the proof.
#[test]
fn body_hashes() {
    let v = vectors();
    let mut checked = 0;
    for (name, e) in v["envelopes"].as_object().unwrap() {
        let bytes = unhex(s(e, "hex")).unwrap();
        let has_spend = Envelope::decode(&bytes).unwrap().spend().is_some();
        assert_eq!(e.get("bodyHash").is_some(), has_spend, "{name}: a bodyHash exactly when there is a spend");
        if has_spend {
            assert_eq!(fr_hex(&body_hash_of(&bytes)), s(e, "bodyHash"), "{name}");
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
}

/// The 23 carrier cases: what a transaction carries, as §3 counts it. `expect` is the one
/// counted envelope, `"none"`, or `"many"`.
#[test]
fn carriers() {
    let v = vectors();
    let cases = v["carriers"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    let (mut one, mut none, mut many) = (0, 0, 0);
    for c in cases {
        let name = s(c, "name");
        let tx = tx_from_vector(&c["tx"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        let found = counted_envelopes(&tx);
        let got = match found.as_slice() {
            [] => "none".to_string(),
            [env] => hex(env),
            _ => "many".to_string(),
        };
        assert_eq!(got, s(c, "expect"), "{name}");
        match found.len() {
            0 => none += 1,
            1 => one += 1,
            _ => many += 1,
        }
    }
    assert_eq!((one, none, many), (10, 10, 3));
}

/// What the state machine does with each carrier case: nothing without a counted envelope, a
/// refusal with several, and with one, whatever decoding and the rules say.
#[test]
fn carriers_through_the_state_machine() {
    let v = vectors();
    for (n, c) in v["carriers"].as_array().unwrap().iter().enumerate() {
        let name = s(c, "name");
        let mut tx = tx_from_vector(&c["tx"]).unwrap();
        tx.txid = [n as u8 + 1; 32];
        let mut indexer = Indexer::new(Profile::new(1, 0), Box::new(TestVerifier));
        let r = indexer.apply_block(&sh20_indexer::Block { height: 1, txs: vec![tx] }).unwrap();
        let events: Vec<&str> = r.events.iter().map(|e| e.name()).collect();
        match s(c, "expect") {
            "none" => assert!(events == ["GENESIS"] && r.rejected.is_empty(), "{name}"),
            "many" => assert!(events == ["GENESIS"] && r.rejected.len() == 1, "{name}"),
            // "SH20" alone counts and is refused; every other single envelope here is a free SH20 mint
            "53483230" => assert!(events == ["GENESIS"] && r.rejected.len() == 1, "{name}"),
            _ => assert!(events == ["GENESIS", "MINT"] && r.rejected.is_empty(), "{name}"),
        }
    }
}

/// The CLAIM vector: the message, its BIP340 signature under `lockKey`, and the two CLAIM
/// envelopes of the scenario (the signed one and a forged one).
#[test]
fn claim() {
    let v = vectors();
    let c = &v["claim"];
    let list_txid = unhex32(s(c, "listTxid")).unwrap();
    // the vectors print field elements big-endian; the envelope and the message hold them little-endian
    let mut npk = unhex32(s(c, "npk")).unwrap();
    npk.reverse();
    let lock_key = unhex32(s(c, "lockKey")).unwrap();
    let message = sh20_indexer::field::sha256(&[b"sh20/v0/claim", &list_txid, &npk]);
    assert_eq!(hex(&message), s(c, "message"));
    let sig: [u8; 64] = unhex(s(c, "sig")).unwrap().try_into().unwrap();
    assert!(bip340_verify(&lock_key, &message, &sig));

    let claim2 = Envelope::decode(&unhex(s(&v["envelopes"]["claim2"], "hex")).unwrap()).unwrap();
    assert_eq!(claim2, Envelope::Claim { list_txid, opening: npk, sig });
    let Envelope::Claim { list_txid: forged_txid, opening: forged_npk, sig: forged_sig } =
        Envelope::decode(&unhex(s(&v["envelopes"]["claimForged"], "hex")).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(forged_txid, list_txid);
    let forged_message = sh20_indexer::field::sha256(&[b"sh20/v0/claim", &forged_txid, &forged_npk]);
    assert!(!bip340_verify(&lock_key, &forged_message, &forged_sig));

    // the key is the lockKey of the listing the scenario closes then claims
    let Envelope::List { lock_key: listed_key, .. } =
        Envelope::decode(&unhex(s(&v["envelopes"]["list2"], "hex")).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(listed_key, lock_key);
}

/// `digest_{A−1} = SHA256("sh20-v0")`, and blocks below `A` have no root and no digest: an
/// indexer whose `A` is above 1 starts from the same digest and refuses a block below `A`.
#[test]
fn pre_activation() {
    let v = vectors();
    let start = s(&v["preActivation"], "digestStart");
    assert_eq!(hex(&sh20_indexer::field::sha256(&[b"sh20-v0"])), start);
    for a in [1u32, 7, 500_000] {
        let mut indexer = Indexer::new(Profile::new(a, 0), Box::new(TestVerifier));
        assert_eq!(hex(&indexer.digest()), start);
        assert_eq!(indexer.tip(), None);
        if a > 1 {
            assert!(indexer.apply_block(&sh20_indexer::Block { height: a - 1, txs: vec![] }).is_err());
            assert_eq!(hex(&indexer.digest()), start);
        }
        let first = indexer.apply_block(&sh20_indexer::Block { height: a, txs: vec![] }).unwrap();
        // digest_A = SHA256(digest_{A−1} ‖ u32le(A) ‖ R[A] ‖ SHA256(events_A)), whatever A is
        let want = sh20_indexer::field::sha256(&[
            &unhex32(start).unwrap(),
            &a.to_le_bytes(),
            &sh20_indexer::field::fr_to_le(&first.root),
            &sh20_indexer::field::sha256(&[&first.events_bytes]),
        ]);
        assert_eq!(first.digest, want);
    }
}

/// The copied LIST of block 2: the same envelope as the accepted one, in a transaction whose
/// output `lockVout` is P2TR to another key than `lockKey`. Refused, and it burns nothing: the
/// original, later in the block, is accepted with the same nullifiers.
#[test]
fn scenario_refuses_the_copied_list() {
    let v = vectors();
    let sc = &v["scenario"];
    let block2 = block_from_vector(&sc["blocks"][1]).unwrap();
    assert_eq!(block2.height, 2);
    let list = unhex(s(&v["envelopes"]["list"], "hex")).unwrap();
    let Envelope::List { lock_vout, lock_key, .. } = Envelope::decode(&list).unwrap() else { panic!() };
    let lists: Vec<_> = block2.txs.iter().filter(|tx| envelopes(tx) == [list.clone()]).collect();
    assert_eq!(lists.len(), 2);
    let pays_lock_key =
        |tx: &sh20_indexer::Tx| sh20_indexer::chain::is_p2tr_to(&tx.vout[lock_vout as usize].script, &lock_key);
    assert!(!pays_lock_key(lists[0]) && pays_lock_key(lists[1]));
    let refused: Vec<&str> = sc["rejected"].as_array().unwrap().iter().map(|r| s(r, "txid")).collect();
    assert!(refused.contains(&hex(&lists[0].txid).as_str()));
    assert!(!refused.contains(&hex(&lists[1].txid).as_str()));

    let mut indexer = Indexer::new(scenario_profile(sc), Box::new(TestVerifier));
    indexer.apply_block(&block_from_vector(&sc["blocks"][0]).unwrap()).unwrap();
    let r = indexer.apply_block(&block2).unwrap();
    assert_eq!(r.rejected.len(), 1);
    assert_eq!(r.rejected[0].txid, lists[0].txid);
    assert!(indexer.listing(&lists[0].txid).is_none());
    let listing = indexer.listing(&lists[1].txid).unwrap();
    assert_eq!(listing.lock_key, lock_key);
    assert_eq!(listing.status, ListingStatus::Active);
}

/// Blocks 9 to 11: two listings; one lock spent with no envelope (CLOSED) and one TAKE that
/// pays nothing (CANCELLED); then a forged CLAIM refused and the signed one accepted.
#[test]
fn scenario_closes_cancels_and_claims() {
    let v = vectors();
    let sc = &v["scenario"];
    let mut indexer = Indexer::new(scenario_profile(sc), Box::new(TestVerifier));
    let mut results = Vec::new();
    for b in sc["blocks"].as_array().unwrap() {
        results.push(indexer.apply_block(&block_from_vector(b).unwrap()).unwrap());
    }
    use sh20_indexer::events::Outcome;
    use sh20_indexer::Event;
    let c = &v["claim"];
    let claimed = unhex32(s(c, "listTxid")).unwrap();

    let [Event::List { txid: l2, .. }, Event::List { txid: l3, .. }] = results[8].events.as_slice() else { panic!() };
    assert_eq!(*l2, claimed);
    let [Event::Closed { list_txid: closed, .. }, Event::Take { list_txid: taken, outcome, .. }] =
        results[9].events.as_slice()
    else {
        panic!()
    };
    assert_eq!((closed, taken, *outcome), (l2, l3, Outcome::Cancelled));
    assert!(results[9].rejected.is_empty());
    let [Event::Claim { list_txid, .. }] = results[10].events.as_slice() else { panic!() };
    assert_eq!(*list_txid, claimed);
    assert_eq!(results[10].rejected.len(), 1);
    // the forged CLAIM comes first in the block and leaves the listing CLOSED for the signed one
    let block11 = block_from_vector(&sc["blocks"][10]).unwrap();
    assert_eq!(results[10].rejected[0].txid, block11.txs[0].txid);
}

/// Blocks 12 and 13. Block 12: four listings, the first anchored below `A` (checked against
/// the empty root). Block 13: a transaction with two envelopes is refused and still closes the
/// lock it spends; a CLAIM in the transaction that spends the lock is refused, and the listing
/// is CLOSED after it; a TAKE that spends two locks takes the first and closes the other.
#[test]
fn scenario_blocks_12_and_13() {
    use sh20_indexer::events::Outcome;
    use sh20_indexer::Event;
    let v = vectors();
    let sc = &v["scenario"];
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(scenario_profile(sc), Box::new(Recording(asked.clone())));
    let blocks: Vec<sh20_indexer::Block> =
        sc["blocks"].as_array().unwrap().iter().map(|b| block_from_vector(b).unwrap()).collect();
    for b in &blocks[..11] {
        indexer.apply_block(b).unwrap();
    }
    asked.borrow_mut().clear();

    let r12 = indexer.apply_block(&blocks[11]).unwrap();
    let lists: Vec<[u8; 32]> = r12
        .events
        .iter()
        .map(|e| match e {
            Event::List { txid, .. } => *txid,
            other => panic!("{}", other.name()),
        })
        .collect();
    assert_eq!(lists.len(), 4);
    assert!(r12.rejected.is_empty());
    // the first LIST is anchored at block 0, below A = 1: the empty root; the others at block 11
    let Envelope::List { spend, .. } = Envelope::decode(&envelopes(&blocks[11].txs[0])[0]).unwrap() else { panic!() };
    assert_eq!(spend.anchor_height, 0);
    let roots: Vec<Fr> = asked.borrow().iter().map(|i| i.root).collect();
    let r11 = indexer.root_at(11).unwrap();
    assert_eq!(roots, [Tree::new().empty_root(), r11, r11, r11]);
    assert_ne!(r11, Tree::new().empty_root());

    let pool_before = indexer.token(&Ticker::parse("GENE").unwrap()).unwrap().pool;
    let r13 = indexer.apply_block(&blocks[12]).unwrap();
    let [two, early, take] = blocks[12].txs.as_slice() else { panic!() };
    assert_eq!(counted_envelopes(two).len(), 2);
    assert_eq!(
        r13.events,
        [
            // two envelopes: none applied, the lock it spends still closes
            Event::Closed { txid: two.txid, list_txid: lists[0] },
            // a CLAIM in the transaction that spends the lock: refused, then CLOSED
            Event::Closed { txid: early.txid, list_txid: lists[1] },
            // two locks spent: the first in input order is taken (paid: SOLD), the other CLOSED
            Event::Take { txid: take.txid, list_txid: lists[2], outcome: Outcome::Sold, pos: 41 },
            Event::Closed { txid: take.txid, list_txid: lists[3] },
        ]
    );
    let refused: Vec<[u8; 32]> = r13.rejected.iter().map(|x| x.txid).collect();
    assert_eq!(refused, [two.txid, early.txid]);
    // nothing of the two envelopes was applied: no mint, and only the taken listing came back
    assert_eq!(indexer.token(&Ticker::SH20).unwrap().mints, 3);
    assert_eq!(indexer.token(&Ticker::parse("GENE").unwrap()).unwrap().pool, pool_before + 100);
    assert_eq!(indexer.tree_size(), 42);
    assert!(indexer.supply_holds());
}

/// `sections` describes each part of the file: every part it names exists, and what it says
/// of the carrier cases and of the verifier calls is what the tests above rely on.
#[test]
fn sections_describe_the_parts() {
    let v = vectors();
    let sections = v["sections"].as_object().unwrap();
    for name in sections.keys() {
        let part = name.split('.').fold(&v, |at, key| &at[key]);
        assert!(!part.is_null(), "sections names {name}, which is not in the file");
    }
    for name in [
        "envelopes",
        "claim",
        "preActivation",
        "carriers",
        "scenario.blocks",
        "scenario.verifierCalls",
        "scenario.after",
    ] {
        assert!(sections.contains_key(name), "{name} has no description");
    }
    // the input of a coinbase is written {"coinbase": true}
    let coinbase: Vec<&Value> = v["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["tx"]["vin"].as_array().unwrap())
        .filter(|i| i.get("coinbase").is_some())
        .collect();
    assert_eq!(coinbase.len(), 1);
    assert_eq!(coinbase[0]["coinbase"], Value::Bool(true));
    assert!(tx_from_vector(&serde_json::json!({"vin": [{"coinbase": true}], "vout": []})).unwrap().vin[0].coinbase);
}

/// DEPLOY maturity, with the scenario's `N = 3`. Block 4 holds the same DEPLOY three times:
/// revealed from a commit of block 3 (too young: refused), in an OP_RETURN (refused), and
/// revealed from a commit of block 1 (accepted). The two copies do not reach the verifier and
/// burn nothing, so the third still deploys the ticker. `N` is in the GENESIS record.
#[test]
fn scenario_refuses_the_copied_deploys() {
    use sh20_indexer::state::Error;
    use sh20_indexer::Event;
    let v = vectors();
    let sc = &v["scenario"];
    let profile = scenario_profile(sc);
    assert_eq!(profile.deploy_maturity, 3);
    let blocks: Vec<sh20_indexer::Block> =
        sc["blocks"].as_array().unwrap().iter().map(|b| block_from_vector(b).unwrap()).collect();
    let block4 = &blocks[3];
    assert_eq!(block4.height, 4);
    let [young, op_return, mature] = block4.txs.as_slice() else { panic!() };
    let deploy = unhex(s(&v["envelopes"]["deployWithTeam"], "hex")).unwrap();
    for tx in [young, op_return, mature] {
        assert_eq!(envelopes(tx), std::slice::from_ref(&deploy));
    }
    let carriers: Vec<Carrier> = block4.txs.iter().map(|tx| sh20_indexer::chain::counted(tx)[0].carrier).collect();
    assert_eq!(carriers, [Carrier::Witness, Carrier::OpReturn, Carrier::Witness]);
    let heights: Vec<Option<u32>> = block4.txs.iter().map(|tx| tx.vin[0].prev_height).collect();
    assert_eq!(heights, [Some(3), None, Some(1)]); // H − N = 1

    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(profile, Box::new(Recording(asked.clone())));
    let r1 = indexer.apply_block(&blocks[0]).unwrap();
    // GENESIS ends with N (u32): 73 bytes
    let Event::Genesis { maturity, .. } = &r1.events[0] else { panic!() };
    assert_eq!(*maturity, 3);
    assert_eq!(r1.events[0].encode().len(), 73);
    assert_eq!(r1.events_bytes[69..73], 3u32.to_le_bytes());
    indexer.apply_block(&blocks[1]).unwrap();
    indexer.apply_block(&blocks[2]).unwrap();
    asked.borrow_mut().clear();

    let r4 = indexer.apply_block(block4).unwrap();
    let refused: Vec<[u8; 32]> = r4.rejected.iter().map(|x| x.txid).collect();
    assert_eq!(refused, [young.txid, op_return.txid]);
    let [Event::Deploy { txid, ticker, burn: Some(_) }] = r4.events.as_slice() else { panic!() };
    assert_eq!((*txid, ticker.as_str()), (mature.txid, "GENE"));
    // the proof is checked last: one call, for the DEPLOY that passed the maturity rule
    assert_eq!(asked.borrow().len(), 1);

    // without the height of the commit an indexer stops instead of refusing: the same block,
    // stripped of its heights, is an error and changes nothing
    let mut indexer = Indexer::new(profile, Box::new(TestVerifier));
    for b in &blocks[..3] {
        indexer.apply_block(b).unwrap();
    }
    let before = indexer.digest();
    let mut stripped = block4.clone();
    for tx in &mut stripped.txs {
        tx.vin[0].prev_height = None;
    }
    assert_eq!(indexer.apply_block(&stripped).unwrap_err(), Error::MissingCommitHeight { height: 4, txid: young.txid });
    assert_eq!((indexer.tip(), indexer.digest()), (Some(3), before));
    // with the heights back, the block applies as the vectors say
    assert_eq!(hex(&indexer.apply_block(block4).unwrap().digest), s(&sc["after"][3], "digest"));
}
