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

/// What a replay gave, to compare with the vectors.
#[derive(Default)]
struct Replay {
    /// (height, txid, index in a batch) of every refusal, in order.
    rejected: Vec<(u64, String, Option<u64>)>,
    /// (height, the nine inputs) of every call the verifier got, in order.
    calls: Vec<(u64, Vec<String>)>,
    accepted_spends: usize,
}

/// Applies `blocks` and checks each against its entry of `after`: the root, the events,
/// `eventsH` and the digest.
fn replay_and_check(
    indexer: &mut Indexer,
    asked: &Rc<RefCell<Vec<PublicInputs>>>,
    blocks: &[Value],
    after: &[Value],
) -> Replay {
    assert_eq!(blocks.len(), after.len());
    let mut out = Replay::default();
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
            out.rejected.push((u64::from(h), hex(&r.txid), r.envelope.map(u64::from)));
        }
        out.accepted_spends += got
            .events
            .iter()
            .filter(|e| {
                use sh20_indexer::Event::*;
                matches!(e, Transfer { .. } | Burn { .. } | List { .. } | Deploy { burn: Some(_), .. })
            })
            .count();
        for inputs in asked.borrow_mut().drain(..) {
            out.calls.push((u64::from(h), inputs.as_fields().iter().map(fr_hex).collect()));
        }
    }
    out
}

/// The verifier got the calls the vectors list, in the same order, each with the same nine
/// inputs; and each call belongs to the envelope the vectors name (`envelope` in a batch).
fn check_calls(calls: &[(u64, Vec<String>)], want_calls: &[Value], blocks: &[Value]) {
    assert_eq!(calls.len(), want_calls.len(), "number of verifier calls");
    for ((height, inputs), want) in calls.iter().zip(want_calls) {
        let want_inputs: Vec<&str> =
            want["publicInputs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(want_inputs.len(), 9);
        assert_eq!(*height, want["height"].as_u64().unwrap(), "height of the call for {}", s(want, "txid"));
        assert_eq!(inputs, &want_inputs, "inputs of the call for {}", s(want, "txid"));
        let block = blocks.iter().find(|b| b["height"].as_u64() == Some(*height)).unwrap();
        let tx = block_from_vector(block).unwrap().txs.into_iter().find(|t| hex(&t.txid) == s(want, "txid")).unwrap();
        let found = sh20_indexer::chain::counted(&tx);
        // `envelope` is given exactly when the transaction is a batch
        assert_eq!(want.get("envelope").is_some(), sh20_indexer::chain::is_batch(&found), "{}", s(want, "txid"));
        let index = want.get("envelope").map_or(0, |i| i.as_u64().unwrap() as usize);
        let env = Envelope::decode(&found[index].bytes).unwrap();
        let mut nf0 = env.spend().unwrap().nf[0];
        nf0.reverse();
        assert_eq!(hex(&nf0), want_inputs[1]);
    }
}

/// The refusals of the vectors: (height, txid, index in a batch).
fn wanted_refusals(list: &Value) -> Vec<(u64, String, Option<u64>)> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (r["height"].as_u64().unwrap(), s(r, "txid").to_string(), r.get("envelope").map(|i| i.as_u64().unwrap()))
        })
        .collect()
}

/// Checks the state against a `final` object: the tree size, the listings, and for each token
/// named (by its ticker in lower case) the counters the vectors give.
fn check_final(indexer: &Indexer, f: &Value) {
    let mut tokens = 0;
    for (key, want) in f.as_object().unwrap() {
        match key.as_str() {
            "treeSize" => assert_eq!(indexer.tree_size(), want.as_u64().unwrap()),
            "listings" => {
                let mut got: Vec<(String, &str)> =
                    indexer.listings().map(|(id, l)| (hex(id), l.status.name())).collect();
                got.sort();
                let mut wanted: Vec<(String, &str)> =
                    want.as_object().unwrap().iter().map(|(id, st)| (id.clone(), st.as_str().unwrap())).collect();
                wanted.sort();
                assert_eq!(got, wanted);
            }
            ticker => {
                let token = indexer.token(&Ticker::parse(&ticker.to_uppercase()).unwrap()).unwrap();
                for (field, value) in want.as_object().unwrap() {
                    match field.as_str() {
                        "mints" => assert_eq!(token.mints, dec(want, "mints"), "{ticker}.mints"),
                        "burned" => assert_eq!(token.burned, dec(want, "burned"), "{ticker}.burned"),
                        "pool" => assert_eq!(token.pool, dec(want, "pool"), "{ticker}.pool"),
                        "teamUnlocked" => {
                            assert_eq!(Value::Bool(token.team_unlocked), *value, "{ticker}.teamUnlocked")
                        }
                        other => panic!("final.{ticker}.{other}: a field this test does not know"),
                    }
                }
                tokens += 1;
            }
        }
    }
    assert!(tokens >= 2);
}

/// The whole scenario: for every block the root, the events, `eventsH` and the digest; then the
/// refusals, the inputs of every verifier call, and the final state.
#[test]
fn scenario() {
    let v = vectors();
    let sc = &v["scenario"];
    let profile = scenario_profile(sc);
    // the window is read from the profile: W = 12 here, not the 100 of SPEC-WIRE §5
    assert_eq!((profile.anchor_window, profile.deploy_maturity), (12, 3));
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(profile, Box::new(Recording(asked.clone())));

    let blocks = sc["blocks"].as_array().unwrap();
    let after = sc["after"].as_array().unwrap();
    assert_eq!(blocks.len(), 17);
    let replay = replay_and_check(&mut indexer, &asked, blocks, after);

    // the refusals: exactly the ones listed, with the index of the envelope in a batch
    let want_rejected = wanted_refusals(&sc["rejected"]);
    assert_eq!(want_rejected.len(), 15);
    assert_eq!(replay.rejected, want_rejected);

    // the verifier: the same calls, in the same order, each with the same nine inputs
    let want_calls = sc["verifierCalls"].as_array().unwrap();
    assert_eq!(want_calls.len(), 18);
    check_calls(&replay.calls, want_calls, blocks);
    // the proof is checked last and every proof of the scenario is the valid one: the calls
    // are the accepted spends, no more
    assert_eq!(replay.calls.len(), replay.accepted_spends);

    // the final state
    let f = &sc["final"];
    check_final(&indexer, f);
    assert_eq!(f["listings"].as_object().unwrap().len(), 7);
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
    let sh20 = indexer.token(&Ticker::SH20).unwrap();
    let g = &v["genesis"];
    assert_eq!(sh20.ticker.as_str(), s(g, "ticker"));
    assert_eq!(sh20.max, dec(g, "max"));
    assert_eq!(sh20.lim, dec(g, "lim"));
    assert_eq!(sh20.pre, dec(g, "pre"));
    assert_eq!(sh20.price, dec(g, "price"));
    assert_eq!(u64::from(sh20.pay_mode), g["payMode"].as_u64().unwrap());
    assert_eq!(sh20.start, profile.activation_height);
}

/// The `reorg` part: after the scenario, roll back to `rollbackTo` and apply the blocks given.
/// `after` and `final` are what an indexer that never saw the first blocks 16 and 17 computes.
#[test]
fn reorg() {
    let v = vectors();
    let (sc, r) = (&v["scenario"], &v["reorg"]);
    let profile = scenario_profile(sc);
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(profile, Box::new(Recording(asked.clone())));
    let blocks = sc["blocks"].as_array().unwrap();
    replay_and_check(&mut indexer, &asked, blocks, sc["after"].as_array().unwrap());
    let tip_digest = indexer.digest();

    let fork = r["rollbackTo"].as_u64().unwrap() as u32;
    assert_eq!(fork, 15);
    indexer.rollback_to(fork).unwrap();
    assert_eq!(indexer.tip(), Some(fork));
    assert_eq!(hex(&indexer.digest()), s(&sc["after"][fork as usize - 1], "digest"));

    let new_blocks = r["blocks"].as_array().unwrap();
    assert_eq!(new_blocks.len(), 2);
    let replay = replay_and_check(&mut indexer, &asked, new_blocks, r["after"].as_array().unwrap());
    assert_ne!(indexer.digest(), tip_digest);
    check_calls(&replay.calls, r["verifierCalls"].as_array().unwrap(), new_blocks);
    assert_eq!(replay.calls.len(), 1);
    // `reorg` lists no refusal, and there is none
    assert!(r.get("rejected").is_none() && replay.rejected.is_empty());
    check_final(&indexer, &r["final"]);

    // 16' spends again the nullifiers the TRANSFER of the first 16 had spent: accepted only
    // because the rollback freed them
    let spends = |block: &Value| -> Vec<[[u8; 32]; 2]> {
        block_from_vector(block)
            .unwrap()
            .txs
            .iter()
            .flat_map(counted_envelopes)
            .filter_map(|e| Envelope::decode(&e).ok().and_then(|env| env.spend().map(|sp| sp.nf)))
            .collect()
    };
    let (first_16, new_16) = (spends(&blocks[15]), spends(&new_blocks[0]));
    assert_eq!((first_16.len(), new_16.len()), (1, 1));
    assert_eq!(first_16[0], new_16[0]);
    assert!(indexer.nullifier_seen(&new_16[0][0]));

    // an indexer that never saw the first 16 and 17 is in the same state
    let mut never_saw = Indexer::new(profile, Box::new(TestVerifier));
    for b in blocks[..fork as usize].iter().chain(new_blocks) {
        never_saw.apply_block(&block_from_vector(b).unwrap()).unwrap();
    }
    assert_eq!(never_saw.digest(), indexer.digest());
    assert_eq!(never_saw.tree_size(), indexer.tree_size());
    assert_eq!(never_saw.root_at(17), indexer.root_at(17));
    check_final(&never_saw, &r["final"]);
    let tokens = |ix: &Indexer| ix.tokens().cloned().collect::<Vec<_>>();
    assert_eq!(tokens(&never_saw), tokens(&indexer));

    // and rolling back again, then applying the first 16 and 17, gives the scenario's digest back
    indexer.rollback_to(fork).unwrap();
    for b in &blocks[fork as usize..] {
        indexer.apply_block(&block_from_vector(b).unwrap()).unwrap();
    }
    assert_eq!(indexer.digest(), tip_digest);
}

/// Block 17: a batch of three TRANSFERs in one tapscript. Each is judged alone, in order: the
/// first is accepted, the second spends one of its nullifiers again and is refused, the third
/// is accepted. The two events share the transaction's txid.
#[test]
fn scenario_batch_of_block_17() {
    use sh20_indexer::Event;
    let v = vectors();
    let sc = &v["scenario"];
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut indexer = Indexer::new(scenario_profile(sc), Box::new(Recording(asked.clone())));
    let blocks: Vec<sh20_indexer::Block> =
        sc["blocks"].as_array().unwrap().iter().map(|b| block_from_vector(b).unwrap()).collect();
    for b in &blocks[..16] {
        indexer.apply_block(b).unwrap();
    }
    asked.borrow_mut().clear();
    let size_before = indexer.tree_size();

    let [batch] = blocks[16].txs.as_slice() else { panic!() };
    let found = sh20_indexer::chain::counted(batch);
    assert_eq!(found.len(), 3);
    assert!(sh20_indexer::chain::is_batch(&found));
    let names = ["batchA", "batchB", "batchC"];
    let spends: Vec<sh20_indexer::envelope::Spend> = found
        .iter()
        .zip(names)
        .map(|(c, name)| {
            assert_eq!(hex(&c.bytes), s(&v["envelopes"][name], "hex"), "{name}: the order of the tapscript");
            let Envelope::Transfer { spend } = Envelope::decode(&c.bytes).unwrap() else { panic!() };
            spend
        })
        .collect();
    // the second shares its first nullifier with the first; the third shares none
    assert_eq!(spends[0].nf[0], spends[1].nf[0]);
    assert_ne!(spends[0].nf[1], spends[1].nf[1]);
    assert!(spends[2].nf.iter().all(|nf| !spends[0].nf.contains(nf) && !spends[1].nf.contains(nf)));

    let r = indexer.apply_block(&blocks[16]).unwrap();
    // two team notes first (by ticker), then the accepted envelopes of the batch, in order
    let [Event::TeamUnlock { ticker: first, .. }, Event::TeamUnlock { ticker: second, .. }, Event::Transfer { txid: t0, spent: s0 }, Event::Transfer { txid: t2, spent: s2 }] =
        r.events.as_slice()
    else {
        panic!()
    };
    assert!(first.0 < second.0);
    assert_eq!((*t0, *t2), (batch.txid, batch.txid));
    assert_eq!((s0.nf, s2.nf), (spends[0].nf, spends[2].nf));
    // the refused envelope appends nothing: the third follows the first in the tree
    let base = size_before as u32 + 2;
    assert_eq!((s0.pos, s2.pos), ([base, base + 1, base + 2], [base + 3, base + 4, base + 5]));
    // one refusal, for the envelope of index 1; the verifier was asked for 0 and 2 only
    assert_eq!(r.rejected.len(), 1);
    assert_eq!((r.rejected[0].txid, r.rejected[0].envelope), (batch.txid, Some(1)));
    let asked_nf: Vec<[u8; 32]> = asked.borrow().iter().map(|i| sh20_indexer::field::fr_to_le(&i.nf[0])).collect();
    assert_eq!(asked_nf, [spends[0].nf[0], spends[2].nf[0]]);
}

/// Every envelope of the scenario and of the reorg is in the `envelopes` section, and every
/// envelope of that section is carried by one of them. A transaction carries one envelope,
/// none (block 10 has a lock spent with no envelope) or several (block 13: refused; block 17:
/// a batch).
#[test]
fn scenario_carries_the_listed_envelopes() {
    let v = vectors();
    let listed: Vec<Vec<u8>> =
        v["envelopes"].as_object().unwrap().values().map(|e| unhex(s(e, "hex")).unwrap()).collect();
    let mut carried: Vec<Vec<u8>> = Vec::new();
    let (mut bare, mut batches, mut refused_whole) = (0, 0, 0);
    let mut deploys_in_op_return = 0;
    let all_blocks = v["scenario"]["blocks"].as_array().unwrap().iter().chain(v["reorg"]["blocks"].as_array().unwrap());
    for b in all_blocks {
        for tx in block_from_vector(b).unwrap().txs {
            let found = sh20_indexer::chain::counted(&tx);
            assert_eq!(counted_envelopes(&tx), envelopes(&tx), "no envelope of another version in the scenario");
            // a height is given for input 0 of every DEPLOY in a witness, and nowhere else
            let is_deploy =
                |c: &sh20_indexer::chain::Carried| matches!(Envelope::decode(&c.bytes), Ok(Envelope::Deploy(_)));
            let witness_deploy = matches!(found.as_slice(), [one] if one.carrier == Carrier::Witness && is_deploy(one));
            assert_eq!(tx.vin[0].prev_height.is_some(), witness_deploy);
            assert!(tx.vin[1..].iter().all(|i| i.prev_height.is_none()));
            deploys_in_op_return += found.iter().filter(|c| c.carrier == Carrier::OpReturn && is_deploy(c)).count();
            match found.len() {
                0 => bare += 1,
                1 => {}
                _ if sh20_indexer::chain::is_batch(&found) => batches += 1,
                _ => refused_whole += 1,
            }
            for c in found {
                assert!(listed.contains(&c.bytes));
                assert!(Envelope::decode(&c.bytes).is_ok());
                carried.push(c.bytes);
            }
        }
    }
    assert_eq!((bare, batches, refused_whole), (1, 1, 1));
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
    assert_eq!(checked, 26);
}

/// What §3 finds in a transaction, in the words of the vectors' `expect`.
#[derive(Debug, PartialEq)]
enum Found {
    None,
    One(String),
    Batch(Vec<String>),
    Many,
}

fn found_in(tx: &sh20_indexer::Tx) -> Found {
    let counted = sh20_indexer::chain::counted(tx);
    match counted.as_slice() {
        [] => Found::None,
        [one] => Found::One(hex(&one.bytes)),
        batch if sh20_indexer::chain::is_batch(batch) => Found::Batch(batch.iter().map(|c| hex(&c.bytes)).collect()),
        _ => Found::Many,
    }
}

fn expected(expect: &Value) -> Found {
    match expect {
        Value::Array(list) => Found::Batch(list.iter().map(|e| e.as_str().unwrap().to_string()).collect()),
        Value::String(text) if text == "none" => Found::None,
        Value::String(text) if text == "many" => Found::Many,
        Value::String(text) => Found::One(text.clone()),
        other => panic!("expect: {other}"),
    }
}

/// The carrier cases: what a transaction carries, as §3 counts it. `expect` is the one counted
/// envelope, `"none"`, a list (a batch) or `"many"`.
#[test]
fn carriers() {
    let v = vectors();
    let cases = v["carriers"].as_array().unwrap();
    assert_eq!(cases.len(), 32);
    let (mut one, mut none, mut batch, mut many) = (0, 0, 0, 0);
    for c in cases {
        let name = s(c, "name");
        let tx = tx_from_vector(&c["tx"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        let got = found_in(&tx);
        assert_eq!(got, expected(&c["expect"]), "{name}");
        match got {
            Found::None => none += 1,
            Found::One(_) => one += 1,
            Found::Batch(_) => batch += 1,
            Found::Many => many += 1,
        }
    }
    assert_eq!((one, none, batch, many), (11, 11, 3, 7));
}

/// What the state machine does with each carrier case: nothing without a counted envelope, one
/// refusal for the transaction with several that are not a batch, one outcome per envelope in a
/// batch, and with one envelope whatever decoding and the rules say.
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
        let indexes: Vec<Option<u32>> = r.rejected.iter().map(|x| x.envelope).collect();
        match expected(&c["expect"]) {
            Found::None => assert!(events == ["GENESIS"] && r.rejected.is_empty(), "{name}"),
            Found::Many => assert!(events == ["GENESIS"] && indexes == [None], "{name}"),
            Found::Batch(list) => {
                // in block 1 their anchors are in the future: each is refused alone, by its index
                assert_eq!(events, ["GENESIS"], "{name}");
                assert_eq!(indexes, (0..list.len() as u32).map(Some).collect::<Vec<_>>(), "{name}");
            }
            Found::One(env) => match Envelope::decode(&unhex(&env).unwrap()) {
                // every single MINT of the cases is a free SH20 mint
                Ok(Envelope::Mint { .. }) => {
                    assert!(events == ["GENESIS", "MINT"] && r.rejected.is_empty(), "{name}")
                }
                // "SH20" alone counts and does not decode; a TRANSFER is anchored in the future
                _ => assert!(events == ["GENESIS"] && indexes == [None], "{name}"),
            },
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
        "reorg",
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
    // twice: once with no witness, once with a witness that is not read
    assert_eq!(coinbase.len(), 2);
    assert!(coinbase.iter().all(|i| i["coinbase"] == Value::Bool(true)));
    assert_eq!(coinbase.iter().filter(|i| i["witness"].as_array().is_some_and(|w| !w.is_empty())).count(), 1);
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
