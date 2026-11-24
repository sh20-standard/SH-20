//! Replays `indexer/vectors/plonk-v0.3.json`: a chain whose spends carry real PLONK proofs.
//! The verifier is the one of `circuit/` under the pinned key; what is checked here is that
//! this indexer hands it the nine inputs the vectors list, gets the answers they list, and
//! ends every block on the same root, events and digest as the reference.

use serde_json::Value;
use sh20_indexer::chain::counted;
use sh20_indexer::envelope::{body_hash_of, PROOF_LEN};
use sh20_indexer::field::{fr_to_be, fr_to_le, hex, sha256, unhex, unhex32};
use sh20_indexer::json::block_from_vector;
use sh20_indexer::verifier::{PublicInputs, SpendVerifier, VERIFYING_KEY, VK_DIGEST};
use sh20_indexer::{Envelope, Event, Indexer, PlonkVerifier, Profile, RejectAll, Ticker};
use std::cell::RefCell;
use std::rc::Rc;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/plonk-v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file")).expect("vectors JSON")
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("string {key}"))
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key].as_array().unwrap_or_else(|| panic!("list {key}"))
}

fn profile(v: &Value) -> Profile {
    let p = &v["profile"];
    let n = |key: &str| p[key].as_u64().unwrap_or_else(|| panic!("number {key}"));
    Profile {
        activation_height: n("activationHeight") as u32,
        deploy_burn: s(p, "deployBurn").parse().expect("deployBurn"),
        anchor_window: n("anchorWindow") as u32,
        anchor_min_depth: n("anchorMinDepth") as u32,
        deploy_maturity: n("deployMaturity") as u32,
    }
}

/// One call to the verifier: the nine inputs as the vectors write them, and the answer.
type Call = (Vec<String>, bool);

/// A verifier that keeps every call it gets and what the one inside answered.
struct Recording<V: SpendVerifier>(V, Rc<RefCell<Vec<Call>>>);

impl<V: SpendVerifier> SpendVerifier for Recording<V> {
    fn verify_spend(&self, inputs: &PublicInputs, proof: &[u8]) -> bool {
        let answer = self.0.verify_spend(inputs, proof);
        let fields = inputs.as_fields().iter().map(|f| hex(&fr_to_be(f))).collect();
        self.1.borrow_mut().push((fields, answer));
        answer
    }
}

/// What a replay of the vectors' blocks gave.
struct Replay {
    indexer: Indexer,
    /// (height, the nine inputs, the answer) of every call, in order.
    calls: Vec<(u64, Vec<String>, bool)>,
    /// (height, txid) of every refusal, in order.
    rejected: Vec<(u64, String)>,
    /// (root, event names, eventsH, digest) after each block.
    after: Vec<(String, Vec<&'static str>, String, String)>,
    events: Vec<Event>,
}

fn replay(v: &Value, verifier: impl SpendVerifier + 'static) -> Replay {
    let asked = Rc::new(RefCell::new(Vec::new()));
    let indexer = Indexer::new(profile(v), Box::new(Recording(verifier, asked.clone())));
    let mut out = Replay { indexer, calls: Vec::new(), rejected: Vec::new(), after: Vec::new(), events: Vec::new() };
    for b in list(v, "blocks") {
        let block = block_from_vector(b).unwrap();
        let h = u64::from(block.height);
        let got = out.indexer.apply_block(&block).unwrap();
        assert!(out.indexer.supply_holds(), "supply identity after block {h}");
        out.calls.extend(asked.borrow_mut().drain(..).map(|(inputs, answer)| (h, inputs, answer)));
        out.rejected.extend(got.rejected.iter().map(|r| (h, hex(&r.txid))));
        out.after.push((
            hex(&fr_to_be(&got.root)),
            got.events.iter().map(|e| e.name()).collect(),
            hex(&got.events_bytes),
            hex(&got.digest),
        ));
        out.events.extend(got.events);
    }
    out
}

/// The key built into the binary is the key of the vectors, and both are the key the spec pins.
#[test]
fn the_verifying_key_is_the_pinned_one() {
    let v = vectors();
    let key = unhex(s(&v["verifyingKey"], "hex")).unwrap();
    assert_eq!(key.len(), 712);
    assert_eq!(key, VERIFYING_KEY);
    // the digest three ways: the vectors, this crate's own SHA-256, and what circuit/ pins
    assert_eq!(s(&v["verifyingKey"], "digest"), VK_DIGEST);
    assert_eq!(hex(&sha256(&[b"sh20/v0/vk", &key])), VK_DIGEST);
    assert_eq!(sh20_circuit::VK_DIGEST, VK_DIGEST);
    assert_eq!((sh20_circuit::N_PUBLIC, sh20_circuit::PROOF_BYTES), (9, PROOF_LEN));
    assert!(PlonkVerifier::pinned().is_ok());
    assert!(PlonkVerifier::with_key(&key).is_ok());

    // any other key is refused, whatever it would verify: one bit of a coordinate, a cut key
    let mut other = key.clone();
    other[100] ^= 1;
    assert!(PlonkVerifier::with_key(&other).is_err());
    assert!(PlonkVerifier::with_key(&key[..711]).is_err());
    assert!(PlonkVerifier::with_key(&[]).is_err());
}

/// The envelopes of the vectors: their sizes, the `bodyHash` of each spend, and the three
/// tampered ones, each a spend with the low bit of the first scalar of its proof flipped.
#[test]
fn the_envelopes() {
    let v = vectors();
    let e = &v["envelopes"];
    for (name, value) in e.as_object().unwrap() {
        let bytes = unhex(s(value, "hex")).unwrap();
        assert_eq!(bytes.len() as u64, value["bytes"].as_u64().unwrap(), "{name}");
        let envelope = Envelope::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(envelope.encode(), bytes, "{name}");
        match value.get("bodyHash") {
            Some(want) => assert_eq!(hex(&fr_to_be(&body_hash_of(&bytes))), want.as_str().unwrap(), "{name}"),
            None => assert!(envelope.spend().is_none(), "{name}"),
        }
    }
    for (good, bad) in [("transfer", "tampered"), ("list", "tamperedList"), ("deploy", "tamperedDeploy")] {
        let spend = unhex(s(&e[good], "hex")).unwrap();
        let tampered = unhex(s(&e[bad], "hex")).unwrap();
        let mut mended = tampered.clone();
        mended[spend.len() - PROOF_LEN + 9 * 32] ^= 1;
        assert_ne!(tampered, spend, "{bad}");
        assert_eq!(mended, spend, "{bad}");
    }
    // every block's envelopes are among them
    let known: Vec<Vec<u8>> = e.as_object().unwrap().values().map(|x| unhex(s(x, "hex")).unwrap()).collect();
    for b in list(&v, "blocks") {
        for tx in block_from_vector(b).unwrap().txs {
            let found = counted(&tx);
            assert_eq!(found.len(), 1);
            assert!(known.contains(&found[0].bytes));
        }
    }
}

/// The whole chain under the real verifier: every call with its nine inputs and its answer,
/// every refusal, and after every block the root, the events, `eventsH` and the digest.
#[test]
fn the_chain() {
    let v = vectors();
    let r = replay(&v, PlonkVerifier::pinned().unwrap());

    let want_calls = list(&v, "verifierCalls");
    assert_eq!(r.calls.len(), want_calls.len(), "number of verifier calls");
    for ((height, inputs, answer), want) in r.calls.iter().zip(want_calls) {
        let txid = s(want, "txid");
        let want_inputs: Vec<&str> = list(want, "publicInputs").iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(want_inputs.len(), 9);
        assert_eq!(*height, want["height"].as_u64().unwrap(), "height of the call for {txid}");
        assert_eq!(inputs, &want_inputs, "inputs of the call for {txid}");
        assert_eq!(*answer, want["accepted"].as_bool().unwrap(), "answer to the call for {txid}");
        // the call is for the transaction the vectors name: its envelope has that nf0
        let block = list(&v, "blocks").iter().find(|b| b["height"].as_u64() == Some(*height)).unwrap();
        let tx = block_from_vector(block).unwrap().txs.into_iter().find(|t| hex(&t.txid) == txid).unwrap();
        let mut nf0 = Envelope::decode(&counted(&tx)[0].bytes).unwrap().spend().unwrap().nf[0];
        nf0.reverse();
        assert_eq!(hex(&nf0), want_inputs[1]);
    }
    // the vectors do hold what they are for: one spend of each kind accepted (a TRANSFER with no
    // public value, then a BURN, a LIST and a DEPLOY with their `vPub` and `tPub`), and before
    // three of them the same spend refused by the pairing alone
    let answers: Vec<bool> = r.calls.iter().map(|c| c.2).collect();
    assert_eq!(answers, [false, true, true, false, true, false, true]);
    for (tampered, good) in [(0, 1), (3, 4), (5, 6)] {
        assert_eq!(r.calls[tampered].1, r.calls[good].1, "a tampered proof comes with the inputs of the good one");
    }
    let zero = "0".repeat(64);
    assert_eq!((&r.calls[1].1[7], &r.calls[1].1[8]), (&zero, &zero));
    for call in [2, 4, 6] {
        assert_ne!(r.calls[call].1[7], zero, "vPub of call {call}");
        assert_eq!(r.calls[call].1[8], r.calls[2].1[8], "tPub of call {call}: one ticker");
    }
    let kinds: Vec<&str> = r.events.iter().map(|e| e.name()).filter(|n| !["GENESIS", "MINT"].contains(n)).collect();
    assert_eq!(kinds, ["TRANSFER", "BURN", "LIST", "DEPLOY"]);

    let want_rejected: Vec<(u64, String)> =
        list(&v, "rejected").iter().map(|x| (x["height"].as_u64().unwrap(), s(x, "txid").to_string())).collect();
    assert_eq!(r.rejected, want_rejected);

    let after = list(&v, "after");
    assert_eq!(r.after.len(), after.len());
    for ((root, events, events_h, digest), want) in r.after.iter().zip(after) {
        let h = &want["height"];
        assert_eq!(root, s(want, "root"), "root of block {h}");
        let want_events: Vec<&str> = list(want, "events").iter().map(|e| e.as_str().unwrap()).collect();
        assert_eq!(events, &want_events, "events of block {h}");
        assert_eq!(events_h, s(want, "eventsH"), "eventsH of block {h}");
        assert_eq!(digest, s(want, "digest"), "digest of block {h}");
    }

    // the final state: the leaves, the nullifiers, the turnstile of SH20 after the BURN, the LIST
    // and the DEPLOY's burn, the token the DEPLOY made, and the listing
    let f = &v["final"];
    assert_eq!(r.indexer.tree_size(), f["treeSize"].as_u64().unwrap());
    for (ticker, key) in [("SH20", "sh20"), ("GENE", "gene")] {
        let token = r.indexer.token(&Ticker::parse(ticker).unwrap()).unwrap();
        assert_eq!(token.mints.to_string(), s(&f[key], "mints"), "{ticker}");
        assert_eq!(token.burned.to_string(), s(&f[key], "burned"), "{ticker}");
        assert_eq!(token.pool.to_string(), s(&f[key], "pool"), "{ticker}");
    }
    let listings: Vec<(String, &str)> = r.indexer.listings().map(|(id, l)| (hex(id), l.status.name())).collect();
    let want_listings: Vec<(String, &str)> =
        f["listings"].as_object().unwrap().iter().map(|(id, state)| (id.clone(), state.as_str().unwrap())).collect();
    assert_eq!(listings, want_listings);
    assert_eq!(listings.len(), 1);
    let listing = r.indexer.listings().next().unwrap().1;
    assert_eq!(hex(&listing.lock_key), s(&v, "lockKey"));
    let spent: Vec<[u8; 32]> = r
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Transfer { spent, .. } | Event::Burn { spent, .. } | Event::List { spent, .. } => Some(spent.nf),
            Event::Deploy { burn, .. } => burn.as_ref().map(|spent| spent.nf),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(spent.len() as u64, f["nullifiers"].as_u64().unwrap());
    assert!(spent.iter().all(|nf| r.indexer.nullifier_seen(nf)));
    // and they are the nullifiers the verifier was shown, not others
    let shown: Vec<String> = r.calls.iter().filter(|c| c.2).flat_map(|c| c.1[1..3].to_vec()).collect();
    let spent_be: Vec<String> = spent.iter().map(|nf| hex(&nf.iter().rev().copied().collect::<Vec<u8>>())).collect();
    assert_eq!(spent_be, shown);
}

/// The same chain where every spend is refused: the verifier is asked the same first question,
/// and the two indexers part at block 3, the first block with a valid proof.
#[test]
fn the_chain_without_a_verifier() {
    let v = vectors();
    let r = replay(&v, RejectAll);
    let after = list(&v, "after");
    for (i, (_, _, _, digest)) in r.after.iter().enumerate() {
        assert_eq!(digest == s(&after[i], "digest"), i < 2, "block {}", i + 1);
    }
    assert!(r.calls.iter().all(|c| !c.2));
    assert_eq!(r.indexer.tree_size(), 2);
}

/// One proof, many ways to be wrong: each is refused, and none makes the verifier panic.
#[test]
fn what_the_verifier_refuses() {
    let v = vectors();
    let verifier = PlonkVerifier::pinned().unwrap();
    // the TRANSFER's call, rebuilt from the vectors alone
    let call = &list(&v, "verifierCalls")[1];
    let fields: Vec<ark_bn254::Fr> = list(call, "publicInputs")
        .iter()
        .map(|x| {
            let mut le = unhex32(x.as_str().unwrap()).unwrap();
            le.reverse();
            sh20_indexer::field::fr_from_le(&le).unwrap()
        })
        .collect();
    let inputs = PublicInputs {
        root: fields[0],
        nf: [fields[1], fields[2]],
        leaves: [fields[3], fields[4], fields[5]],
        body_hash: fields[6],
        v_pub: 0,
        t_pub: 0,
    };
    assert_eq!(inputs.as_fields().to_vec(), fields);
    let envelope = unhex(s(&v["envelopes"]["transfer"], "hex")).unwrap();
    let proof = &envelope[envelope.len() - PROOF_LEN..];
    assert!(verifier.verify_spend(&inputs, proof));

    // each public input moved by one
    let one = ark_bn254::Fr::from(1u64);
    let moved: [PublicInputs; 9] = [
        PublicInputs { root: inputs.root + one, ..inputs.clone() },
        PublicInputs { nf: [inputs.nf[0] + one, inputs.nf[1]], ..inputs.clone() },
        PublicInputs { nf: [inputs.nf[0], inputs.nf[1] + one], ..inputs.clone() },
        PublicInputs { leaves: [inputs.leaves[0] + one, inputs.leaves[1], inputs.leaves[2]], ..inputs.clone() },
        PublicInputs { leaves: [inputs.leaves[0], inputs.leaves[1] + one, inputs.leaves[2]], ..inputs.clone() },
        PublicInputs { leaves: [inputs.leaves[0], inputs.leaves[1], inputs.leaves[2] + one], ..inputs.clone() },
        PublicInputs { body_hash: inputs.body_hash + one, ..inputs.clone() },
        PublicInputs { v_pub: 1, ..inputs.clone() },
        PublicInputs { t_pub: 1, ..inputs.clone() },
    ];
    for (i, m) in moved.iter().enumerate() {
        assert!(!verifier.verify_spend(m, proof), "public input {i}");
    }
    // two inputs swapped
    let swapped = PublicInputs { nf: [inputs.nf[1], inputs.nf[0]], ..inputs.clone() };
    assert!(!verifier.verify_spend(&swapped, proof));

    // one bit flipped in each of the fifteen parts of the proof (nine points, six scalars)
    for part in 0..15 {
        let mut bad = proof.to_vec();
        bad[part * 32] ^= 1;
        assert!(!verifier.verify_spend(&inputs, &bad), "part {part}");
    }
    // a scalar that is r itself (not below r), and bytes that are no point
    let r_le = {
        let mut minus_one = fr_to_le(&(-one));
        minus_one[0] += 1; // r − 1 ends in an even byte: no carry
        minus_one
    };
    let mut bad = proof.to_vec();
    bad[9 * 32..10 * 32].copy_from_slice(&r_le);
    assert!(!verifier.verify_spend(&inputs, &bad));
    let mut bad = proof.to_vec();
    bad[..32].copy_from_slice(&[0xff; 32]);
    assert!(!verifier.verify_spend(&inputs, &bad));
    // another length, the proof of another spend, and nothing at all
    assert!(!verifier.verify_spend(&inputs, &proof[..PROOF_LEN - 1]));
    assert!(!verifier.verify_spend(&inputs, &[proof, &[0u8][..]].concat()));
    assert!(!verifier.verify_spend(&inputs, &[]));
    assert!(!verifier.verify_spend(&inputs, &[0u8; PROOF_LEN]));
    let burn = unhex(s(&v["envelopes"]["burn"], "hex")).unwrap();
    assert!(!verifier.verify_spend(&inputs, &burn[burn.len() - PROOF_LEN..]));
}
