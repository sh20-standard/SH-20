//! The routes of `docs/API.md` over the vectors' scenario: what each one returns, checked
//! against the vectors and against the rules (leaves recomputed, paths folded up to the root).

mod common;

use ark_bn254::Fr;
use common::fake::*;
use serde_json::{json, Value};
use sh20_indexer::api::Store;
use sh20_indexer::envelope::Ticker;
use sh20_indexer::field::{fr_from_le, fr_to_be, h2, hex, public_leaf, unhex32};
use sh20_indexer::tree::Tree;
use std::sync::{Arc, RwLock};

/// The store after the 17 blocks of the scenario.
fn followed(v: &Value) -> Arc<RwLock<Store>> {
    let (mut f, store) = follower(v, Chain::new(scenario(v, true)));
    f.catch_up().unwrap();
    store
}

fn list(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// A field element from the API's big-endian hex.
fn fr(v: &Value) -> Fr {
    let mut bytes = unhex32(text(v)).unwrap();
    bytes.reverse();
    fr_from_le(&bytes).unwrap()
}

fn fr_hex(f: &Fr) -> String {
    hex(&fr_to_be(f))
}

/// How many events of a type the vectors list for the scenario.
fn count_events(v: &Value, name: &str) -> usize {
    list(&v["scenario"]["after"]).iter().flat_map(|a| list(&a["events"])).filter(|e| *e == name).count()
}

#[test]
fn status() {
    let v = vectors();
    let store = followed(&v);
    let s = get(&store, "/status");
    let last = v["scenario"]["after"].as_array().unwrap().last().unwrap();
    assert_eq!(s["height"], 17);
    assert_eq!(s["hash"], block_hash(17, 0));
    assert_eq!(s["digest"], last["digest"]);
    assert_eq!(s["root"], last["root"]);
    assert_eq!(s["leaves"], v["scenario"]["final"]["treeSize"]);
    assert_eq!(s["nullifiers"], 2 * v["scenario"]["verifierCalls"].as_array().unwrap().len() as u64 - 2);
    assert_eq!(s["tokens"], 1 + count_events(&v, "DEPLOY"));
    assert_eq!((&s["network"], &s["verifier"]), (&json!("test"), &json!("test")));
    // the profile, under the names of the vectors
    let p = &v["scenario"]["profile"];
    for key in ["activationHeight", "deployBurn", "anchorWindow", "anchorMinDepth", "deployMaturity"] {
        assert_eq!(s[key], p[key], "{key}");
    }
    // the genesis token, as the vectors describe it
    for key in ["ticker", "max", "lim", "pre", "price", "payMode"] {
        assert_eq!(s["genesis"][key], v["genesis"][key], "genesis.{key}");
    }

    // before the first block: no height, the digest an indexer starts from, the empty root
    let empty = follower(&v, Chain::default()).1;
    let s = get(&empty, "/status");
    assert_eq!((&s["height"], &s["hash"]), (&Value::Null, &Value::Null));
    assert_eq!(s["digest"], v["preActivation"]["digestStart"]);
    assert_eq!(s["root"], v["emptyRootDepth32"]);
    assert_eq!((&s["leaves"], &s["nullifiers"], &s["tokens"]), (&json!(0), &json!(0), &json!(0)));
    assert_eq!(get(&empty, "/roots"), json!([]));
    assert_eq!(get(&empty, "/blocks"), json!([]));
    assert_eq!(get(&empty, "/nullifiers"), json!({ "from": 1, "height": null, "nullifiers": [] }));
}

#[test]
fn tokens() {
    let v = vectors();
    let store = followed(&v);
    let tokens = get(&store, "/tokens");
    let tickers: Vec<String> = list(&tokens).iter().map(|t| text(&t["ticker"]).to_string()).collect();
    // the genesis token first, then in DEPLOY order: the order of the DEPLOY events of the blocks
    let mut want = vec!["SH20".to_string()];
    for h in 1..=17 {
        let block = get(&store, &format!("/block/{h}"));
        for e in list(&block["events"]).iter().filter(|e| e["type"] == "DEPLOY") {
            want.push(text(&e["ticker"]).to_string());
            let token = get(&store, &format!("/token/{}", text(&e["ticker"])));
            assert_eq!((&token["deployTxid"], &token["deployHeight"]), (&e["txid"], &json!(h)));
        }
    }
    assert_eq!(tickers, want);
    assert_eq!(tickers.len(), 1 + count_events(&v, "DEPLOY"));
    assert_eq!(tickers[..2], ["SH20", "GENE"]);
    let f = &v["scenario"]["final"];
    for t in list(&tokens) {
        let ticker = text(&t["ticker"]);
        let want = &f[ticker.to_lowercase()];
        for key in ["mints", "burned", "pool"] {
            if !want[key].is_null() {
                assert_eq!(t[key], want[key], "{ticker}.{key}");
            }
        }
        assert_eq!(t["t"], Ticker::parse(ticker).unwrap().t().to_string());
        assert_eq!(get(&store, &format!("/token/{ticker}")), *t);
    }
    let sh20 = &list(&tokens)[0];
    assert_eq!((&sh20["genesis"], &sh20["deployTxid"], &sh20["deployHeight"]), (&json!(true), &Value::Null, &json!(1)));
    assert_eq!(
        (&sh20["max"], &sh20["lim"], &sh20["payMode"], &sh20["payScript"]),
        (&json!("21000000"), &json!("1000"), &json!(0), &json!(""))
    );
    // a deployed token names its DEPLOY transaction, which /tx knows as such
    let pay2 = list(&tokens).iter().find(|t| t["ticker"] == "PAY2").unwrap();
    assert!(pay2.get("genesis").is_none());
    assert_eq!((&pay2["deployHeight"], &pay2["payMode"]), (&json!(15), &json!(2)));
    let deploy = get(&store, &format!("/tx/{}", text(&pay2["deployTxid"])));
    assert_eq!(
        (&deploy["event"]["type"], &deploy["event"]["ticker"], &deploy["height"]),
        (&json!("DEPLOY"), &json!("PAY2"), &json!(15))
    );

    assert_eq!(status_of(&store, "/token/NONE"), 404);
    assert_eq!(status_of(&store, "/token/sh20"), 400);
    assert_eq!(status_of(&store, "/token/TOOLONG"), 400);
}

/// Every leaf, in tree order: a public note's leaf is recomputed from its opening, and the
/// leaves together give the root of every block.
#[test]
fn notes_roots_and_paths() {
    let v = vectors();
    let store = followed(&v);
    let all = get(&store, "/notes?limit=5000");
    let notes = list(&all["notes"]);
    let total = v["scenario"]["final"]["treeSize"].as_u64().unwrap() as usize;
    assert_eq!((&all["from"], &all["total"]), (&json!(0), &json!(total)));
    assert_eq!(notes.len(), total);

    let after = v["scenario"]["after"].as_array().unwrap();
    let roots = get(&store, "/roots?from=1");
    assert_eq!(list(&roots).len(), 17);
    let mut tree = Tree::new();
    let mut kinds = std::collections::BTreeMap::new();
    for (pos, n) in notes.iter().enumerate() {
        assert_eq!(n["pos"], pos);
        let height = n["height"].as_u64().unwrap() as usize;
        let kind = text(&n["kind"]);
        *kinds.entry(kind).or_insert(0) += 1;
        match kind {
            "OUT" => {
                assert!(n["j"].as_u64().unwrap() < 3);
                assert_eq!((text(&n["pkEph"]).len(), text(&n["ct"]).len()), (64, 56));
            }
            _ => {
                let t = Ticker::parse(text(&n["ticker"])).unwrap().t();
                let leaf = public_leaf(t, text(&n["v"]).parse().unwrap(), &fr(&n["npk"]));
                assert_eq!(fr_hex(&leaf), text(&n["leaf"]), "leaf {pos}");
            }
        }
        // a team note has no transaction; any other note names one that /tx knows at that height
        match kind {
            "TEAM" => assert_eq!(n["txid"], Value::Null),
            _ => {
                let tx = get(&store, &format!("/tx/{}", text(&n["txid"])));
                assert_eq!(tx["height"], n["height"]);
                assert!(list(&tx["notes"]).contains(n));
            }
        }
        tree.append(fr(&n["leaf"]));
        // the root after the last leaf of a block is that block's root, in the vectors too
        if notes.get(pos + 1).is_none_or(|next| next["height"] != n["height"]) {
            assert_eq!(fr_hex(&tree.root()), text(&after[height - 1]["root"]), "root of block {height}");
            assert_eq!(roots[height - 1], json!({ "height": height, "root": after[height - 1]["root"] }));
        }
    }
    // one public note for each MINT, TAKE, CLAIM and team unlock of the vectors; the rest are
    // the outputs of spends, three by three
    let public = [("CLAIM", "CLAIM"), ("MINT", "MINT"), ("TAKE", "TAKE"), ("TEAM", "TEAM_UNLOCK")];
    let mut outs = total;
    for (kind, event) in public {
        assert_eq!(kinds[kind], count_events(&v, event), "{kind}");
        outs -= kinds[kind];
    }
    assert_eq!(kinds["OUT"], outs);
    assert_eq!((kinds.len(), outs % 3), (5, 0));

    // the notes of the first block: two mints of the genesis token, the second of a batch of 2
    assert_eq!((&notes[0]["ticker"], &notes[0]["v"], &notes[1]["v"]), (&json!("SH20"), &json!("1000"), &json!("2000")));
    assert_eq!(notes[0]["leaf"], v["noteLeaf"]["leaf"]);
    assert_eq!(notes[0]["npk"], v["noteLeaf"]["npk"]);

    // pages
    let page = get(&store, "/notes?from=80&limit=3");
    assert_eq!(page, json!({ "from": 80, "total": total, "notes": notes[80..83] }));
    assert_eq!(list(&get(&store, "/notes")["notes"]).len(), total);
    assert_eq!(list(&get(&store, &format!("/notes?from={}", total - 2))["notes"]).len(), 2);
    assert_eq!(get(&store, "/notes?from=500"), json!({ "from": total, "total": total, "notes": [] }));
    assert_eq!(list(&get(&store, "/notes?limit=0")["notes"]).len(), 0);
    assert_eq!(list(&get(&store, "/notes?limit=999999")["notes"]).len(), total);
    for bad in ["/notes?from=-1", "/notes?limit=x", "/notes?from=", "/notes?from", "/notes?limit=1.5"] {
        assert_eq!(status_of(&store, bad), 400, "{bad}");
    }
    // a parameter the route does not know is ignored; of one given twice, the first counts
    assert_eq!(get(&store, "/notes?from=80&limit=3&t=1700000000&from=2"), page);

    // a path: 32 siblings from the leaf up, which fold to the current root
    let root = get(&store, "/status")["root"].clone();
    for pos in [0, 1, 2, 41, total as u64 - 2, total as u64 - 1] {
        let path = get(&store, &format!("/path/{pos}"));
        assert_eq!((&path["pos"], &path["height"], &path["root"]), (&json!(pos), &json!(17), &root));
        let siblings = list(&path["siblings"]);
        assert_eq!(siblings.len(), 32);
        let mut node = fr(&notes[pos as usize]["leaf"]);
        for (level, sibling) in siblings.iter().enumerate() {
            node = if (pos >> level) & 1 == 0 { h2(&node, &fr(sibling)) } else { h2(&fr(sibling), &node) };
        }
        assert_eq!(json!(fr_hex(&node)), root, "path of leaf {pos}");
    }
    assert_eq!(status_of(&store, &format!("/path/{total}")), 404);
    assert_eq!(status_of(&store, "/path/x"), 400);

    // roots: from the anchor window by default (W = 12 here), from the activation block at most
    let default = get(&store, "/roots");
    assert_eq!(list(&default).first().unwrap()["height"], 17 - 12);
    assert_eq!(list(&default).len(), 13);
    assert_eq!(get(&store, "/roots?from=0"), roots);
    assert_eq!(get(&store, "/roots?from=17"), json!([{ "height": 17, "root": root }]));
    assert_eq!(get(&store, "/roots?from=18"), json!([]));
}

#[test]
fn nullifiers() {
    let v = vectors();
    let store = followed(&v);
    let all = get(&store, "/nullifiers");
    assert_eq!((&all["from"], &all["height"]), (&json!(1), &json!(17)));
    let spent = list(&all["nullifiers"]);
    // the two nullifiers of every verifier call but the one refused, in the order of the calls
    let calls = v["scenario"]["verifierCalls"].as_array().unwrap();
    let refused_proof =
        &v["scenario"]["rejected"].as_array().unwrap().iter().find(|r| r["reason"] == "invalid proof").unwrap()["txid"];
    let mut want = Vec::new();
    for c in calls.iter().filter(|c| !(c["txid"] == *refused_proof && c["envelope"] == 0)) {
        for i in [1, 2] {
            want.push(json!({ "height": c["height"], "nullifier": c["publicInputs"][i] }));
        }
    }
    assert_eq!(spent, &want);
    assert_eq!(spent.len(), 2 * (calls.len() - 1));

    for n in spent {
        let one = get(&store, &format!("/nullifier/{}", text(&n["nullifier"])));
        assert_eq!(one, json!({ "nullifier": n["nullifier"], "spent": true }));
    }
    // the second nullifier of the refused proof was never spent
    let unspent =
        calls.iter().find(|c| c["txid"] == *refused_proof && c["envelope"] == 0).unwrap()["publicInputs"][2].clone();
    assert_eq!(get(&store, &format!("/nullifier/{}", text(&unspent)))["spent"], false);
    assert_eq!(status_of(&store, "/nullifier/abcd"), 400);

    // from a block on
    let late = get(&store, "/nullifiers?from=17");
    assert_eq!(late["from"], 17);
    assert!(!list(&late["nullifiers"]).is_empty());
    assert!(list(&late["nullifiers"]).iter().all(|n| n["height"] == 17));
    let before_17 = spent.iter().filter(|n| n["height"] != 17).count();
    assert_eq!(list(&late["nullifiers"])[..], spent[before_17..]);
    assert_eq!(list(&get(&store, "/nullifiers?from=18")["nullifiers"]).len(), 0);
    assert_eq!(get(&store, "/nullifiers?from=0")["nullifiers"], all["nullifiers"]);
}

#[test]
fn listings() {
    let v = vectors();
    let store = followed(&v);
    let all = get(&store, "/listings");
    let want = v["scenario"]["final"]["listings"].as_object().unwrap();
    assert_eq!(list(&all).len(), want.len());
    let mut last_height = 0;
    for l in list(&all) {
        let txid = text(&l["txid"]);
        assert_eq!(l["state"], want[txid], "{txid}");
        assert_eq!(get(&store, &format!("/listing/{txid}")), *l);
        // in LIST order, each one from the LIST event of its transaction
        let height = l["height"].as_u64().unwrap();
        assert!(height >= last_height);
        last_height = height;
        let tx = get(&store, &format!("/tx/{txid}"));
        let e = &tx["event"];
        assert_eq!((&e["type"], &tx["height"]), (&json!("LIST"), &l["height"]));
        for key in ["ticker", "amount", "price"] {
            assert_eq!(e[key], l[key], "{key}");
        }
        assert_eq!(text(&l["lockKey"]).len(), 64);
        assert!(!text(&l["payScript"]).is_empty());
    }
    // the first listing is the one whose envelope the codec test reads field by field
    let first = &list(&all)[0];
    assert_eq!(
        (&first["ticker"], &first["amount"], &first["price"], &first["lockVout"]),
        (&json!("SH20"), &json!("1000"), &json!("5000"), &json!(0))
    );
    assert_eq!(first["lockKey"], "abdc60eb9a25f0d97db71b0fc34b8f9fdb6bed43d241e4b2dffad16bf8d07311");
    assert_eq!(first["payScript"], "00149350872d712a127c494d7dc35e46b0bc9e62e288");

    let mut seen = 0;
    for state in ["ACTIVE", "SOLD", "CANCELLED", "CLOSED", "CLAIMED"] {
        let some = get(&store, &format!("/listings?state={state}"));
        assert!(list(&some).iter().all(|l| l["state"] == state));
        assert_eq!(list(&some).len(), want.values().filter(|s| *s == state).count(), "{state}");
        seen += list(&some).len();
    }
    assert_eq!(seen, want.len());
    assert_eq!(status_of(&store, "/listings?state=active"), 400);
    assert_eq!(status_of(&store, &format!("/listing/{}", unknown_txid())), 404);
    assert_eq!(status_of(&store, "/listing/xyz"), 400);
}

/// `/block/:height`, `/blocks` and `/digest/:height` against the vectors' `after`.
#[test]
fn blocks_and_digests() {
    let v = vectors();
    let store = followed(&v);
    let after = v["scenario"]["after"].as_array().unwrap();
    let rejected = v["scenario"]["rejected"].as_array().unwrap();
    let mut leaves = 0;
    for a in after {
        let h = a["height"].as_u64().unwrap();
        let b = get(&store, &format!("/block/{h}"));
        for key in ["height", "root", "digest", "eventsH"] {
            assert_eq!(b[key], a[key], "{key} of block {h}");
        }
        assert_eq!(b["hash"], block_hash(h as u32, 0));
        let types: Vec<&Value> = list(&b["events"]).iter().map(|e| &e["type"]).collect();
        assert_eq!(types, list(&a["events"]).iter().collect::<Vec<_>>(), "events of block {h}");
        // the refusals of the vectors for this block, with the index of the envelope in a batch
        let want: Vec<(&Value, &Value)> =
            rejected.iter().filter(|r| r["height"] == h).map(|r| (&r["txid"], &r["envelope"])).collect();
        let got: Vec<(&Value, &Value)> = list(&b["rejected"]).iter().map(|r| (&r["txid"], &r["envelope"])).collect();
        assert_eq!(got, want, "refusals of block {h}");
        assert!(list(&b["rejected"]).iter().all(|r| r["reason"].is_string()));
        // leaves: the size of the tree after the block
        let notes = get(&store, "/notes?limit=5000");
        leaves += list(&notes["notes"]).iter().filter(|n| n["height"] == h).count();
        assert_eq!(b["leaves"], leaves, "leaves after block {h}");
        assert_eq!(get(&store, &format!("/digest/{h}")), json!({ "height": h, "digest": a["digest"] }));
    }
    for missing in ["/block/0", "/block/18", "/digest/0", "/digest/18"] {
        assert_eq!(status_of(&store, missing), 404, "{missing}");
    }
    assert_eq!(status_of(&store, "/block/latest"), 400);

    // the events carry the fields of their record in the digest
    let b1 = get(&store, "/block/1");
    assert_eq!(
        b1["events"][0],
        json!({ "type": "GENESIS", "ticker": "SH20", "max": "21000000", "lim": "1000", "deployBurn": "1000",
                "anchorWindow": 12, "anchorMinDepth": 1, "deployMaturity": 3 })
    );
    assert_eq!(b1["events"][1]["type"], "MINT");
    assert_eq!(
        (&b1["events"][1]["ticker"], &b1["events"][1]["v"], &b1["events"][1]["pos"]),
        (&json!("SH20"), &json!("1000"), &json!(0))
    );
    let b17 = get(&store, "/block/17");
    assert_eq!(b17["events"][0]["type"], "TEAM_UNLOCK");
    assert!(b17["events"][0].get("txid").is_none());
    let closed = list(&b17["events"]).last().unwrap();
    assert_eq!(closed["type"], "CLOSED");
    assert_eq!(get(&store, &format!("/listing/{}", text(&closed["listTxid"])))["state"], "CLOSED");

    // /blocks: newest first, 20 by default; every block of the scenario has an event or a refusal
    let newest = get(&store, "/blocks");
    assert_eq!(list(&newest).len(), 17);
    assert_eq!(list(&newest)[0], b17);
    assert_eq!(list(&newest)[16], b1);
    let page = get(&store, "/blocks?before=17&limit=2");
    assert_eq!(list(&page).iter().map(|b| b["height"].as_u64().unwrap()).collect::<Vec<_>>(), [16, 15]);
    assert_eq!(get(&store, "/blocks?before=1"), json!([]));
    assert_eq!(list(&get(&store, "/blocks?limit=5000")).len(), 17);
    assert_eq!(status_of(&store, "/blocks?before=x"), 400);
}

/// A block with no envelope in it is a block all the same for `/block`, `/digest` and
/// `/roots`, and is left out of `/blocks`.
#[test]
fn blocks_with_no_activity() {
    let v = vectors();
    let mut blocks = scenario(&v, true);
    blocks.truncate(1);
    for height in 2..=4 {
        let mut b = blocks[0].clone();
        b.prev = block_hash(height - 1, 0);
        b.hash = block_hash(height, 0);
        b.block.height = height;
        b.block.txs.truncate(1); // its coinbase
        blocks.push(b);
    }
    let (mut f, store) = follower(&v, Chain::new(blocks));
    f.catch_up().unwrap();
    let quiet = get(&store, "/block/3");
    assert_eq!((&quiet["events"], &quiet["rejected"], &quiet["eventsH"]), (&json!([]), &json!([]), &json!("")));
    assert_eq!(quiet["root"], get(&store, "/block/1")["root"]);
    assert_ne!(quiet["digest"], get(&store, "/block/2")["digest"]);
    assert_eq!(list(&get(&store, "/roots?from=1")).len(), 4);
    assert_eq!(list(&get(&store, "/blocks")).iter().map(|b| b["height"].as_u64().unwrap()).collect::<Vec<_>>(), [1]);
    assert_eq!(get(&store, "/status")["height"], 4);
}

/// `/tx/:txid`: one envelope has one verdict; a batch has one for each envelope and none for
/// the whole.
#[test]
fn transactions() {
    let v = vectors();
    let store = followed(&v);
    let b17 = &v["scenario"]["blocks"][16]["txs"];
    let rejected = v["scenario"]["rejected"].as_array().unwrap();

    // the first batch of block 17: envelopes 0 and 2 accepted, 1 refused
    let txid = text(&b17[0]["txid"]);
    let tx = get(&store, &format!("/tx/{txid}"));
    assert_eq!(
        (&tx["txid"], &tx["height"], &tx["event"], &tx["rejected"]),
        (&json!(txid), &json!(17), &Value::Null, &Value::Null)
    );
    let events = list(&tx["events"]);
    assert_eq!(
        events.iter().map(|e| (&e["type"], &e["envelope"])).collect::<Vec<_>>(),
        [(&json!("TRANSFER"), &json!(0)), (&json!("TRANSFER"), &json!(2))]
    );
    assert!(events.iter().all(|e| e["txid"] == txid && list(&e["nullifiers"]).len() == 2));
    assert_eq!(list(&tx["rejections"]).len(), 1);
    assert_eq!(tx["rejections"][0]["envelope"], 1);
    assert!(tx["rejections"][0]["reason"].is_string());
    // six notes, three for each accepted envelope, at the positions the events give
    let notes = list(&tx["notes"]);
    assert_eq!(
        notes.iter().map(|n| (n["envelope"].as_u64().unwrap(), n["j"].as_u64().unwrap())).collect::<Vec<_>>(),
        [(0, 0), (0, 1), (0, 2), (2, 0), (2, 1), (2, 2)]
    );
    let positions: Vec<&Value> = events.iter().flat_map(|e| list(&e["pos"])).collect();
    assert_eq!(notes.iter().map(|n| &n["pos"]).collect::<Vec<_>>(), positions);
    assert!(notes.iter().all(|n| n["kind"] == "OUT" && n["txid"] == txid && n["height"] == 17));

    // the batch that spends a lock: two TRANSFERs, then CLOSED, which belongs to no envelope
    let txid = text(&b17[4]["txid"]);
    let tx = get(&store, &format!("/tx/{txid}"));
    assert_eq!(
        list(&tx["events"]).iter().map(|e| (&e["type"], &e["envelope"])).collect::<Vec<_>>(),
        [(&json!("TRANSFER"), &json!(0)), (&json!("TRANSFER"), &json!(1)), (&json!("CLOSED"), &Value::Null)]
    );
    assert_eq!((&tx["event"], &tx["rejected"], &tx["rejections"]), (&Value::Null, &Value::Null, &json!([])));

    // a TRANSFER alone: one event, no index
    let txid = text(&b17[2]["txid"]);
    let tx = get(&store, &format!("/tx/{txid}"));
    assert_eq!((&tx["event"]["type"], &tx["rejected"]), (&json!("TRANSFER"), &Value::Null));
    assert!(tx["event"].get("envelope").is_none());
    assert_eq!(tx["events"], json!([tx["event"]]));
    assert_eq!(list(&tx["notes"]).len(), 3);
    assert!(list(&tx["notes"]).iter().all(|n| n.get("envelope").is_none()));

    // every refusal outside a batch: the reason, no event, no note
    let mut closing = 0;
    for r in rejected.iter().filter(|r| r.get("envelope").is_none()) {
        let tx = get(&store, &format!("/tx/{}", text(&r["txid"])));
        assert_eq!((&tx["height"], &tx["event"], &tx["notes"]), (&r["height"], &Value::Null, &json!([])));
        assert!(tx["rejected"].is_string());
        assert_eq!(tx["rejections"], json!([{ "reason": tx["rejected"] }]));
        // a refused transaction still closes the listing whose lock it spends (two of block
        // 13 do): the CLOSED is among its events, and is not a verdict on its envelope
        assert!(list(&tx["events"]).iter().all(|e| e["type"] == "CLOSED"));
        closing += list(&tx["events"]).len();
    }
    assert!(closing >= 1);

    // a MINT: its note is public
    let mint = &v["scenario"]["blocks"][0]["txs"][0]["txid"];
    let tx = get(&store, &format!("/tx/{}", text(mint)));
    assert_eq!(tx["event"]["type"], "MINT");
    assert_eq!(
        (&tx["notes"][0]["kind"], &tx["notes"][0]["pos"], &tx["notes"][0]["npk"]),
        (&json!("MINT"), &json!(0), &v["noteLeaf"]["npk"])
    );

    // the transaction of block 10 that spends a lock and carries nothing: no verdict, one event
    let bare =
        get(&store, "/block/10")["events"].as_array().unwrap().iter().find(|e| e["type"] == "CLOSED").unwrap().clone();
    let tx = get(&store, &format!("/tx/{}", text(&bare["txid"])));
    assert_eq!((&tx["event"], &tx["rejected"], &tx["notes"]), (&Value::Null, &Value::Null, &json!([])));
    assert_eq!((&tx["events"], &tx["rejections"]), (&json!([bare]), &json!([])));

    // a transaction that carries nothing is not an SH-20 transaction
    assert_eq!(status_of(&store, &format!("/tx/{}", hex(&noise_txid(4, 1)))), 404);
    assert_eq!(status_of(&store, &format!("/tx/{}", unknown_txid())), 404);
    assert_eq!(status_of(&store, "/tx/1234"), 400);
}

#[test]
fn only_get_and_only_the_routes() {
    let v = vectors();
    let store = followed(&v);
    let read = store.read().unwrap();
    for method in ["POST", "PUT", "DELETE", "HEAD", "PATCH"] {
        assert_eq!(read.respond(method, "/status").status, 405, "{method}");
    }
    for target in ["/nothing", "/status/extra", "/tokens/SH20", "/block", "/tx", "/notes/1", "//x//"] {
        let r = read.respond("GET", target);
        assert_eq!(r.status, 404, "{target}");
        assert!(r.body["error"].is_string());
    }
    for target in ["/status?x=1", "/tokens?from=1", "/block/1?verbose=1", "/status?", "/status/", "/status?&&"] {
        assert_eq!(read.respond("GET", target).status, 200, "{target}");
    }
    // the index names every route
    let index = read.respond("GET", "/");
    assert_eq!(index.status, 200);
    assert_eq!(index.body["routes"].as_array().unwrap().len(), 14);
}
