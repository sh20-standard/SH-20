//! The `replay` command over a folder of `getblock <hash> 2` files: the vectors' scenario,
//! written the way Bitcoin Core prints blocks, must give the vectors' digests.

use serde_json::{json, Value};
use std::process::Command;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A scenario block as `getblock <hash> 2` prints it: amounts in BTC, `txinwitness`,
/// `scriptPubKey.hex`, and a coinbase first.
fn getblock_json(b: &Value) -> String {
    let height = b["height"].as_u64().unwrap();
    let mut txs = vec![format!(
        r#"{{"txid":"{:064x}","vin":[{{"coinbase":"01{:02x}","txinwitness":["{}"],"sequence":4294967295}}],"vout":[{{"value":50.00000000,"n":0,"scriptPubKey":{{"hex":"5120{}","type":"witness_v1_taproot"}}}},{{"value":0.00000000,"n":1,"scriptPubKey":{{"hex":"6a24aa21a9ed{}","type":"nulldata"}}}}]}}"#,
        height,
        height,
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(32)
    )];
    for t in b["txs"].as_array().unwrap() {
        let vin: Vec<String> = t["vin"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| json!({"txid": i["txid"], "vout": i["vout"], "scriptSig": {"hex": ""}, "txinwitness": i["witness"], "sequence": 4294967293u32}).to_string())
            .collect();
        let vout: Vec<String> = t["vout"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(n, o)| {
                let sats: u64 = o["value"].as_str().unwrap().parse().unwrap();
                format!(
                    r#"{{"value":{}.{:08},"n":{},"scriptPubKey":{{"asm":"","hex":{}}}}}"#,
                    sats / 100_000_000,
                    sats % 100_000_000,
                    n,
                    o["script"]
                )
            })
            .collect();
        txs.push(format!(
            r#"{{"txid":{},"hash":{},"vin":[{}],"vout":[{}]}}"#,
            t["txid"],
            t["txid"],
            vin.join(","),
            vout.join(",")
        ));
    }
    format!(
        r#"{{"hash":"{:064x}","confirmations":1,"height":{},"tx":[{}]}}"#,
        0xb10c_0000 + height,
        height,
        txs.join(",")
    )
}

fn replay(dir: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sh20-indexer-rs")).arg("replay").arg(dir).args(args).output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

#[test]
fn replay_prints_the_vectors_digests() {
    let v = vectors();
    let sc = &v["scenario"];
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("replay-vectors");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // file names carry no order: the heights inside do
    for b in sc["blocks"].as_array().unwrap() {
        let h = b["height"].as_u64().unwrap();
        std::fs::write(dir.join(format!("block-{:02}.json", 99 - h)), getblock_json(b)).unwrap();
    }
    // a block before activation is not read, and a file that is not JSON is not a block
    std::fs::write(dir.join("zero.json"), getblock_json(&json!({"height": 0, "txs": sc["blocks"][0]["txs"]}))).unwrap();
    std::fs::write(dir.join("README.txt"), "not a block").unwrap();

    let want: Vec<String> = sc["after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| format!("{} {}", a["height"], a["digest"].as_str().unwrap()))
        .collect();
    let (ok, stdout, stderr) = replay(&dir, &["--activation", "1", "--deploy-burn", "1000", "--verifier", "test"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.lines().collect::<Vec<_>>(), want);
    assert!(stderr.contains("A = 1, D = 1000, W = 100, K_min = 1"));

    // --json gives what the vectors give for each block
    let (ok, stdout, _) = replay(&dir, &["--activation", "1", "--deploy-burn", "1000", "--verifier", "test", "--json"]);
    assert!(ok);
    let lines: Vec<Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 13);
    for (got, a) in lines.iter().zip(sc["after"].as_array().unwrap()) {
        for key in ["height", "root", "events", "eventsH", "digest"] {
            assert_eq!(got[key], a[key], "{key} of block {}", a["height"]);
        }
    }
    let refused: Vec<&Value> = lines.iter().flat_map(|l| l["rejected"].as_array().unwrap()).collect();
    let want_refused = sc["rejected"].as_array().unwrap();
    assert_eq!(refused.len(), want_refused.len());
    for (got, want) in refused.iter().zip(want_refused) {
        assert_eq!(got["txid"], want["txid"]);
    }

    // without a verifier every spend is refused: the digests leave the vectors' at block 2
    let (ok, stdout, _) = replay(&dir, &["--activation", "1", "--deploy-burn", "1000"]);
    assert!(ok);
    let got: Vec<&str> = stdout.lines().collect();
    assert_eq!(got[0], want[0]);
    assert_ne!(got[1], want[1]);

    // a missing block stops the replay
    std::fs::remove_file(dir.join("block-95.json")).unwrap();
    let (ok, stdout, stderr) = replay(&dir, &["--activation", "1", "--deploy-burn", "1000", "--verifier", "test"]);
    assert!(!ok);
    assert_eq!(stdout.lines().count(), 3);
    assert!(stderr.contains("expected block 4, got block 5"), "{stderr}");
}

#[test]
fn replay_refuses_bad_arguments() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("replay-empty");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(!replay(&dir, &[]).0);
    assert!(!replay(&dir, &["--verifier", "plonk"]).0);
    assert!(!replay(&dir, &["--activation"]).0);
    assert!(!replay(&dir, &["--frobnicate"]).0);
}
