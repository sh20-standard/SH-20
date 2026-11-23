//! The `replay` command over a folder of `getblock <hash> 2` files: the vectors' scenario,
//! written the way Bitcoin Core prints blocks, must give the vectors' digests.

use serde_json::{json, Value};
use std::process::Command;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A scenario block as `getblock <hash> 3` prints it: amounts in BTC, `txinwitness`,
/// `scriptPubKey.hex`, `prevout.height` where the vectors give a height, and a coinbase first.
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
            .map(|i| {
                let mut vin = json!({"txid": i["txid"], "vout": i["vout"], "scriptSig": {"hex": ""}, "txinwitness": i["witness"], "sequence": 4294967293u32});
                // verbosity 3: the spent output, with the height of its block
                if let Some(h) = i.get("prevHeight") {
                    vin["prevout"] = json!({"generated": false, "height": h, "value": 0.00001000, "scriptPubKey": {"hex": "5120"}});
                }
                vin.to_string()
            })
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
    let (ok, stdout, stderr) = replay(
        &dir,
        &["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--maturity", "3", "--verifier", "test"],
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout.lines().collect::<Vec<_>>(), want);
    assert!(stderr.contains("A = 1, D = 1000, W = 12, K_min = 1, N = 3"));

    // --json gives what the vectors give for each block
    let (ok, stdout, _) = replay(
        &dir,
        &[
            "--activation",
            "1",
            "--deploy-burn",
            "1000",
            "--window",
            "12",
            "--maturity",
            "3",
            "--verifier",
            "test",
            "--json",
        ],
    );
    assert!(ok);
    let lines: Vec<Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 17);
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
        // in a batch, the index of the refused envelope
        assert_eq!(got.get("envelope"), want.get("envelope"));
    }
    assert_eq!(refused.iter().filter(|r| r.get("envelope").is_some()).count(), 3);

    // without a verifier every spend is refused: the digests leave the vectors' at block 2
    let (ok, stdout, _) =
        replay(&dir, &["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--maturity", "3"]);
    assert!(ok);
    let got: Vec<&str> = stdout.lines().collect();
    assert_eq!(got[0], want[0]);
    assert_ne!(got[1], want[1]);

    // another N: the GENESIS record differs, and so does every digest
    let (ok, stdout, _) =
        replay(&dir, &["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--verifier", "test"]);
    assert!(ok);
    assert_ne!(stdout.lines().next().unwrap(), want[0]);

    // blocks without prevout.height (verbosity 2): the replay stops at the first DEPLOY
    // revealed in a witness, here in block 4, and says what it needs
    let no_heights = dir.with_file_name("replay-vectors-verbosity-2");
    let _ = std::fs::remove_dir_all(&no_heights);
    std::fs::create_dir_all(&no_heights).unwrap();
    for b in sc["blocks"].as_array().unwrap() {
        let mut b = b.clone();
        for tx in b["txs"].as_array_mut().unwrap() {
            for vin in tx["vin"].as_array_mut().unwrap() {
                vin.as_object_mut().unwrap().remove("prevHeight");
            }
        }
        std::fs::write(no_heights.join(format!("{}.json", b["height"])), getblock_json(&b)).unwrap();
    }
    let (ok, stdout, stderr) = replay(
        &no_heights,
        &["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--maturity", "3", "--verifier", "test"],
    );
    assert!(!ok);
    assert_eq!(stdout.lines().collect::<Vec<_>>(), want[..3]);
    assert!(stderr.contains("block 4") && stderr.contains("getblock <hash> 3"), "{stderr}");

    // a missing block stops the replay
    std::fs::remove_file(dir.join("block-95.json")).unwrap();
    let (ok, stdout, stderr) = replay(
        &dir,
        &["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--maturity", "3", "--verifier", "test"],
    );
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

/// `indexer/vectors/plonk-v0.3.json` as `getblock` files, under the real verifier: the digests
/// of the vectors. Under `reject-all` the command parts with them at block 3, the first block
/// with a valid proof.
#[test]
fn replay_checks_real_proofs() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/plonk-v0.3.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("replay-plonk");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for b in v["blocks"].as_array().unwrap() {
        std::fs::write(dir.join(format!("{}.json", b["height"])), getblock_json(b)).unwrap();
    }
    let want: Vec<String> = v["after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| format!("{} {}", a["height"], a["digest"].as_str().unwrap()))
        .collect();
    let profile = ["--activation", "1", "--deploy-burn", "0", "--maturity", "0"];

    let (ok, stdout, stderr) = replay(&dir, &[&profile[..], &["--verifier", "plonk-bn254-hermez"]].concat());
    assert!(ok, "{stderr}");
    assert_eq!(stdout.lines().collect::<Vec<_>>(), want);
    assert!(stderr.contains("verifier = plonk-bn254-hermez"), "{stderr}");

    // --json: the refusals of the vectors, and no other
    let (ok, stdout, _) = replay(&dir, &[&profile[..], &["--verifier", "plonk-bn254-hermez", "--json"]].concat());
    assert!(ok);
    let lines: Vec<Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let refused: Vec<(&Value, &Value)> = lines
        .iter()
        .flat_map(|l| l["rejected"].as_array().unwrap().iter().map(|r| (&l["height"], &r["txid"])))
        .collect();
    let want_refused: Vec<(&Value, &Value)> =
        v["rejected"].as_array().unwrap().iter().map(|r| (&r["height"], &r["txid"])).collect();
    assert_eq!(refused, want_refused);

    let (ok, stdout, stderr) = replay(&dir, &profile);
    assert!(ok, "{stderr}");
    let got: Vec<&str> = stdout.lines().collect();
    assert_eq!(got[..2], want[..2]);
    assert!(got[2..].iter().zip(&want[2..]).all(|(g, w)| g != w));
    assert!(stderr.contains("verifier = reject-all"), "{stderr}");
}
