//! The two sources and the HTTP server over real sockets, on local ports: the vectors'
//! scenario served as Bitcoin Core's RPC and as an Esplora API, and the `follow` command
//! from its first block to a reorg and a restart.

mod common;

use common::fake::*;
use serde_json::{json, Value};
use sh20_indexer::follow::{FollowError, Source, SourceError, Step};
use sh20_indexer::sources::{basic_auth, CoreRpc, Esplora, Http};
use sh20_indexer::state::needs_commit_height;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn last_digest(v: &Value, part: &str) -> String {
    v[part]["after"].as_array().unwrap().last().unwrap()["digest"].as_str().unwrap().to_string()
}

/// Bitcoin Core: `getblockhash`, `getblock <hash> 3` with `prevout.height`, and the reorg.
#[test]
fn bitcoin_core_rpc() {
    let v = vectors();
    let chain = Chain::new(scenario(&v, true));
    let auth = basic_auth("sh20", "p4ss:word");
    let url = http_server(core_rpc(chain.clone(), Some(auth.clone()), true));

    let mut source = CoreRpc::new(&url, Some(auth.clone()));
    assert_eq!(source.network(), Ok(Some("signet".to_string())));
    assert_eq!(source.hash_at(17), Ok(Some(block_hash(17, 0))));
    assert_eq!(source.hash_at(18), Ok(None));
    let b = source.block(&block_hash(4, 0)).unwrap();
    assert_eq!((b.block.height, b.prev.clone(), b.hash.clone()), (4, block_hash(3, 0), block_hash(4, 0)));
    // the block as the chain holds it, amounts back from BTC to satoshis
    assert_eq!(b, chain.state().blocks[3]);
    assert!(matches!(source.block(&block_hash(4, 7)), Err(SourceError::Later(m)) if m.contains("Block not found")));

    let same = follower(&v, Chain::new(scenario(&v, true)));
    let (mut f, store) = follower(&v, source);
    f.catch_up().unwrap();
    assert_eq!(get(&store, "/status")["digest"], last_digest(&v, "scenario"));
    {
        let (mut memory, memory_store) = same;
        memory.catch_up().unwrap();
        assert_eq!(dump(&store), dump(&memory_store));
    }
    chain.set(reorged(&v, true));
    f.catch_up().unwrap();
    assert_eq!(get(&store, "/status")["digest"], last_digest(&v, "reorg"));

    // the node is busy: asked again later, nothing lost
    chain.state().down = true;
    assert!(matches!(f.step(), Err(FollowError::Later(m)) if m.contains("503")));
    chain.state().down = false;
    assert_eq!(f.step(), Ok(Step::AtTip));

    // wrong credentials, or none: no point in asking again
    for bad in [Some(basic_auth("sh20", "wrong")), None] {
        let mut source = CoreRpc::new(&url, bad);
        assert!(matches!(source.hash_at(1), Err(SourceError::Fatal(m)) if m.contains("credentials")));
    }
    // nobody listens: the node is down, to be asked again
    let mut down = CoreRpc::new(&dead_url(), None);
    assert!(matches!(down.hash_at(1), Err(SourceError::Later(_))));
    let (mut f, store) = follower(&v, down);
    assert!(matches!(f.step(), Err(FollowError::Later(_))));
    assert_eq!(get(&store, "/status")["height"], Value::Null);
}

/// A node that answers without `prevout.height` (no undo data for the block): the follower
/// stops at the first DEPLOY revealed, in block 4 (SPEC-WIRE §5).
#[test]
fn bitcoin_core_without_prevout_heights() {
    let v = vectors();
    let url = http_server(core_rpc(Chain::new(scenario(&v, true)), None, false));
    let (mut f, store) = follower(&v, CoreRpc::new(&url, None));
    let stopped = loop {
        match f.step() {
            Ok(_) => {}
            Err(e) => break e,
        }
    };
    assert!(matches!(stopped, FollowError::Fatal(m) if m.contains("block 4") && m.contains("prevout.height")));
    assert_eq!(get(&store, "/status")["height"], 3);
}

/// Esplora: blocks page by page, and the height of a DEPLOY's commit from the status of the
/// transaction it spends, asked only where §5 needs it.
#[test]
fn esplora_api() {
    let v = vectors();
    // 60 transactions more in block 9: three pages and a bit
    let chain = Chain::new(padded(scenario(&v, true), 9, 60));
    let url = http_server(esplora(chain.clone()));
    let mut source = Esplora::new(&format!("{url}/"));
    assert_eq!(source.network(), Ok(None));
    assert_eq!(source.hash_at(17), Ok(Some(block_hash(17, 0))));
    assert_eq!(source.hash_at(18), Ok(None));
    let b9 = source.block(&block_hash(9, 0)).unwrap();
    assert!(b9.block.txs.len() > 60);
    assert_eq!(b9, chain.state().blocks[8]);
    assert_eq!(chain.state().fetched, [9, 9, 9]);
    assert!(matches!(source.block(&block_hash(9, 7)), Err(SourceError::Later(_))));

    // a height was asked for each DEPLOY in a witness that decodes, and for nothing else
    let wanted: usize =
        chain.state().blocks.iter().flat_map(|b| b.block.txs.iter()).filter(|t| needs_commit_height(t)).count();
    assert!(wanted >= 4);
    let (mut f, store) = follower(&v, source);
    f.catch_up().unwrap();
    assert_eq!(chain.state().status_calls, wanted);
    assert_eq!(get(&store, "/status")["digest"], last_digest(&v, "scenario"));
    let (mut memory, memory_store) = follower(&v, Chain::new(scenario(&v, true)));
    memory.catch_up().unwrap();
    assert_eq!(dump(&store), dump(&memory_store));

    chain.set(reorged(&v, true));
    f.catch_up().unwrap();
    assert_eq!(get(&store, "/status")["digest"], last_digest(&v, "reorg"));

    // the API refuses for a while (429): asked again later
    chain.state().down = true;
    assert!(matches!(f.step(), Err(FollowError::Later(m)) if m.contains("429")));
    chain.state().down = false;
    assert_eq!(f.step(), Ok(Step::AtTip));
}

/// A commit that Esplora does not show as confirmed (a reorg under way): not a refusal, not a
/// stop, a question to ask again.
#[test]
fn esplora_commit_not_confirmed() {
    let v = vectors();
    let mut blocks = scenario(&v, false);
    for tx in &mut blocks[3].block.txs {
        tx.vin[0].prev_height = None; // the fake API then answers {"confirmed": false}
    }
    let url = http_server(esplora(Chain::new(blocks)));
    let (mut f, store) = follower(&v, Esplora::new(&url));
    for height in 1..=3 {
        assert_eq!(f.step(), Ok(Step::Applied(height)));
    }
    assert!(matches!(f.step(), Err(FollowError::Later(m)) if m.contains("not confirmed")));
    assert_eq!(get(&store, "/status")["height"], 3);
}

// ---------------------------------------------------------------- the command

struct Running {
    child: Child,
    url: String,
    stderr: std::sync::mpsc::Receiver<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `sh20-indexer-rs follow` on a free port and waits for its "listening" line.
fn start(args: &[&str]) -> Running {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sh20-indexer-rs"))
        .arg("follow")
        .args(args)
        .args(["--listen", "127.0.0.1:0", "--poll", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, stderr) = std::sync::mpsc::channel();
    let pipe = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut running = Running { child, url: String::new(), stderr };
    let mut seen = Vec::new();
    while let Ok(line) = running.stderr.recv_timeout(Duration::from_secs(30)) {
        if let Some(url) = line.strip_prefix("listening on ") {
            running.url = url.to_string();
            return running;
        }
        seen.push(line);
    }
    panic!("the command did not start listening: {seen:?}");
}

fn http_get(url: &str) -> (u16, Value) {
    let (status, body) = Http::new().get(url).unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// Asks `/status` until `done` says yes.
fn wait_for(running: &Running, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    let start = Instant::now();
    loop {
        let (status, body) = http_get(&format!("{}/status", running.url));
        assert_eq!(status, 200);
        if done(&body) {
            return body;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "{what}: still {body}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One raw request: the status line and headers, and the body.
fn raw(url: &str, request: &str) -> (String, String) {
    let mut stream = std::net::TcpStream::connect(url.trim_start_matches("http://")).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    (head.to_string(), body.to_string())
}

/// `follow --rpc` from the first block to the tip, through a reorg, and again after a stop:
/// the API it serves gives the vectors' digests, to any origin, and changes nothing.
#[test]
fn follow_command() {
    let v = vectors();
    let chain = Chain::new(scenario(&v, true)[..12].to_vec());
    let auth = basic_auth("user", "secret");
    let rpc = http_server(core_rpc(chain.clone(), Some(auth), true));
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("follow-command");
    let _ = std::fs::remove_dir_all(&dir);
    let profile =
        ["--activation", "1", "--deploy-burn", "1000", "--window", "12", "--maturity", "3", "--verifier", "test"];
    let source = ["--rpc", rpc.as_str(), "--rpcuser", "user", "--rpcpass", "secret", "--data", dir.to_str().unwrap()];

    let running = start(&[&source[..], &profile[..]].concat());
    let digests = v["scenario"]["after"].as_array().unwrap();
    let s = wait_for(&running, "block 12", |s| s["height"] == 12);
    assert_eq!(s["digest"], digests[11]["digest"]);
    assert_eq!((&s["network"], &s["verifier"], &s["activationHeight"]), (&json!("signet"), &json!("test"), &json!(1)));

    // the chain grows: the follower follows
    chain.set(scenario(&v, true));
    let s = wait_for(&running, "block 17", |s| s["height"] == 17);
    assert_eq!(s["digest"], last_digest(&v, "scenario"));
    let (status, block) = http_get(&format!("{}/block/17", running.url));
    assert_eq!((status, &block["eventsH"]), (200, &digests[16]["eventsH"]));
    assert_eq!(http_get(&format!("{}/tx/{}", running.url, unknown_txid())).0, 404);
    assert_eq!(http_get(&format!("{}/notes?limit=x", running.url)).0, 400);

    // what a browser needs: JSON, any origin, and an answer to its preflight
    let (head, body) = raw(&running.url, "GET /digest/17 HTTP/1.1\r\nHost: x\r\nOrigin: https://example.org\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("Access-Control-Allow-Origin: *") && head.contains("Content-Type: application/json"));
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["digest"], last_digest(&v, "scenario"));
    let (head, body) = raw(&running.url, "OPTIONS /status HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 204") && head.contains("Access-Control-Allow-Origin: *") && body.is_empty());
    // read-only: nothing but GET, and nothing that is not HTTP
    let (head, _) = raw(&running.url, "POST /status HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
    let (head, _) = raw(&running.url, "hello\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    // a reorg: blocks 16 and 17 give way
    chain.set(reorged(&v, true));
    let s = wait_for(&running, "the reorg", |s| s["digest"] == json!(last_digest(&v, "reorg")));
    assert_eq!((&s["height"], &s["hash"]), (&json!(17), &json!(block_hash(17, 1))));
    let reorg_line = Instant::now();
    let mut undone = Vec::new();
    while undone.len() < 2 && reorg_line.elapsed() < Duration::from_secs(10) {
        if let Ok(line) = running.stderr.recv_timeout(Duration::from_secs(1)) {
            undone.extend(line.starts_with("reorg: ").then_some(line));
        }
    }
    assert_eq!(undone, ["reorg: block 17 undone", "reorg: block 16 undone"]);
    let whole = http_get(&format!("{}/notes?limit=5000", running.url)).1;
    drop(running);

    // a restart with the node down: the block file alone gives the state back
    chain.state().down = true;
    chain.state().fetched.clear();
    let running = start(&[&source[..], &profile[..]].concat());
    let s = wait_for(&running, "the block file", |s| s["height"] == 17);
    assert_eq!(s["digest"], last_digest(&v, "reorg"));
    assert_eq!(http_get(&format!("{}/notes?limit=5000", running.url)).1, whole);
    assert!(chain.state().fetched.is_empty());
    // the node comes back with the first chain: the follower finds its way
    chain.set(scenario(&v, true));
    chain.state().down = false;
    wait_for(&running, "the way back", |s| s["digest"] == json!(last_digest(&v, "scenario")));
    assert_eq!(chain.state().fetched, [16, 17]);
}

/// `follow --esplora`, without a block file.
#[test]
fn follow_command_over_esplora() {
    let v = vectors();
    let api = http_server(esplora(Chain::new(scenario(&v, true))));
    let running = start(&[
        "--esplora",
        &api,
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
        "--network",
        "signet-test",
    ]);
    let s = wait_for(&running, "block 17", |s| s["height"] == 17);
    assert_eq!(s["digest"], last_digest(&v, "scenario"));
    assert_eq!(s["network"], "signet-test");
    assert_eq!(http_get(&format!("{}/listings?state=CLOSED", running.url)).1.as_array().unwrap().len(), 4);
}

/// `docs/API.md`: the verifier that refuses every spend is `reject-all` in `/status`, whether
/// it is the default or asked for under either of its names.
#[test]
fn follow_command_names_its_verifier() {
    let v = vectors();
    let api = http_server(esplora(Chain::new(scenario(&v, true))));
    for verifier in [&[][..], &["--verifier", "reject-all"][..], &["--verifier", "reject"][..]] {
        let mut args = vec!["--esplora", api.as_str(), "--activation", "1", "--deploy-burn", "1000"];
        args.extend_from_slice(verifier);
        let running = start(&args);
        let s = wait_for(&running, "block 17", |s| s["height"] == 17);
        assert_eq!((&s["verifier"], &s["genesis"]), (&json!("reject-all"), &json!("SH20")), "{verifier:?}");
        // every spend refused: no nullifier, and not the digest of the vectors
        assert_eq!(s["nullifiers"], 0);
        assert_ne!(s["digest"], last_digest(&v, "scenario"));
    }
}

/// `follow --verifier plonk-bn254-hermez` over the chain of `indexer/vectors/plonk-v0.3.json`:
/// the digests of the vectors, the name `docs/API.md` gives the verifier, and in the API what
/// the accepted spends left.
#[test]
fn follow_command_checks_real_proofs() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/plonk-v0.3.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let api = http_server(esplora(Chain::new(chain_of(&v["blocks"]))));
    // the profile of the vectors: its DEPLOY burns, so `D` is not zero
    let (burn, maturity) = (v["profile"]["deployBurn"].as_str().unwrap(), v["profile"]["deployMaturity"].to_string());
    let args = ["--esplora", api.as_str(), "--activation", "1", "--deploy-burn", burn, "--maturity", maturity.as_str()];
    let running = start(&[&args[..], &["--verifier", "plonk-bn254-hermez"]].concat());
    let after = v["after"].as_array().unwrap();
    let last = after.len();
    let s = wait_for(&running, "the last block", |s| s["height"] == last);
    assert_eq!(s["digest"], after[last - 1]["digest"]);
    assert_eq!(
        (&s["verifier"], &s["nullifiers"], &s["leaves"]),
        (&json!("plonk-bn254-hermez"), &v["final"]["nullifiers"], &v["final"]["treeSize"])
    );
    for a in after {
        let (status, block) = http_get(&format!("{}/block/{}", running.url, a["height"]));
        assert_eq!(status, 200);
        for key in ["root", "digest", "eventsH"] {
            assert_eq!(block[key], a[key], "{key} of block {}", a["height"]);
        }
    }
    for (ticker, key) in [("SH20", "sh20"), ("GENE", "gene")] {
        let token = http_get(&format!("{}/token/{ticker}", running.url)).1;
        let want = &v["final"][key];
        assert_eq!((&token["burned"], &token["pool"]), (&want["burned"], &want["pool"]), "{ticker}");
    }
    // the LIST and the DEPLOY: a listing locked to the key of the vectors, and a spend of three notes each
    for (id, state) in v["final"]["listings"].as_object().unwrap() {
        let listing = http_get(&format!("{}/listing/{id}", running.url)).1;
        assert_eq!((&listing["state"], &listing["lockKey"]), (state, &v["lockKey"]));
    }
    for (call, kind) in [(4, "LIST"), (6, "DEPLOY")] {
        let txid = v["verifierCalls"][call]["txid"].as_str().unwrap();
        let tx = http_get(&format!("{}/tx/{txid}", running.url)).1;
        assert_eq!(
            (&tx["event"]["type"], &tx["rejected"], tx["notes"].as_array().unwrap().len()),
            (&json!(kind), &Value::Null, 3)
        );
    }
    // the tampered TRANSFER: refused, and the good one of the same block accepted
    let refused = v["rejected"][0]["txid"].as_str().unwrap();
    let tx = http_get(&format!("{}/tx/{refused}", running.url)).1;
    assert_eq!((&tx["event"], tx["rejected"].is_string()), (&Value::Null, true));
    let accepted = v["verifierCalls"][1]["txid"].as_str().unwrap();
    let tx = http_get(&format!("{}/tx/{accepted}", running.url)).1;
    assert_eq!(
        (&tx["event"]["type"], &tx["rejected"], tx["notes"].as_array().unwrap().len()),
        (&json!("TRANSFER"), &Value::Null, 3)
    );
}

/// What the command refuses to start with, and how it ends when it must stop.
#[test]
fn follow_command_errors() {
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sh20-indexer-rs")).arg("follow").args(args).output().unwrap();
        (out.status.success(), String::from_utf8(out.stderr).unwrap())
    };
    for (args, message) in [
        (&["--activation", "1", "--deploy-burn", "0"][..], "give one source"),
        (
            &["--rpc", "http://x", "--esplora", "http://y", "--activation", "1", "--deploy-burn", "0"][..],
            "give one source",
        ),
        (&["--rpc", "http://x", "--deploy-burn", "0"][..], "needs --activation"),
        (&["--rpc", "http://x", "--activation", "1"][..], "and --deploy-burn"),
        (&["--rpc", "http://x", "--activation", "1", "--deploy-burn", "0", "--rpcuser", "u"][..], "go together"),
        (
            &["--esplora", "http://x", "--activation", "1", "--deploy-burn", "0", "--rpccookie", "c"][..],
            "go with --rpc",
        ),
        (
            &["--rpc", "http://x", "--activation", "1", "--deploy-burn", "0", "--verifier", "plonk"][..],
            "unknown verifier",
        ),
        (
            &["--rpc", "http://x", "--activation", "1", "--deploy-burn", "0", "--listen", "nowhere"][..],
            "--listen nowhere",
        ),
        (&["--rpc", "http://x", "--activation", "1", "--deploy-burn", "0", "--json"][..], "unknown option --json"),
    ] {
        let (ok, stderr) = run(args);
        assert!(!ok && stderr.contains(message), "{args:?}: {stderr}");
    }

    // a node that gives no prevout.height: the command stops at block 4, with an error
    let v = vectors();
    let rpc = http_server(core_rpc(Chain::new(scenario(&v, false)), None, false));
    let (ok, stderr) = run(&[
        "--rpc",
        &rpc,
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
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(!ok);
    assert!(stderr.contains("error: block 4") && stderr.contains("prevout.height"), "{stderr}");
    // never the password
    let cookie = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("follow-cookie");
    std::fs::write(&cookie, "__cookie__:hunter2\n").unwrap();
    let (ok, stderr) = run(&[
        "--rpc",
        &rpc,
        "--rpccookie",
        cookie.to_str().unwrap(),
        "--activation",
        "1",
        "--deploy-burn",
        "1",
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(!ok && stderr.contains("credentials") && !stderr.contains("hunter2"), "{stderr}");
}
