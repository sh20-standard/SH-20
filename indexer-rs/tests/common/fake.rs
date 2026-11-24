//! A chain to follow in tests: the vectors' scenario with block hashes and transactions that
//! carry nothing, as a `Source`, and as Bitcoin Core's RPC or an Esplora API on a local port.

use super::{control_block, input, out, p2tr, tapscript, transfer, txid};
use serde_json::{json, Value};
use sh20_indexer::api::Store;
use sh20_indexer::chain::{Block, Tx, TxIn, TxOut};
use sh20_indexer::field::{hex, sha256};
use sh20_indexer::follow::{Follower, Source, SourceBlock, SourceError};
use sh20_indexer::json::block_from_vector;
use sh20_indexer::{Indexer, Profile, TestVerifier};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, RwLock};

pub fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn profile(v: &Value) -> Profile {
    let p = &v["scenario"]["profile"];
    let n = |key: &str| p[key].as_u64().unwrap() as u32;
    Profile {
        activation_height: n("activationHeight"),
        deploy_burn: p["deployBurn"].as_str().unwrap().parse().unwrap(),
        anchor_window: n("anchorWindow"),
        anchor_min_depth: n("anchorMinDepth"),
        deploy_maturity: n("deployMaturity"),
    }
}

/// The hash of the block at `height` on a branch: any 64 hex characters will do.
pub fn block_hash(height: u32, branch: u8) -> String {
    hex(&sha256(&[b"test block", &height.to_le_bytes(), &[branch]]))
}

pub fn noise_txid(height: u32, n: u8) -> [u8; 32] {
    sha256(&[b"noise", &height.to_le_bytes(), &[n]])
}

/// Transactions an indexer has nothing to read in: a coinbase (with a witness, which is not
/// looked at), a payment, and one whose *second* input reveals a TRANSFER (only input 0 is read).
fn noise(height: u32) -> [Tx; 3] {
    let coinbase = Tx {
        txid: noise_txid(height, 0),
        vin: vec![TxIn { prevout: None, coinbase: true, prev_height: None, witness: vec![vec![0; 32]] }],
        vout: vec![
            out(5_000_000_000, &p2tr(&[0x11; 32])),
            out(0, &[&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..], &[0x22; 32]].concat()),
        ],
    };
    let mut payer = input(u64::from(height) * 10 + 1);
    payer.witness = vec![vec![1; 64], vec![2; 33]];
    let payment = Tx {
        txid: noise_txid(height, 1),
        vin: vec![payer.clone()],
        vout: vec![out(70_000, &[&[0x00, 0x14][..], &[0x33; 20]].concat()), out(1_234, &p2tr(&[0x44; 32]))],
    };
    let mut second = input(u64::from(height) * 10 + 2);
    second.witness = vec![vec![1; 64], tapscript(&transfer(0, 9_000 + u64::from(height))), control_block()];
    let not_input_0 =
        Tx { txid: noise_txid(height, 2), vin: vec![payer, second], vout: vec![out(600, &p2tr(&[0x55; 32]))] };
    [coinbase, payment, not_input_0]
}

fn with_hashes(blocks: &[Value], prev: String, branch: u8, noisy: bool) -> Vec<SourceBlock> {
    let mut prev = prev;
    let mut list = Vec::new();
    for b in blocks {
        let mut block = block_from_vector(b).unwrap();
        if noisy {
            let [coinbase, payment, not_input_0] = noise(block.height);
            block.txs.insert(0, coinbase);
            block.txs.insert(block.txs.len().min(2), payment);
            block.txs.push(not_input_0);
        }
        let hash = block_hash(block.height, branch);
        list.push(SourceBlock { hash: hash.clone(), prev, block });
        prev = hash;
    }
    list
}

/// The blocks of another vectors file (`blocks` at its top), as a chain from block 1.
pub fn chain_of(blocks: &Value) -> Vec<SourceBlock> {
    with_hashes(blocks.as_array().unwrap(), block_hash(0, 0), 0, true)
}

/// Blocks 1 to 17 of the scenario.
pub fn scenario(v: &Value, noisy: bool) -> Vec<SourceBlock> {
    with_hashes(v["scenario"]["blocks"].as_array().unwrap(), block_hash(0, 0), 0, noisy)
}

/// The chain after the vectors' reorg: blocks 1 to `rollbackTo`, then the two new blocks.
pub fn reorged(v: &Value, noisy: bool) -> Vec<SourceBlock> {
    let fork = v["reorg"]["rollbackTo"].as_u64().unwrap() as usize;
    let mut chain = scenario(v, noisy);
    chain.truncate(fork);
    let new = with_hashes(v["reorg"]["blocks"].as_array().unwrap(), chain[fork - 1].hash.clone(), 1, noisy);
    chain.extend(new);
    chain
}

// ---------------------------------------------------------------- a source in memory

#[derive(Default)]
pub struct ChainState {
    /// The best chain, lowest block first.
    pub blocks: Vec<SourceBlock>,
    /// Calls answered so far, of any kind.
    pub calls: usize,
    /// The call with this number fails once.
    pub fail_call: Option<usize>,
    /// Every call fails while this is set.
    pub down: bool,
    /// The heights of the blocks fetched, in order.
    pub fetched: Vec<u32>,
    /// `/tx/:txid/status` requests answered (Esplora).
    pub status_calls: usize,
    /// Whether the Esplora API has `/block/:hash/raw` (for the blocks of `mined`).
    pub raw: bool,
    /// `/block/:hash/raw` requests, answered with a block or with 404.
    pub raw_calls: usize,
}

/// A chain shared between a test and the source it gives to a follower.
#[derive(Clone, Default)]
pub struct Chain(pub Arc<Mutex<ChainState>>);

impl Chain {
    pub fn new(blocks: Vec<SourceBlock>) -> Chain {
        Chain(Arc::new(Mutex::new(ChainState { blocks, ..ChainState::default() })))
    }

    pub fn set(&self, blocks: Vec<SourceBlock>) {
        self.0.lock().unwrap().blocks = blocks;
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.0.lock().unwrap()
    }

    /// Counts a call; says whether it must fail.
    fn fails(&self) -> bool {
        let mut s = self.state();
        s.calls += 1;
        s.down || s.fail_call == Some(s.calls - 1)
    }

    fn hash_of(&self, height: u32) -> Option<String> {
        self.state().blocks.iter().find(|b| b.block.height == height).map(|b| b.hash.clone())
    }

    fn fetch(&self, hash: &str) -> Option<SourceBlock> {
        let mut s = self.state();
        let b = s.blocks.iter().find(|b| b.hash == hash).cloned()?;
        s.fetched.push(b.block.height);
        Some(b)
    }
}

impl Source for Chain {
    fn hash_at(&mut self, height: u32) -> Result<Option<String>, SourceError> {
        if self.fails() {
            return Err(SourceError::Later("the source is down".into()));
        }
        Ok(self.hash_of(height))
    }

    fn block(&mut self, hash: &str) -> Result<SourceBlock, SourceError> {
        if self.fails() {
            return Err(SourceError::Later("the source is down".into()));
        }
        self.fetch(hash).ok_or(SourceError::Later("block not known any more".into()))
    }
}

pub fn new_store(v: &Value) -> Arc<RwLock<Store>> {
    Arc::new(RwLock::new(Store::new(profile(v), "test", "test")))
}

/// A follower of `source` with the vectors' profile and test verifier, and no block file.
pub fn follower<S: Source>(v: &Value, source: S) -> (Follower<S>, Arc<RwLock<Store>>) {
    let store = new_store(v);
    let indexer = Indexer::new(profile(v), Box::new(TestVerifier));
    (Follower::new(source, indexer, store.clone(), None).unwrap(), store)
}

// ---------------------------------------------------------------- reading the API

/// The body of a 200 answer.
pub fn get(store: &RwLock<Store>, target: &str) -> Value {
    let r = store.read().unwrap().respond("GET", target);
    assert_eq!(r.status, 200, "{target}: {}", r.body);
    r.body
}

pub fn status_of(store: &RwLock<Store>, target: &str) -> u16 {
    store.read().unwrap().respond("GET", target).status
}

/// Everything the API says, route by route: two stores that give the same are in the same state.
pub fn dump(store: &RwLock<Store>) -> Value {
    let mut all = serde_json::Map::new();
    let mut take = |target: String| {
        let body = get(store, &target);
        all.insert(target, body.clone());
        body
    };
    let status = take("/status".into());
    for t in take("/tokens".into()).as_array().unwrap() {
        take(format!("/token/{}", t["ticker"].as_str().unwrap()));
    }
    let notes = take("/notes?limit=5000".into());
    assert_eq!(notes["total"], notes["notes"].as_array().unwrap().len());
    for n in notes["notes"].as_array().unwrap() {
        take(format!("/path/{}", n["pos"]));
    }
    take("/roots?from=0".into());
    for n in take("/nullifiers".into())["nullifiers"].as_array().unwrap() {
        take(format!("/nullifier/{}", n["nullifier"].as_str().unwrap()));
    }
    for l in take("/listings".into()).as_array().unwrap() {
        take(format!("/listing/{}", l["listTxid"].as_str().unwrap()));
    }
    for state in ["ACTIVE", "SOLD", "CANCELLED", "CLOSED", "CLAIMED"] {
        take(format!("/listings?state={state}"));
    }
    take("/blocks?limit=200".into());
    let a = status["activationHeight"].as_u64().unwrap();
    for h in a..=status["height"].as_u64().unwrap_or(a - 1) {
        take(format!("/digest/{h}"));
        let block = take(format!("/block/{h}"));
        let named = block["events"].as_array().unwrap().iter().chain(block["rejected"].as_array().unwrap());
        for txid in named.filter_map(|e| e["txid"].as_str()) {
            take(format!("/tx/{txid}"));
        }
    }
    Value::Object(all)
}

// ---------------------------------------------------------------- a local HTTP server

pub struct Request {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: String,
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = stream.read(&mut buffer).ok().filter(|n| *n > 0)?;
        data.extend_from_slice(&buffer[..n]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let header = |name: &str| {
        head.lines().find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    while data.len() < head_end + length {
        let n = stream.read(&mut buffer).ok().filter(|n| *n > 0)?;
        data.extend_from_slice(&buffer[..n]);
    }
    let body = String::from_utf8_lossy(&data[head_end..head_end + length]).to_string();
    Some(Request { method, path, authorization: header("authorization"), body })
}

/// Serves `handler` on a free local port, one request per connection, and returns its URL.
pub fn http_server<B: AsRef<[u8]>>(handler: impl Fn(&Request) -> (u16, B) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(request) = read_request(&mut stream) else { continue };
            let (status, body) = handler(&request);
            let body = body.as_ref();
            let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(body));
        }
    });
    url
}

/// A URL nobody listens on (port 1, which no test here can be given).
pub fn dead_url() -> String {
    "http://127.0.0.1:1".to_string()
}

// ---------------------------------------------------------------- the chain as Bitcoin Core

fn btc(sats: u64) -> Value {
    serde_json::from_str(&format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)).unwrap()
}

/// A block as `getblock <hash> 3` prints it. `heights`: with `prevout.height` (verbosity 3).
fn getblock(b: &SourceBlock, heights: bool) -> Value {
    let txs: Vec<Value> = b
        .block
        .txs
        .iter()
        .map(|t| {
            let vin: Vec<Value> = t
                .vin
                .iter()
                .map(|i| {
                    let witness: Vec<String> = i.witness.iter().map(|w| hex(w)).collect();
                    let Some((prev, vout)) = i.prevout else {
                        return json!({ "coinbase": "0101", "txinwitness": witness, "sequence": 4294967295u32 });
                    };
                    let mut o = json!({ "txid": hex(&prev), "vout": vout, "scriptSig": { "asm": "", "hex": "" } });
                    if !witness.is_empty() {
                        o["txinwitness"] = json!(witness);
                    }
                    if let Some(h) = i.prev_height.filter(|_| heights) {
                        o["prevout"] = json!({ "generated": false, "height": h, "value": btc(1_000), "scriptPubKey": { "hex": "5120" } });
                    }
                    o
                })
                .collect();
            let vout: Vec<Value> = t
                .vout
                .iter()
                .enumerate()
                .map(|(n, o)| json!({ "value": btc(o.value), "n": n, "scriptPubKey": { "asm": "", "hex": hex(&o.script) } }))
                .collect();
            json!({ "txid": hex(&t.txid), "hash": hex(&t.txid), "vin": vin, "vout": vout })
        })
        .collect();
    json!({ "hash": b.hash, "confirmations": 1, "height": b.block.height, "previousblockhash": b.prev, "tx": txs })
}

/// Bitcoin Core's JSON-RPC over `chain`. `authorization`: the header it asks for.
pub fn core_rpc(chain: Chain, authorization: Option<String>, heights: bool) -> impl Fn(&Request) -> (u16, String) {
    move |request| {
        if request.authorization != authorization {
            return (401, String::new());
        }
        if chain.fails() {
            return (503, "Work queue depth exceeded".into());
        }
        let call: Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(request.method, "POST");
        let failure = |code: i64, message: &str| {
            (
                500,
                json!({ "result": null, "error": { "code": code, "message": message }, "id": call["id"] }).to_string(),
            )
        };
        let result = match call["method"].as_str().unwrap() {
            "getblockchaininfo" => json!({ "chain": "signet", "blocks": chain.state().blocks.len() }),
            "getblockhash" => match chain.hash_of(call["params"][0].as_u64().unwrap() as u32) {
                Some(hash) => json!(hash),
                None => return failure(-8, "Block height out of range"),
            },
            "getblock" => {
                assert_eq!(call["params"][1], 3, "the follower asks for verbosity 3");
                match chain.fetch(call["params"][0].as_str().unwrap()) {
                    Some(b) => getblock(&b, heights),
                    None => return failure(-5, "Block not found"),
                }
            }
            other => return failure(-32601, &format!("Method not found: {other}")),
        };
        (200, json!({ "result": result, "error": null, "id": call["id"] }).to_string())
    }
}

// ---------------------------------------------------------------- the chain as Esplora

fn esplora_tx(t: &Tx) -> Value {
    let vin: Vec<Value> = t
        .vin
        .iter()
        .map(|i| {
            let (prev, vout) = i.prevout.unwrap_or(([0; 32], u32::MAX));
            let mut o =
                json!({ "txid": hex(&prev), "vout": vout, "is_coinbase": i.coinbase, "scriptsig": "", "sequence": 1 });
            // Esplora leaves `witness` out of an input that has none
            if !i.witness.is_empty() {
                o["witness"] = i.witness.iter().map(|w| json!(hex(w))).collect();
            }
            o
        })
        .collect();
    let vout: Vec<Value> =
        t.vout.iter().map(|o: &TxOut| json!({ "scriptpubkey": hex(&o.script), "value": o.value })).collect();
    json!({ "txid": hex(&t.txid), "version": 2, "locktime": 0, "vin": vin, "vout": vout, "status": { "confirmed": true } })
}

/// An Esplora API over `chain`. The height of a spent output is only in `/tx/:txid/status`:
/// here, for the outputs the scenario gives a `prevHeight` for.
/// The Esplora API over `chain`. `/block/:hash/raw` answers 404 unless the chain's `raw` is set
/// (its blocks then come from `mined`: the bytes must hash to the hashes the chain gives).
pub fn esplora(chain: Chain) -> impl Fn(&Request) -> (u16, Vec<u8>) {
    let json_routes = esplora_json(chain.clone());
    move |request| {
        let Some(hash) = request.path.strip_prefix("/block/").and_then(|p| p.strip_suffix("/raw")) else {
            let (status, body) = json_routes(request);
            return (status, body.into_bytes());
        };
        if chain.fails() {
            return (429, b"Too Many Requests".to_vec());
        }
        let mut s = chain.state();
        s.raw_calls += 1;
        match s.blocks.iter().find(|b| b.hash == hash) {
            Some(b) if s.raw => (200, serialized(b)),
            _ => (404, b"Not found".to_vec()),
        }
    }
}

fn esplora_json(chain: Chain) -> impl Fn(&Request) -> (u16, String) {
    move |request| {
        assert_eq!(request.method, "GET");
        if chain.fails() {
            return (429, "Too Many Requests".into());
        }
        let parts: Vec<&str> = request.path.split('/').filter(|p| !p.is_empty()).collect();
        let block = |hash: &str| chain.state().blocks.iter().find(|b| b.hash == hash).cloned();
        match parts.as_slice() {
            ["block-height", height] => match chain.hash_of(height.parse().unwrap()) {
                Some(hash) => (200, hash),
                None => (404, "Block not found".into()),
            },
            ["block", hash] => match block(hash) {
                Some(b) => {
                    let head = json!({ "id": b.hash, "height": b.block.height, "tx_count": b.block.txs.len(), "previousblockhash": b.prev });
                    (200, head.to_string())
                }
                None => (404, "Block not found".into()),
            },
            ["block", hash, "txs", start] => {
                let start: usize = start.parse().unwrap();
                assert_eq!(start % 25, 0, "pages start at multiples of 25");
                let Some(b) = chain.fetch(hash) else { return (404, "Block not found".into()) };
                let page: Vec<Value> = b.block.txs.iter().skip(start).take(25).map(esplora_tx).collect();
                (200, Value::Array(page).to_string())
            }
            ["tx", txid, "status"] => {
                let mut s = chain.state();
                s.status_calls += 1;
                let spends =
                    |t: &&Tx| t.vin.first().and_then(|i| i.prevout).is_some_and(|(prev, _)| hex(&prev) == *txid);
                let spender = s.blocks.iter().flat_map(|b: &SourceBlock| b.block.txs.iter()).find(spends);
                match spender.and_then(|t| t.vin[0].prev_height) {
                    Some(h) => (200, json!({ "confirmed": true, "block_height": h, "block_hash": "" }).to_string()),
                    None => (200, json!({ "confirmed": false }).to_string()),
                }
            }
            _ => (404, "Not found".into()),
        }
    }
}

/// Blocks with a transaction more: `count` payments that carry nothing.
pub fn padded(mut blocks: Vec<SourceBlock>, height: u32, count: u8) -> Vec<SourceBlock> {
    let b: &mut Block = &mut blocks.iter_mut().find(|b| b.block.height == height).unwrap().block;
    for n in 0..count {
        let payment = Tx {
            txid: noise_txid(height, 100 + n),
            vin: vec![input(7_000 + u64::from(n))],
            vout: vec![out(1, &[0x51])],
        };
        b.txs.insert(usize::from(n) % (b.txs.len() + 1), payment);
    }
    blocks
}

/// A txid no block holds.
pub fn unknown_txid() -> String {
    hex(&txid(424_242))
}

// ---------------------------------------------------------------- blocks in Bitcoin's bytes

/// Bitcoin's serialization, written here from the format and on its own: the reader under test
/// is `src/raw.rs`, and the two meet only through the bytes.
fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [&[0xfd][..], &(n as u16).to_le_bytes()].concat(),
        _ => [&[0xfe][..], &(n as u32).to_le_bytes()].concat(),
    }
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    sha256(&[&sha256(&[bytes])])
}

fn reversed(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes.reverse();
    bytes
}

fn merkle(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level.chunks(2).map(|p| sha256d(&[p[0], p[1]].concat())).collect();
    }
    level[0]
}

/// The transaction at place `n` of its block. What a `Tx` does not hold comes from `n`, so that
/// the bytes vary: the version, the lock time, the sequence, and the scriptSig of an input
/// without a witness (empty, a few bytes, or more than 252: a length on three bytes).
fn tx_bytes(t: &Tx, n: usize, with_witness: bool) -> Vec<u8> {
    let segwit = with_witness && t.vin.iter().any(|i| !i.witness.is_empty());
    let mut b = (1 + (n as u32 % 2)).to_le_bytes().to_vec();
    if segwit {
        b.extend([0x00, 0x01]);
    }
    b.extend(compact_size(t.vin.len()));
    for (k, i) in t.vin.iter().enumerate() {
        let script_sig = match (i.coinbase, i.witness.is_empty(), n % 3) {
            (true, _, _) => vec![0x02, n as u8, 0x01],
            (false, true, 0) => vec![0x51; 300],
            (false, true, _) => vec![0x01, k as u8],
            (false, false, _) => Vec::new(),
        };
        match i.prevout {
            Some((txid, vout)) => b.extend([&reversed(txid)[..], &vout.to_le_bytes()].concat()),
            None => b.extend([&[0u8; 32][..], &[0xff; 4]].concat()),
        }
        b.extend(compact_size(script_sig.len()));
        b.extend(script_sig);
        b.extend((0xffff_fffd_u32 - n as u32).to_le_bytes());
    }
    b.extend(compact_size(t.vout.len()));
    for o in &t.vout {
        b.extend(o.value.to_le_bytes());
        b.extend(compact_size(o.script.len()));
        b.extend(&o.script);
    }
    if segwit {
        for i in &t.vin {
            b.extend(compact_size(i.witness.len()));
            for item in &i.witness {
                b.extend(compact_size(item.len()));
                b.extend(item);
            }
        }
    }
    b.extend((n as u32 * 7).to_le_bytes());
    b
}

fn header(prev: &str, height: u32, txs: &[Tx]) -> Vec<u8> {
    let prev: [u8; 32] = sh20_indexer::field::unhex32(prev).unwrap();
    let root = merkle(txs.iter().map(|t| reversed(t.txid)).collect());
    let mut h = 0x2000_0000_u32.to_le_bytes().to_vec();
    h.extend(reversed(prev));
    h.extend(root);
    h.extend((1_700_000_000 + height).to_le_bytes()); // time
    h.extend(0x207f_ffff_u32.to_le_bytes()); // bits
    h.extend(height.to_le_bytes()); // nonce
    h
}

/// A block of `mined` in Bitcoin's bytes: what `/block/:hash/raw` answers.
pub fn serialized(b: &SourceBlock) -> Vec<u8> {
    let mut bytes = header(&b.prev, b.block.height, &b.block.txs);
    bytes.extend(compact_size(b.block.txs.len()));
    for (n, t) in b.block.txs.iter().enumerate() {
        bytes.extend(tx_bytes(t, n, true));
    }
    bytes
}

/// Blocks as a miner would make them, from transactions without a coinbase: each transaction
/// gets the txid of its bytes, each block a coinbase that commits to the witnesses (BIP 141) and
/// the hash of its header. No transaction here spends another: a txid changes nothing above it.
pub fn mined(blocks: Vec<Block>) -> Vec<SourceBlock> {
    let mut prev = block_hash(0, 0);
    let mut chain = Vec::new();
    for mut block in blocks {
        let reserved = vec![0u8; 32];
        let mut wtxids = vec![[0u8; 32]];
        for (n, t) in block.txs.iter_mut().enumerate() {
            t.txid = reversed(sha256d(&tx_bytes(t, n + 1, false)));
            wtxids.push(sha256d(&tx_bytes(t, n + 1, true)));
        }
        let commitment = sha256d(&[&merkle(wtxids)[..], &reserved].concat());
        let mut coinbase = Tx {
            txid: [0; 32],
            vin: vec![TxIn { prevout: None, coinbase: true, prev_height: None, witness: vec![reserved] }],
            vout: vec![
                out(5_000_000_000, &p2tr(&[0x11; 32])),
                out(0, &[&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..], &commitment].concat()),
            ],
        };
        coinbase.txid = reversed(sha256d(&tx_bytes(&coinbase, 0, false)));
        block.txs.insert(0, coinbase);
        let hash = hex(&reversed(sha256d(&header(&prev, block.height, &block.txs))));
        chain.push(SourceBlock { hash: hash.clone(), prev, block });
        prev = hash;
    }
    chain
}
