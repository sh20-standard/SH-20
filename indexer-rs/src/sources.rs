//! Where the follower reads blocks: Bitcoin Core over JSON-RPC, or an Esplora server.
//!
//! Both give the height of the block that confirmed the output a DEPLOY reveals (SPEC-WIRE §5,
//! "DEPLOY maturity"): Core in the block itself (`getblock <hash> 3`, `prevout.height`),
//! Esplora as the spent transaction's `status.block_height`.
//!
//! Esplora gives a block's transactions 25 to a page. A block of more than one page is read
//! from `/block/:hash/raw` instead, Bitcoin's serialized block in one request (`raw`): a mainnet
//! block holds thousands of transactions. A server without that route still serves the pages.

use crate::chain::{Block, Tx, TxIn, TxOut};
use crate::field::{hex, unhex, unhex32};
use crate::follow::{Source, SourceBlock, SourceError};
use crate::json::block_from_getblock_value;
use crate::raw::block_from_raw;
use crate::state::needs_commit_height;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

/// The largest answer read. A full block as `getblock <hash> 3` prints it stays well below.
const MAX_BODY: u64 = 512 << 20;

fn later(m: impl Into<String>) -> SourceError {
    SourceError::Later(m.into())
}

/// A blocking HTTP client: the status and the body of an answer, whatever the status.
pub struct Http {
    agent: ureq::Agent,
}

impl Default for Http {
    fn default() -> Self {
        Http::new()
    }
}

impl Http {
    pub fn new() -> Http {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .user_agent("sh20-indexer-rs")
            .build();
        Http { agent }
    }

    fn finish(result: Result<ureq::Response, ureq::Error>) -> Result<(u16, Vec<u8>), SourceError> {
        let response = match result {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => return Err(later(t.to_string())),
        };
        let status = response.status();
        let mut body = Vec::new();
        response.into_reader().take(MAX_BODY).read_to_end(&mut body).map_err(|e| later(e.to_string()))?;
        Ok((status, body))
    }

    pub fn get(&self, url: &str) -> Result<(u16, Vec<u8>), SourceError> {
        Http::finish(self.agent.get(url).call())
    }

    pub fn post_json(&self, url: &str, authorization: Option<&str>, body: &str) -> Result<(u16, Vec<u8>), SourceError> {
        let mut request = self.agent.post(url).set("Content-Type", "application/json");
        if let Some(a) = authorization {
            request = request.set("Authorization", a);
        }
        Http::finish(request.send_string(body))
    }
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `user:password` as the value of an `Authorization: Basic` header.
pub fn basic_auth(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = format!("{user}:{password}").into_bytes();
    let mut out = String::from("Basic ");
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------- Bitcoin Core

/// Bitcoin Core's JSON-RPC: `getblockhash`, `getblock <hash> 3`, `getblockchaininfo`.
pub struct CoreRpc {
    http: Http,
    url: String,
    authorization: Option<String>,
}

/// What a call gave: a result, or the node's error (its code and its message).
type RpcAnswer = Result<Value, (i64, String)>;

// Bitcoin Core's error codes (rpc/protocol.h).
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_MISC_ERROR: i64 = -1;

impl CoreRpc {
    /// `authorization` is the value of the header (`basic_auth`), when the node asks for one.
    pub fn new(url: &str, authorization: Option<String>) -> CoreRpc {
        CoreRpc { http: Http::new(), url: url.to_string(), authorization }
    }

    fn call(&self, method: &str, params: Value) -> Result<RpcAnswer, SourceError> {
        let request = json!({ "jsonrpc": "1.0", "id": "sh20", "method": method, "params": params });
        let (status, body) = self.http.post_json(&self.url, self.authorization.as_deref(), &request.to_string())?;
        if status == 401 || status == 403 {
            return Err(SourceError::Fatal(format!("the node refuses the RPC credentials (HTTP {status})")));
        }
        // the node answers an RPC error with HTTP 404 or 500 and a JSON body that says which
        let answer: Value = serde_json::from_slice(&body)
            .map_err(|_| later(format!("{method}: HTTP {status}, and the answer is not JSON")))?;
        match answer.get("error") {
            Some(e) if !e.is_null() => {
                let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
                let message = e.get("message").and_then(Value::as_str).unwrap_or("no message").to_string();
                Ok(Err((code, message)))
            }
            _ if status == 200 => Ok(Ok(answer.get("result").cloned().unwrap_or(Value::Null))),
            _ => Err(later(format!("{method}: HTTP {status}"))),
        }
    }

    fn result(&self, method: &str, params: Value) -> Result<Value, SourceError> {
        self.call(method, params)?.map_err(|(code, message)| later(format!("{method}: {message} (code {code})")))
    }
}

impl Source for CoreRpc {
    fn hash_at(&mut self, height: u32) -> Result<Option<String>, SourceError> {
        match self.call("getblockhash", json!([height]))? {
            Ok(Value::String(hash)) if is_hash(&hash) => Ok(Some(hash)),
            Ok(other) => Err(later(format!("getblockhash: unexpected answer {other}"))),
            // "Block height out of range": above the tip
            Err((RPC_INVALID_PARAMETER, _)) => Ok(None),
            Err((code, message)) => Err(later(format!("getblockhash: {message} (code {code})"))),
        }
    }

    fn block(&mut self, hash: &str) -> Result<SourceBlock, SourceError> {
        let b = match self.call("getblock", json!([hash, 3]))? {
            Ok(b) => b,
            Err((RPC_MISC_ERROR, message)) if message.contains("pruned") => {
                return Err(SourceError::Fatal(format!("getblock {hash}: {message}: the node must keep its blocks")))
            }
            Err((code, message)) => return Err(later(format!("getblock {hash}: {message} (code {code})"))),
        };
        let text = |key: &str| b.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        if text("hash") != hash {
            return Err(later(format!("getblock {hash}: the node answered with another block")));
        }
        let block = block_from_getblock_value(&b).map_err(|e| later(format!("getblock {hash}: {e}")))?;
        Ok(SourceBlock { hash: hash.to_string(), prev: text("previousblockhash"), block })
    }

    fn network(&mut self) -> Result<Option<String>, SourceError> {
        let info = self.result("getblockchaininfo", json!([]))?;
        Ok(info.get("chain").and_then(Value::as_str).map(str::to_string))
    }
}

// ---------------------------------------------------------------- Esplora

/// An Esplora server (`https://mempool.space/signet/api`, or one's own):
/// `/block-height/:height`, `/block/:hash`, `/block/:hash/txs/:start`, `/block/:hash/raw`,
/// `/tx/:txid/status`.
pub struct Esplora {
    http: Http,
    base: String,
}

/// Transactions per page of `/block/:hash/txs/:start`.
const PAGE: usize = 25;

impl Esplora {
    pub fn new(base: &str) -> Esplora {
        Esplora { http: Http::new(), base: base.trim_end_matches('/').to_string() }
    }

    /// The body of a 200 answer; `None` for a 404.
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let (status, body) = self.http.get(&format!("{}{path}", self.base))?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            _ => Err(later(format!("GET {path}: HTTP {status}"))),
        }
    }

    fn get_json(&self, path: &str) -> Result<Value, SourceError> {
        let body = self.get(path)?.ok_or_else(|| later(format!("GET {path}: not found")))?;
        serde_json::from_slice(&body).map_err(|e| later(format!("GET {path}: {e}")))
    }

    /// The transactions of a block, 25 to a request.
    fn pages(&self, hash: &str, count: u64) -> Result<Vec<Tx>, SourceError> {
        let mut txs: Vec<Tx> = Vec::new();
        while (txs.len() as u64) < count {
            let path = format!("/block/{hash}/txs/{}", txs.len());
            let page = self.get_json(&path)?;
            let page = page.as_array().filter(|p| !p.is_empty() && p.len() <= PAGE);
            let page = page.ok_or_else(|| later(format!("GET {path}: not a page of transactions")))?;
            for t in page {
                txs.push(esplora_tx(t).map_err(|e| later(format!("GET {path}: {e}")))?);
            }
        }
        if txs.len() as u64 != count {
            return Err(later(format!("GET /block/{hash}/txs: {} transactions for a tx_count of {count}", txs.len())));
        }
        Ok(txs)
    }

    /// The transactions of a block from its serialization, in one request; `None` where the
    /// server has no such route (404). Bytes that are not the block asked for are an answer to
    /// ask for again, not a reason to fall back on pages that nothing can check.
    fn raw(&self, hash: &str, prev: &str, count: u64) -> Result<Option<Vec<Tx>>, SourceError> {
        let path = format!("/block/{hash}/raw");
        let Some(bytes) = self.get(&path)? else { return Ok(None) };
        let block = block_from_raw(&bytes).map_err(|e| later(format!("GET {path}: {e}")))?;
        if hex(&block.hash) != hash {
            return Err(later(format!("GET {path}: the bytes are those of block {}", hex(&block.hash))));
        }
        // the block's own header against what /block/:hash said of it
        if hex(&block.prev) != prev && !(prev.is_empty() && block.prev == [0; 32]) {
            return Err(later(format!("GET {path}: the block before is {}, not {prev}", hex(&block.prev))));
        }
        if block.txs.len() as u64 != count {
            return Err(later(format!("GET {path}: {} transactions for a tx_count of {count}", block.txs.len())));
        }
        Ok(Some(block.txs))
    }

    /// The height of the block that confirmed `txid`, in the best chain.
    fn confirmed_at(&self, txid: &str) -> Result<u32, SourceError> {
        let path = format!("/tx/{txid}/status");
        let status = self.get_json(&path)?;
        let height = status.get("block_height").and_then(Value::as_u64).and_then(|h| u32::try_from(h).ok());
        match (status.get("confirmed").and_then(Value::as_bool), height) {
            (Some(true), Some(h)) => Ok(h),
            _ => Err(later(format!("GET {path}: not confirmed in the best chain"))),
        }
    }
}

fn esplora_tx(t: &Value) -> Result<Tx, String> {
    let text =
        |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("no \"{key}\""));
    let list = |v: &Value, key: &str| v.get(key).and_then(Value::as_array).cloned().ok_or(format!("no \"{key}\""));
    let txid = unhex32(&text(t, "txid")?).ok_or("bad txid")?;
    let mut vin = Vec::new();
    for i in list(t, "vin")? {
        let coinbase = i.get("is_coinbase").and_then(Value::as_bool).unwrap_or(false);
        let prevout = if coinbase {
            None
        } else {
            let vout =
                i.get("vout").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or("no \"vout\"")?;
            Some((unhex32(&text(&i, "txid")?).ok_or("bad input txid")?, vout))
        };
        let mut witness = Vec::new();
        for w in i.get("witness").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            witness.push(w.as_str().and_then(unhex).ok_or("bad witness item")?);
        }
        vin.push(TxIn { prevout, coinbase, prev_height: None, witness });
    }
    let mut vout = Vec::new();
    for o in list(t, "vout")? {
        let value = o.get("value").and_then(Value::as_u64).ok_or("no \"value\"")?;
        vout.push(TxOut { value, script: unhex(&text(&o, "scriptpubkey")?).ok_or("bad scriptpubkey")? });
    }
    Ok(Tx { txid, vin, vout })
}

impl Source for Esplora {
    fn hash_at(&mut self, height: u32) -> Result<Option<String>, SourceError> {
        let path = format!("/block-height/{height}");
        let Some(body) = self.get(&path)? else { return Ok(None) };
        let hash = String::from_utf8_lossy(&body).trim().to_string();
        if !is_hash(&hash) {
            return Err(later(format!("GET {path}: not a block hash")));
        }
        Ok(Some(hash))
    }

    fn block(&mut self, hash: &str) -> Result<SourceBlock, SourceError> {
        let head = self.get_json(&format!("/block/{hash}"))?;
        let number = |key: &str| head.get(key).and_then(Value::as_u64);
        let (Some(height), Some(count)) = (number("height").and_then(|h| u32::try_from(h).ok()), number("tx_count"))
        else {
            return Err(later(format!("GET /block/{hash}: no height or no tx_count")));
        };
        let prev = head.get("previousblockhash").and_then(Value::as_str).unwrap_or("").to_string();
        // more than one page: the whole block in one request, where the server has the route
        let raw = if count > PAGE as u64 { self.raw(hash, &prev, count)? } else { None };
        let mut txs = match raw {
            Some(txs) => txs,
            None => self.pages(hash, count)?,
        };
        // the height of the commit a DEPLOY reveals: the block does not give it
        for tx in &mut txs {
            if needs_commit_height(tx) {
                let (commit, _) = tx.vin[0].prevout.expect("a witness carrier is not a coinbase");
                let at = self.confirmed_at(&hex(&commit))?;
                if at > height {
                    return Err(later(format!("GET /block/{hash}: a commit confirmed after its reveal")));
                }
                tx.vin[0].prev_height = Some(at);
            }
        }
        Ok(SourceBlock { hash: hash.to_string(), prev, block: Block { height, txs } })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_of_rfc_4648() {
        let b64 = |s: &str| basic_auth(s, "").trim_start_matches("Basic ").to_string();
        // the vectors of RFC 4648 §10, each followed by the ":" of "user:password"
        assert_eq!(b64(""), "Og==");
        assert_eq!(b64("f"), "Zjo=");
        assert_eq!(b64("fo"), "Zm86");
        assert_eq!(b64("foo"), "Zm9vOg==");
        assert_eq!(basic_auth("Aladdin", "open sesame"), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }
}
