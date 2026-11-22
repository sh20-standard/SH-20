//! The read-only API of `docs/API.md`: what the follower keeps to answer it, and the routes.
//!
//! The state machine keeps what the rules need (the tree's frontier, a set of nullifiers).
//! A wallet needs more: every leaf with what opens it, every nullifier with its block, the
//! root and the digest of every block. `Store` keeps that, block by block, and can drop its
//! last block again when the chain reorganises.
//!
//! `docs/API.md` names the routes and the fields. Where it does not say what a field holds,
//! `docs/SPEC-GAPS.md` ("The HTTP API") says what was chosen here.

use crate::envelope::Ticker;
use crate::events::{Event, Outcome, Spent};
use crate::field::{fr_to_be, h2, hex, sha256, unhex32, Bytes32};
use crate::state::{BlockResult, Indexer, Listing, ListingStatus, Note, NoteKind, Profile, Rejection, Token};
use crate::tree::DEPTH;
use ark_bn254::Fr;
use ark_ff::Zero;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub const NOTES_LIMIT_DEFAULT: usize = 1000;
pub const NOTES_LIMIT_MAX: usize = 5000;
pub const BLOCKS_LIMIT_DEFAULT: usize = 20;
pub const BLOCKS_LIMIT_MAX: usize = 200;

struct BlockRecord {
    height: u32,
    hash: String,
    digest: Bytes32,
    root: Fr,
    /// Leaves in the tree after the block.
    leaves: u64,
    events: Vec<(Event, Option<u32>)>,
    events_bytes: Vec<u8>,
    rejected: Vec<Rejection>,
    /// How many notes and nullifiers the store held before the block: where to cut on a rollback.
    notes_before: usize,
    nullifiers_before: usize,
}

struct TokenView {
    token: Token,
    /// The DEPLOY transaction and its block; `None` for the genesis token.
    deploy: Option<(Bytes32, u32)>,
}

struct ListingView {
    txid: Bytes32,
    height: u32,
    listing: Listing,
    /// The TAKE that sold or cancelled it.
    take: Option<Bytes32>,
    /// The transaction that spent its lock without a TAKE.
    closed_by: Option<Bytes32>,
}

pub struct Store {
    profile: Profile,
    network: String,
    verifier: String,
    /// `blocks[i]` is block `A + i`.
    blocks: Vec<BlockRecord>,
    /// Every leaf, by position, with the height of its block.
    notes: Vec<(u32, Note)>,
    /// Every nullifier spent, in order, with the height of its block.
    nullifiers: Vec<(u32, Bytes32)>,
    spent: HashSet<Bytes32>,
    /// The block of every transaction that has an event or a refusal.
    txs: HashMap<Bytes32, u32>,
    /// The genesis token, then the others in DEPLOY order.
    tokens: Vec<TokenView>,
    /// In LIST order.
    listings: Vec<ListingView>,
    listing_index: HashMap<Bytes32, usize>,
    /// `levels[k]`: the nodes of height `k` whose `2^k` leaves all exist (`levels[0]`: the leaves).
    levels: Vec<Vec<Fr>>,
    zeros: [Fr; DEPTH + 1],
}

pub struct Response {
    pub status: u16,
    pub body: Value,
}

fn ok(body: Value) -> Response {
    Response { status: 200, body }
}

fn error(status: u16, message: &str) -> Response {
    Response { status, body: json!({ "error": message }) }
}

fn not_found(what: &str) -> Response {
    error(404, &format!("{what} not found"))
}

fn fr_hex(f: &Fr) -> String {
    hex(&fr_to_be(f))
}

/// A field element as the wire has it (little-endian), in the API's big-endian hex.
fn le_hex(b: &Bytes32) -> String {
    let mut be = *b;
    be.reverse();
    hex(&be)
}

fn spent_json(o: &mut Value, s: &Spent) {
    o["nullifiers"] = json!([le_hex(&s.nf[0]), le_hex(&s.nf[1])]);
    o["pos"] = json!(s.pos);
}

/// An event as JSON: its type, its transaction, and the fields of its record in the digest
/// (SPEC-WIRE §6) under their names in the spec. `envelope` is its index in a batch.
pub fn event_json(event: &Event, envelope: Option<u32>) -> Value {
    let mut o = json!({ "type": event.name() });
    if !matches!(event, Event::Genesis { .. } | Event::TeamUnlock { .. }) {
        o["txid"] = json!(hex(event.txid()));
    }
    if let Some(i) = envelope {
        o["envelope"] = json!(i);
    }
    match event {
        Event::Deploy { ticker, burn, .. } => {
            o["ticker"] = json!(ticker.as_str());
            if let Some(s) = burn {
                spent_json(&mut o, s);
            }
        }
        Event::Mint { ticker, v, pos, .. } => {
            o["ticker"] = json!(ticker.as_str());
            o["v"] = json!(v.to_string());
            o["pos"] = json!(pos);
        }
        Event::Transfer { spent, .. } => spent_json(&mut o, spent),
        Event::Burn { ticker, v_pub, spent, .. } => {
            o["ticker"] = json!(ticker.as_str());
            o["vPub"] = json!(v_pub.to_string());
            spent_json(&mut o, spent);
        }
        Event::List { ticker, amount, price, spent, .. } => {
            o["ticker"] = json!(ticker.as_str());
            o["amount"] = json!(amount.to_string());
            o["price"] = json!(price.to_string());
            spent_json(&mut o, spent);
        }
        Event::Take { list_txid, outcome, pos, .. } => {
            o["listTxid"] = json!(hex(list_txid));
            o["outcome"] = json!(match outcome {
                Outcome::Sold => "SOLD",
                Outcome::Cancelled => "CANCELLED",
            });
            o["pos"] = json!(pos);
        }
        Event::Claim { list_txid, pos, .. } => {
            o["listTxid"] = json!(hex(list_txid));
            o["pos"] = json!(pos);
        }
        Event::Genesis { ticker, max, lim, deploy_burn, window, min_depth, maturity } => {
            o["ticker"] = json!(ticker.as_str());
            o["max"] = json!(max.to_string());
            o["lim"] = json!(lim.to_string());
            o["deployBurn"] = json!(deploy_burn.to_string());
            o["anchorWindow"] = json!(window);
            o["anchorMinDepth"] = json!(min_depth);
            o["deployMaturity"] = json!(maturity);
        }
        Event::TeamUnlock { ticker, pre, pos } => {
            o["ticker"] = json!(ticker.as_str());
            o["pre"] = json!(pre.to_string());
            o["pos"] = json!(pos);
        }
        Event::Closed { list_txid, .. } => o["listTxid"] = json!(hex(list_txid)),
    }
    o
}

fn rejection_json(r: &Rejection, with_txid: bool) -> Value {
    let mut o = json!({});
    if with_txid {
        o["txid"] = json!(hex(&r.txid));
    }
    if let Some(i) = r.envelope {
        o["envelope"] = json!(i);
    }
    o["reason"] = json!(r.reason);
    o
}

fn note_json(height: u32, n: &Note) -> Value {
    let mut o = json!({
        "pos": n.pos,
        "height": height,
        "txid": n.txid.map(|t| hex(&t)),
        "leaf": fr_hex(&n.leaf),
    });
    match &n.kind {
        NoteKind::Public { kind, ticker, v, npk } => {
            o["kind"] = json!(kind.name());
            o["ticker"] = json!(ticker.as_str());
            o["v"] = json!(v.to_string());
            o["npk"] = json!(le_hex(npk));
        }
        NoteKind::Out { j, pk_eph, ct } => {
            o["kind"] = json!("OUT");
            o["j"] = json!(j);
            o["pkEph"] = json!(hex(pk_eph));
            o["ct"] = json!(hex(ct));
        }
    }
    if let Some(i) = n.envelope {
        o["envelope"] = json!(i);
    }
    o
}

fn token_json(v: &TokenView, activation: u32) -> Value {
    let t = &v.token;
    let mut o = json!({
        "ticker": t.ticker.as_str(),
        "t": t.ticker.t().to_string(),
        "max": t.max.to_string(),
        "lim": t.lim.to_string(),
        "pre": t.pre.to_string(),
        "start": t.start,
        "end": t.end,
        "unlock": t.unlock,
        "price": t.price.to_string(),
        "payMode": t.pay_mode,
        "payScript": hex(&t.pay_script),
        "mints": t.mints.to_string(),
        "burned": t.burned.to_string(),
        "pool": t.pool.to_string(),
    });
    match v.deploy {
        Some((txid, height)) => {
            o["deployTxid"] = json!(hex(&txid));
            o["deployHeight"] = json!(height);
        }
        None => {
            o["genesis"] = json!(true);
            o["deployTxid"] = Value::Null;
            o["deployHeight"] = json!(activation);
        }
    }
    o
}

fn listing_json(v: &ListingView) -> Value {
    let l = &v.listing;
    let mut o = json!({
        "listTxid": hex(&v.txid),
        "ticker": l.ticker.as_str(),
        "amount": l.amount.to_string(),
        "price": l.price.to_string(),
        "payScript": hex(&l.pay_script),
        "lock": format!("{}:{}", hex(&l.lock.0), l.lock.1),
        "lockKey": hex(&l.lock_key),
        "state": l.status.name(),
        "height": v.height,
    });
    if let Some(txid) = &v.take {
        o["takeTxid"] = json!(hex(txid));
    }
    if let Some(txid) = &v.closed_by {
        o["closedBy"] = json!(hex(txid));
    }
    o
}

fn block_json(b: &BlockRecord) -> Value {
    json!({
        "height": b.height,
        "hash": b.hash,
        "digest": hex(&b.digest),
        "root": fr_hex(&b.root),
        "leaves": b.leaves,
        "events": b.events.iter().map(|(e, i)| event_json(e, *i)).collect::<Vec<_>>(),
        "eventsH": hex(&b.events_bytes),
        "rejected": b.rejected.iter().map(|r| rejection_json(r, true)).collect::<Vec<_>>(),
    })
}

impl Store {
    /// `network` and `verifier` are reported by `/status` as given.
    pub fn new(profile: Profile, network: &str, verifier: &str) -> Store {
        let mut zeros = [Fr::zero(); DEPTH + 1];
        for i in 0..DEPTH {
            zeros[i + 1] = h2(&zeros[i], &zeros[i]);
        }
        Store {
            profile,
            network: network.to_string(),
            verifier: verifier.to_string(),
            blocks: Vec::new(),
            notes: Vec::new(),
            nullifiers: Vec::new(),
            spent: HashSet::new(),
            txs: HashMap::new(),
            tokens: Vec::new(),
            listings: Vec::new(),
            listing_index: HashMap::new(),
            levels: vec![Vec::new(); DEPTH + 1],
            zeros,
        }
    }

    pub fn set_network(&mut self, network: &str) {
        self.network = network.to_string();
    }

    /// The last block held: its height and its hash.
    pub fn tip(&self) -> Option<(u32, &str)> {
        self.blocks.last().map(|b| (b.height, b.hash.as_str()))
    }

    pub fn digest(&self) -> Bytes32 {
        self.blocks.last().map_or(sha256(&[b"sh20-v0"]), |b| b.digest)
    }

    fn block_at(&self, height: u32) -> Option<&BlockRecord> {
        self.blocks.get(height.checked_sub(self.profile.activation_height)? as usize)
    }

    // ---- writing: one block more, one block less ----

    /// Records a block the indexer has just applied. `hash` is the block's hash.
    pub fn apply(&mut self, hash: &str, r: &BlockResult, indexer: &Indexer) {
        let h = r.height;
        let (notes_before, nullifiers_before) = (self.notes.len(), self.nullifiers.len());
        for n in &r.notes {
            debug_assert_eq!(n.pos as usize, self.notes.len());
            self.notes.push((h, n.clone()));
            self.grow(n.leaf);
        }
        for e in &r.events {
            let spent = match e {
                Event::Deploy { burn: Some(s), .. } => Some(s),
                Event::Transfer { spent, .. } | Event::Burn { spent, .. } | Event::List { spent, .. } => Some(spent),
                _ => None,
            };
            for nf in spent.iter().flat_map(|s| s.nf) {
                self.nullifiers.push((h, nf));
                self.spent.insert(nf);
            }
            match e {
                Event::Genesis { ticker, .. } => self.new_token(indexer, ticker, None),
                Event::Deploy { txid, ticker, .. } => self.new_token(indexer, ticker, Some((*txid, h))),
                Event::List { txid, .. } => {
                    if let Some(l) = indexer.listing(txid) {
                        self.listing_index.insert(*txid, self.listings.len());
                        let listing = l.clone();
                        self.listings.push(ListingView {
                            txid: *txid,
                            height: h,
                            listing,
                            take: None,
                            closed_by: None,
                        });
                    }
                }
                Event::Take { txid, list_txid, .. } => {
                    if let Some(l) = self.listing_mut(list_txid) {
                        l.take = Some(*txid);
                    }
                }
                Event::Closed { txid, list_txid } => {
                    if let Some(l) = self.listing_mut(list_txid) {
                        l.closed_by = Some(*txid);
                    }
                }
                _ => {}
            }
            if !matches!(e, Event::Genesis { .. } | Event::TeamUnlock { .. }) {
                self.txs.insert(*e.txid(), h);
            }
        }
        for x in &r.rejected {
            self.txs.insert(x.txid, h);
        }
        if !r.events.is_empty() {
            self.sync(indexer);
        }
        self.blocks.push(BlockRecord {
            height: h,
            hash: hash.to_string(),
            digest: r.digest,
            root: r.root,
            leaves: self.notes.len() as u64,
            events: r.events.iter().cloned().zip(r.event_envelopes.iter().copied()).collect(),
            events_bytes: r.events_bytes.clone(),
            rejected: r.rejected.clone(),
            notes_before,
            nullifiers_before,
        });
    }

    /// Drops the last block. `indexer` has already rolled it back.
    pub fn rollback(&mut self, indexer: &Indexer) {
        let Some(b) = self.blocks.pop() else { return };
        let h = b.height;
        self.notes.truncate(b.notes_before);
        for k in 0..=DEPTH {
            self.levels[k].truncate(b.notes_before >> k);
        }
        for (_, nf) in self.nullifiers.drain(b.nullifiers_before..) {
            self.spent.remove(&nf);
        }
        self.txs.retain(|_, height| *height != h);
        self.tokens.retain(|t| match t.deploy {
            Some((_, height)) => height != h,
            None => h != self.profile.activation_height,
        });
        while self.listings.last().is_some_and(|l| l.height == h) {
            let l = self.listings.pop().expect("checked");
            self.listing_index.remove(&l.txid);
        }
        // a listing is taken once or closed once: what this block did to it is all there was
        for (e, _) in &b.events {
            match e {
                Event::Take { list_txid, .. } => {
                    if let Some(l) = self.listing_mut(list_txid) {
                        l.take = None;
                    }
                }
                Event::Closed { list_txid, .. } => {
                    if let Some(l) = self.listing_mut(list_txid) {
                        l.closed_by = None;
                    }
                }
                _ => {}
            }
        }
        self.sync(indexer);
    }

    fn listing_mut(&mut self, list_txid: &Bytes32) -> Option<&mut ListingView> {
        let i = *self.listing_index.get(list_txid)?;
        self.listings.get_mut(i)
    }

    fn new_token(&mut self, indexer: &Indexer, ticker: &Ticker, deploy: Option<(Bytes32, u32)>) {
        if let Some(t) = indexer.token(ticker) {
            self.tokens.push(TokenView { token: t.clone(), deploy });
        }
    }

    /// Takes the counters of every token and the state of every listing from the indexer.
    /// One pass over both for each block that has an event: enough for a signet.
    fn sync(&mut self, indexer: &Indexer) {
        for v in &mut self.tokens {
            if let Some(t) = indexer.token(&v.token.ticker) {
                v.token = t.clone();
            }
        }
        for v in &mut self.listings {
            if let Some(l) = indexer.listing(&v.txid) {
                v.listing.status = l.status;
            }
        }
    }

    // ---- the tree, for /path ----

    fn grow(&mut self, leaf: Fr) {
        self.levels[0].push(leaf);
        let mut k = 0;
        while k < DEPTH && self.levels[k].len().is_multiple_of(2) {
            let n = self.levels[k].len();
            let parent = h2(&self.levels[k][n - 2], &self.levels[k][n - 1]);
            self.levels[k + 1].push(parent);
            k += 1;
        }
    }

    /// Node `index` of height `k`: kept when all its leaves exist, `Z[k]` when none does, and
    /// computed from its two children otherwise (one such node per level at most).
    fn node(&self, k: usize, index: u64) -> Fr {
        if let Some(n) = self.levels[k].get(index as usize) {
            return *n;
        }
        if k == 0 || (index << k) >= self.notes.len() as u64 {
            return self.zeros[k];
        }
        h2(&self.node(k - 1, 2 * index), &self.node(k - 1, 2 * index + 1))
    }

    /// The siblings of leaf `pos`, from the leaf's level up to the root's children.
    pub fn siblings(&self, pos: u32) -> Option<Vec<Fr>> {
        if pos as usize >= self.notes.len() {
            return None;
        }
        Some((0..DEPTH).map(|k| self.node(k, (u64::from(pos) >> k) ^ 1)).collect())
    }

    /// The root of the tree of every leaf held.
    pub fn root(&self) -> Fr {
        self.node(DEPTH, 0)
    }

    // ---- reading: the routes ----

    fn status(&self) -> Value {
        let p = &self.profile;
        json!({
            "implementation": concat!("sh20-indexer-rs ", env!("CARGO_PKG_VERSION")),
            "network": self.network,
            "activationHeight": p.activation_height,
            "height": self.tip().map(|(h, _)| h),
            "hash": self.tip().map(|(_, hash)| hash),
            "digest": hex(&self.digest()),
            "root": fr_hex(&self.root()),
            "leaves": self.notes.len(),
            "nullifiers": self.nullifiers.len(),
            "tokens": self.tokens.len(),
            "genesis": Ticker::SH20.as_str(),
            "deployBurn": p.deploy_burn.to_string(),
            "deployMaturity": p.deploy_maturity,
            "anchorWindow": p.anchor_window,
            "anchorMinDepth": p.anchor_min_depth,
            "verifier": self.verifier,
        })
    }

    fn tx(&self, txid: &Bytes32) -> Option<Value> {
        let height = *self.txs.get(txid)?;
        let b = self.block_at(height)?;
        let events: Vec<&(Event, Option<u32>)> = b.events.iter().filter(|(e, _)| e.txid() == txid).collect();
        let rejections: Vec<&Rejection> = b.rejected.iter().filter(|r| r.txid == *txid).collect();
        // a batch has a verdict for each envelope and none for the whole
        let batch = events.iter().any(|(_, i)| i.is_some()) || rejections.iter().any(|r| r.envelope.is_some());
        // the verdict on the transaction's envelope: CLOSED is no envelope's event
        let verdict = events.iter().find(|(e, _)| !matches!(e, Event::Closed { .. })).filter(|_| !batch);
        let first = b.notes_before;
        let last = self.blocks.get((height - self.profile.activation_height) as usize + 1).map(|n| n.notes_before);
        let notes: Vec<Value> = self.notes[first..last.unwrap_or(self.notes.len())]
            .iter()
            .filter(|(_, n)| n.txid.as_ref() == Some(txid))
            .map(|(h, n)| note_json(*h, n))
            .collect();
        Some(json!({
            "txid": hex(txid),
            "height": height,
            "event": verdict.map(|(e, i)| event_json(e, *i)),
            "rejected": rejections.first().filter(|_| !batch).map(|r| r.reason),
            "events": events.iter().map(|(e, i)| event_json(e, *i)).collect::<Vec<_>>(),
            "rejections": rejections.iter().map(|r| rejection_json(r, false)).collect::<Vec<_>>(),
            "notes": notes,
        }))
    }

    /// Answers one request. `target` is the request target: a path and an optional query.
    pub fn respond(&self, method: &str, target: &str) -> Response {
        if method != "GET" {
            return error(405, "GET only");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match self.route(&segments, &Query::parse(query)) {
            Ok(r) => r,
            Err(e) => error(400, &e),
        }
    }

    fn route(&self, segments: &[&str], query: &Query) -> Result<Response, String> {
        let a = self.profile.activation_height;
        let tip = self.tip().map(|(h, _)| h);
        Ok(match segments {
            [] => ok(json!({
                "implementation": concat!("sh20-indexer-rs ", env!("CARGO_PKG_VERSION")),
                "routes": ROUTES,
            })),
            ["status"] => ok(self.status()),
            ["tokens"] => ok(self.tokens.iter().map(|t| token_json(t, a)).collect()),
            ["token", ticker] => {
                let ticker = Ticker::parse(ticker).ok_or("a ticker is 4 characters of [A-Z0-9]")?;
                match self.tokens.iter().find(|t| t.token.ticker == ticker) {
                    Some(t) => ok(token_json(t, a)),
                    None => not_found("token"),
                }
            }
            ["notes"] => {
                let from = query.number("from")?.unwrap_or(0).min(self.notes.len() as u64) as usize;
                let limit = query.number("limit")?.map_or(NOTES_LIMIT_DEFAULT, |n| (n as usize).min(NOTES_LIMIT_MAX));
                let to = from.saturating_add(limit).min(self.notes.len());
                let notes: Vec<Value> = self.notes[from..to].iter().map(|(h, n)| note_json(*h, n)).collect();
                ok(json!({ "from": from, "total": self.notes.len(), "notes": notes }))
            }
            ["path", pos] => {
                let pos: u32 = pos.parse().map_err(|_| "pos is a leaf position")?;
                match self.siblings(pos) {
                    Some(s) => ok(json!({
                        "pos": pos,
                        "height": tip,
                        "root": fr_hex(&self.root()),
                        "siblings": s.iter().map(fr_hex).collect::<Vec<_>>(),
                    })),
                    None => not_found("leaf"),
                }
            }
            ["roots"] => {
                let default = tip.map_or(a, |h| h.saturating_sub(self.profile.anchor_window));
                let from = query.height("from")?.unwrap_or(default).max(a);
                let roots: Vec<Value> = self
                    .blocks
                    .iter()
                    .skip((from - a) as usize)
                    .map(|b| json!({ "height": b.height, "root": fr_hex(&b.root) }))
                    .collect();
                ok(Value::Array(roots))
            }
            ["nullifier", nf] => {
                let mut le = unhex32(nf).ok_or("a nullifier is 64 hex characters")?;
                le.reverse();
                ok(json!({ "nullifier": le_hex(&le), "spent": self.spent.contains(&le) }))
            }
            ["nullifiers"] => {
                let from = query.height("from")?.unwrap_or(a);
                let start = self.nullifiers.partition_point(|(h, _)| *h < from);
                let list: Vec<Value> = self.nullifiers[start..]
                    .iter()
                    .map(|(h, nf)| json!({ "height": h, "nullifier": le_hex(nf) }))
                    .collect();
                ok(json!({ "from": from, "height": tip, "nullifiers": list }))
            }
            ["listings"] => {
                let state = match query.get("state") {
                    None => None,
                    Some(name) => Some(
                        [
                            ListingStatus::Active,
                            ListingStatus::Sold,
                            ListingStatus::Cancelled,
                            ListingStatus::Closed,
                            ListingStatus::Claimed,
                        ]
                        .into_iter()
                        .find(|s| s.name() == name)
                        .ok_or("state is ACTIVE, SOLD, CANCELLED, CLOSED or CLAIMED")?,
                    ),
                };
                let list = self.listings.iter().filter(|l| state.is_none_or(|s| l.listing.status == s));
                ok(list.map(listing_json).collect())
            }
            ["listing", txid] => {
                let txid = unhex32(txid).ok_or("a txid is 64 hex characters")?;
                match self.listing_index.get(&txid) {
                    Some(i) => ok(listing_json(&self.listings[*i])),
                    None => not_found("listing"),
                }
            }
            ["digest", height] => {
                let height: u32 = height.parse().map_err(|_| "height is a block height")?;
                match self.block_at(height) {
                    Some(b) => ok(json!({ "height": height, "digest": hex(&b.digest) })),
                    None => not_found("block"),
                }
            }
            ["blocks"] => {
                let before = query.height("before")?.unwrap_or(u32::MAX);
                let limit = query.number("limit")?.map_or(BLOCKS_LIMIT_DEFAULT, |n| (n as usize).min(BLOCKS_LIMIT_MAX));
                let end = (before.saturating_sub(a) as usize).min(self.blocks.len());
                let list = self.blocks[..end].iter().rev().filter(|b| !b.events.is_empty() || !b.rejected.is_empty());
                ok(list.take(limit).map(block_json).collect())
            }
            ["block", height] => {
                let height: u32 = height.parse().map_err(|_| "height is a block height")?;
                match self.block_at(height) {
                    Some(b) => ok(block_json(b)),
                    None => not_found("block"),
                }
            }
            ["tx", txid] => {
                let txid = unhex32(txid).ok_or("a txid is 64 hex characters")?;
                match self.tx(&txid) {
                    Some(t) => ok(t),
                    None => not_found("transaction"),
                }
            }
            _ => not_found("route"),
        })
    }
}

const ROUTES: &[&str] = &[
    "/status",
    "/tokens",
    "/token/:ticker",
    "/notes?from=0&limit=1000",
    "/path/:pos",
    "/roots?from=H",
    "/nullifier/:hex",
    "/nullifiers?from=H",
    "/listings?state=ACTIVE",
    "/listing/:txid",
    "/digest/:height",
    "/blocks?before=H&limit=20",
    "/block/:height",
    "/tx/:txid",
];

/// The parameters of a query string. Values are plain: digits and capitals, nothing to decode.
/// A parameter a route does not know is ignored; of one given twice, the first counts.
struct Query<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Query<'a> {
    fn parse(text: &'a str) -> Query<'a> {
        Query(text.split('&').map(|part| part.split_once('=').unwrap_or((part, ""))).collect())
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    fn number(&self, name: &str) -> Result<Option<u64>, String> {
        match self.get(name) {
            None => Ok(None),
            Some(v) if !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()) => {
                v.parse().map(Some).map_err(|_| format!("{name} is too large"))
            }
            Some(_) => Err(format!("{name} is a whole number")),
        }
    }

    fn height(&self, name: &str) -> Result<Option<u32>, String> {
        match self.number(name)? {
            None => Ok(None),
            Some(n) => u32::try_from(n).map(Some).map_err(|_| format!("{name} is a block height")),
        }
    }
}
