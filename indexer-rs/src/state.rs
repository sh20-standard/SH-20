//! The state machine: acceptance rules (SPEC-WIRE §5), block processing and digest (§6),
//! and the per-block undo log for reorgs.

use crate::chain::{burned_sats, counted_envelopes, is_p2tr_to, paid_to, Block, Tx};
use crate::envelope::{body_hash_of, DecodeError, Deploy, Envelope, Spend, Ticker};
use crate::events::{encode_all, Event, Outcome, Spent};
use crate::field::{fr_from_le, fr_to_le, public_leaf, sha256, Bytes32};
use crate::tree::{Tree, TreeSnapshot};
use crate::verifier::{PublicInputs, SpendVerifier};
use ark_bn254::Fr;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// The profile constants of §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `A`: nothing before it is read.
    pub activation_height: u32,
    /// `D`: SH20 burned by every DEPLOY (0 turns the burn off).
    pub deploy_burn: u64,
    /// `W`.
    pub anchor_window: u32,
    /// `K_min`.
    pub anchor_min_depth: u32,
}

impl Profile {
    pub fn new(activation_height: u32, deploy_burn: u64) -> Profile {
        Profile { activation_height, deploy_burn, anchor_window: 100, anchor_min_depth: 1 }
    }
}

pub const GENESIS_MAX: u64 = 21_000_000;
pub const GENESIS_LIM: u64 = 1_000;
pub const LOCK_MIN_SATS: u64 = 330;
/// Blocks of undo kept by default.
pub const DEFAULT_UNDO_DEPTH: usize = 288;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub ticker: Ticker,
    pub max: u64,
    pub lim: u64,
    pub pre: u64,
    pub start: u32,
    pub end: u32,
    pub unlock: u32,
    pub price: u64,
    pub pay_mode: u8,
    pub pay_script: Vec<u8>,
    pub team_opening: Option<Bytes32>,
    /// Number of mints taken (a batch of `m` counts `m`).
    pub mints: u64,
    pub burned: u64,
    /// The turnstile: what entered the shielded pool in public minus what left it in public.
    pub pool: u64,
    pub team_unlocked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingStatus {
    Active,
    Sold,
    Cancelled,
    Closed,
    Claimed,
}

impl ListingStatus {
    pub fn name(&self) -> &'static str {
        match self {
            ListingStatus::Active => "ACTIVE",
            ListingStatus::Sold => "SOLD",
            ListingStatus::Cancelled => "CANCELLED",
            ListingStatus::Closed => "CLOSED",
            ListingStatus::Claimed => "CLAIMED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    pub ticker: Ticker,
    pub amount: u64,
    pub price: u64,
    pub pay_script: Vec<u8>,
    /// `(txid, lockVout)` of the LIST transaction.
    pub lock: (Bytes32, u32),
    /// The output key of the P2TR lock: the `lockKey` of the LIST.
    pub lock_key: Bytes32,
    pub status: ListingStatus,
}

/// An envelope the indexer refused. The reason is informative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub txid: Bytes32,
    pub reason: &'static str,
}

#[derive(Clone, Debug)]
pub struct BlockResult {
    pub height: u32,
    /// `R[H]`.
    pub root: Fr,
    pub events: Vec<Event>,
    /// `events_H`.
    pub events_bytes: Vec<u8>,
    /// `digest_H`.
    pub digest: Bytes32,
    pub rejected: Vec<Rejection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The block is not the one the indexer expects next (the first one is the activation block).
    UnexpectedHeight { expected: u32, got: u32 },
    /// A rollback deeper than the undo log.
    NoUndo,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedHeight { expected, got } => write!(f, "expected block {expected}, got block {got}"),
            Error::NoUndo => write!(f, "no undo data left for this block"),
        }
    }
}

impl std::error::Error for Error {}

enum UndoOp {
    TokenCreated(Ticker),
    TokenCounters { ticker: Ticker, mints: u64, burned: u64, pool: u64, team_unlocked: bool },
    ListingCreated(Bytes32),
    ListingStatus(Bytes32, ListingStatus),
    Nullifier(Bytes32),
}

struct Undo {
    tree: TreeSnapshot,
    digest: Bytes32,
    ops: Vec<UndoOp>,
}

type Reject = &'static str;

pub struct Indexer {
    profile: Profile,
    verifier: Box<dyn SpendVerifier>,
    tokens: BTreeMap<Ticker, Token>,
    /// Team notes still to come, by unlock block; tickers in byte order.
    unlocks: BTreeMap<u32, BTreeSet<Ticker>>,
    tree: Tree,
    nullifiers: HashSet<Bytes32>,
    /// Listings by the txid of their LIST transaction.
    listings: HashMap<Bytes32, Listing>,
    /// Lock outpoints of the ACTIVE listings.
    locks: HashMap<(Bytes32, u32), Bytes32>,
    /// `roots[i] = R[A + i]`.
    roots: Vec<Fr>,
    digest: Bytes32,
    undo: VecDeque<Undo>,
    undo_depth: usize,
    journal: Vec<UndoOp>,
}

impl Indexer {
    pub fn new(profile: Profile, verifier: Box<dyn SpendVerifier>) -> Indexer {
        Indexer {
            profile,
            verifier,
            tokens: BTreeMap::new(),
            unlocks: BTreeMap::new(),
            tree: Tree::new(),
            nullifiers: HashSet::new(),
            listings: HashMap::new(),
            locks: HashMap::new(),
            roots: Vec::new(),
            digest: sha256(&[b"sh20-v0"]),
            undo: VecDeque::new(),
            undo_depth: DEFAULT_UNDO_DEPTH,
            journal: Vec::new(),
        }
    }

    pub fn with_undo_depth(mut self, blocks: usize) -> Indexer {
        self.undo_depth = blocks;
        self
    }

    // ---- reading the state ----

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The last block applied, if any.
    pub fn tip(&self) -> Option<u32> {
        if self.roots.is_empty() {
            None
        } else {
            Some(self.profile.activation_height + (self.roots.len() as u32 - 1))
        }
    }

    /// The block `apply_block` expects.
    pub fn next_height(&self) -> u32 {
        self.profile.activation_height + self.roots.len() as u32
    }

    pub fn digest(&self) -> Bytes32 {
        self.digest
    }

    /// `R[h]` as a spend anchored at `h` sees it: the empty root before activation,
    /// `None` for a block not applied yet.
    pub fn root_at(&self, h: u32) -> Option<Fr> {
        if h < self.profile.activation_height {
            Some(self.tree.empty_root())
        } else {
            self.roots.get((h - self.profile.activation_height) as usize).copied()
        }
    }

    pub fn tree_size(&self) -> u64 {
        self.tree.size()
    }

    pub fn token(&self, ticker: &Ticker) -> Option<&Token> {
        self.tokens.get(ticker)
    }

    pub fn tokens(&self) -> impl Iterator<Item = &Token> {
        self.tokens.values()
    }

    pub fn listing(&self, list_txid: &Bytes32) -> Option<&Listing> {
        self.listings.get(list_txid)
    }

    pub fn listings(&self) -> impl Iterator<Item = (&Bytes32, &Listing)> {
        self.listings.iter()
    }

    pub fn nullifier_seen(&self, nf: &Bytes32) -> bool {
        self.nullifiers.contains(nf)
    }

    /// The identity of §5, for every ticker:
    /// `pool + Σ amount of ACTIVE and CLOSED listings + burned = mints·lim + pre if unlocked`.
    pub fn supply_holds(&self) -> bool {
        self.tokens.values().all(|t| {
            let escrow: u128 = self
                .listings
                .values()
                .filter(|l| l.ticker == t.ticker && matches!(l.status, ListingStatus::Active | ListingStatus::Closed))
                .map(|l| l.amount as u128)
                .sum();
            let issued = t.mints as u128 * t.lim as u128 + if t.team_unlocked { t.pre as u128 } else { 0 };
            t.pool as u128 + escrow + t.burned as u128 == issued
        })
    }

    // ---- blocks ----

    /// Applies the next block (§6). The first block must be the activation block.
    pub fn apply_block(&mut self, block: &Block) -> Result<BlockResult, Error> {
        let h = block.height;
        if h != self.next_height() {
            return Err(Error::UnexpectedHeight { expected: self.next_height(), got: h });
        }
        let tree_before = self.tree.snapshot();
        let digest_before = self.digest;
        self.journal.clear();
        let mut events = Vec::new();
        let mut rejected = Vec::new();

        // 1. genesis, team unlocks, then the transactions in block order
        if h == self.profile.activation_height {
            events.push(self.create_genesis(h));
        }
        if let Some(tickers) = self.unlocks.get(&h).cloned() {
            for ticker in tickers {
                if let Some(e) = self.unlock_team(ticker) {
                    events.push(e);
                }
            }
        }
        for tx in &block.txs {
            self.apply_tx(h, tx, &mut events, &mut rejected);
        }

        // 2. R[H]
        let root = self.tree.root();
        self.roots.push(root);

        // 3. digest
        let events_bytes = encode_all(&events);
        self.digest = sha256(&[&digest_before, &h.to_le_bytes(), &fr_to_le(&root), &sha256(&[&events_bytes])]);

        self.undo.push_back(Undo { tree: tree_before, digest: digest_before, ops: std::mem::take(&mut self.journal) });
        while self.undo.len() > self.undo_depth {
            self.undo.pop_front();
        }
        Ok(BlockResult { height: h, root, events, events_bytes, digest: self.digest, rejected })
    }

    /// Undoes the last block applied and returns its height.
    pub fn rollback(&mut self) -> Result<u32, Error> {
        let height = self.tip().ok_or(Error::NoUndo)?;
        let undo = self.undo.pop_back().ok_or(Error::NoUndo)?;
        for op in undo.ops.into_iter().rev() {
            match op {
                UndoOp::TokenCreated(ticker) => {
                    if let Some(t) = self.tokens.remove(&ticker) {
                        if let Some(set) = self.unlocks.get_mut(&t.unlock) {
                            set.remove(&ticker);
                            if set.is_empty() {
                                self.unlocks.remove(&t.unlock);
                            }
                        }
                    }
                }
                UndoOp::TokenCounters { ticker, mints, burned, pool, team_unlocked } => {
                    let t = self.tokens.get_mut(&ticker).expect("token of an undo record");
                    t.mints = mints;
                    t.burned = burned;
                    t.pool = pool;
                    t.team_unlocked = team_unlocked;
                }
                UndoOp::ListingCreated(txid) => {
                    if let Some(l) = self.listings.remove(&txid) {
                        self.locks.remove(&l.lock);
                    }
                }
                UndoOp::ListingStatus(txid, status) => {
                    let l = self.listings.get_mut(&txid).expect("listing of an undo record");
                    l.status = status;
                    if status == ListingStatus::Active {
                        self.locks.insert(l.lock, txid);
                    }
                }
                UndoOp::Nullifier(nf) => {
                    self.nullifiers.remove(&nf);
                }
            }
        }
        self.tree.restore(&undo.tree);
        self.digest = undo.digest;
        self.roots.pop();
        Ok(height)
    }

    /// Reorg: rolls back to the fork point, so that `height` is the tip again.
    /// A `height` below the activation block undoes everything.
    pub fn rollback_to(&mut self, height: u32) -> Result<(), Error> {
        while self.tip().is_some_and(|tip| tip > height) {
            self.rollback()?;
        }
        Ok(())
    }

    // ---- block events ----

    fn create_genesis(&mut self, h: u32) -> Event {
        let ticker = Ticker::SH20;
        self.tokens.insert(
            ticker,
            Token {
                ticker,
                max: GENESIS_MAX,
                lim: GENESIS_LIM,
                pre: 0,
                start: h,
                end: 0,
                unlock: h,
                price: 0,
                pay_mode: 0,
                pay_script: Vec::new(),
                team_opening: None,
                mints: 0,
                burned: 0,
                pool: 0,
                team_unlocked: false,
            },
        );
        self.journal.push(UndoOp::TokenCreated(ticker));
        Event::Genesis {
            ticker,
            max: GENESIS_MAX,
            lim: GENESIS_LIM,
            deploy_burn: self.profile.deploy_burn,
            window: self.profile.anchor_window,
            min_depth: self.profile.anchor_min_depth,
        }
    }

    fn unlock_team(&mut self, ticker: Ticker) -> Option<Event> {
        let t = self.tokens.get(&ticker)?;
        let opening = t.team_opening?;
        if t.team_unlocked || t.pre == 0 || self.tree.room() < 1 {
            return None; // a team note that does not fit is dropped: no event, pool unchanged (§5)
        }
        let pre = t.pre;
        let leaf = public_leaf(ticker.t(), pre, &fr_from_le(&opening)?);
        self.touch(ticker);
        let pos = self.tree.append(leaf);
        let t = self.tokens.get_mut(&ticker).expect("checked above");
        t.team_unlocked = true;
        t.pool += pre;
        Some(Event::TeamUnlock { ticker, pre, pos })
    }

    // ---- transactions ----

    fn apply_tx(&mut self, h: u32, tx: &Tx, events: &mut Vec<Event>, rejected: &mut Vec<Rejection>) {
        // the ACTIVE listings whose lock this transaction spends, in input order
        let mut spent_locks: Vec<Bytes32> = Vec::new();
        for input in &tx.vin {
            if let Some(list_txid) = input.prevout.and_then(|p| self.locks.get(&p)) {
                if !spent_locks.contains(list_txid) {
                    spent_locks.push(*list_txid);
                }
            }
        }

        // one counted envelope is applied; two or more refuse the transaction
        let found = counted_envelopes(tx);
        let outcome: Option<Result<Event, Reject>> = match found.as_slice() {
            [] => None,
            [raw] => Some(match Envelope::decode(raw) {
                Ok(env) => self.apply_envelope(h, tx, &env, raw, &spent_locks),
                Err(DecodeError::Rejected(reason)) => Err(reason),
                Err(_) => Err("not an SH-20 v0 envelope"),
            }),
            _ => Some(Err("more than one envelope")),
        };
        match outcome {
            Some(Ok(event)) => events.push(event),
            Some(Err(reason)) => rejected.push(Rejection { txid: tx.txid, reason }),
            None => {}
        }

        // a lock spent with no TAKE closes its listing
        for list_txid in spent_locks {
            if self.listings.get(&list_txid).is_some_and(|l| l.status == ListingStatus::Active) {
                self.set_status(list_txid, ListingStatus::Closed);
                events.push(Event::Closed { txid: tx.txid, list_txid });
            }
        }
    }

    /// Checks everything first, then applies: a rejected envelope changes nothing.
    fn apply_envelope(
        &mut self,
        h: u32,
        tx: &Tx,
        env: &Envelope,
        raw: &[u8],
        spent_locks: &[Bytes32],
    ) -> Result<Event, Reject> {
        let txid = tx.txid;
        match env {
            Envelope::Deploy(d) => self.apply_deploy(h, txid, d, raw),

            Envelope::Mint { ticker, opening, k } => {
                let t = self.tokens.get(ticker).ok_or("ticker not deployed")?;
                if t.start > h {
                    return Err("mint not open yet");
                }
                if t.end != 0 && h > t.end {
                    return Err("mint closed");
                }
                let left = (t.max - t.pre) / t.lim - t.mints;
                if left == 0 {
                    return Err("minted out");
                }
                let m = u64::from(k.unwrap_or(1)).min(left);
                let due = m as u128 * t.price as u128;
                let paid = match t.pay_mode {
                    1 => burned_sats(tx),
                    2 => paid_to(tx, &t.pay_script),
                    _ => 0,
                };
                if t.pay_mode != 0 && paid < due {
                    return Err("mint not paid");
                }
                if self.tree.room() < 1 {
                    return Err("no room in the tree");
                }
                let v = m * t.lim;
                let leaf = public_leaf(ticker.t(), v, &fr_from_le(opening).ok_or("opening is not a field element")?);
                self.touch(*ticker);
                let pos = self.tree.append(leaf);
                let t = self.tokens.get_mut(ticker).expect("checked above");
                t.mints += m;
                t.pool += v;
                Ok(Event::Mint { txid, ticker: *ticker, v, pos })
            }

            Envelope::Transfer { spend } => {
                self.check_spend(h, spend, raw, 0, 0)?;
                let spent = self.apply_spend(spend);
                Ok(Event::Transfer { txid, spent })
            }

            Envelope::Burn { ticker, v_pub, spend } => {
                let t = self.tokens.get(ticker).ok_or("ticker not deployed")?;
                if *v_pub == 0 {
                    return Err("vPub is zero");
                }
                if *v_pub > t.pool {
                    return Err("more than the pool holds of this ticker");
                }
                self.check_spend(h, spend, raw, *v_pub, ticker.t())?;
                self.touch(*ticker);
                let spent = self.apply_spend(spend);
                let t = self.tokens.get_mut(ticker).expect("checked above");
                t.burned += v_pub;
                t.pool -= v_pub;
                Ok(Event::Burn { txid, ticker: *ticker, v_pub: *v_pub, spent })
            }

            Envelope::List { ticker, amount, price, lock_vout, lock_key, pay_script, spend } => {
                let t = self.tokens.get(ticker).ok_or("ticker not deployed")?;
                if *amount == 0 {
                    return Err("amount is zero");
                }
                if *amount > t.pool {
                    return Err("more than the pool holds of this ticker");
                }
                if *price == 0 {
                    return Err("price is zero");
                }
                let lock_out = tx.vout.get(*lock_vout as usize).ok_or("no output at lockVout")?;
                if !is_p2tr_to(&lock_out.script, lock_key) {
                    return Err("lock output is not P2TR to lockKey");
                }
                if lock_out.value < LOCK_MIN_SATS {
                    return Err("lock output below 330 sats");
                }
                // §5 says a LIST txid is unique (BIP30, BIP34), and so gives no rule for a second
                // listing under one txid; it is refused here (SPEC-GAPS R4)
                if self.listings.contains_key(&txid) {
                    return Err("a listing with this txid exists");
                }
                self.check_spend(h, spend, raw, *amount, ticker.t())?;
                self.touch(*ticker);
                let spent = self.apply_spend(spend);
                self.tokens.get_mut(ticker).expect("checked above").pool -= amount;
                let lock = (txid, *lock_vout as u32);
                self.listings.insert(
                    txid,
                    Listing {
                        ticker: *ticker,
                        amount: *amount,
                        price: *price,
                        pay_script: pay_script.clone(),
                        lock,
                        lock_key: *lock_key,
                        status: ListingStatus::Active,
                    },
                );
                self.locks.insert(lock, txid);
                self.journal.push(UndoOp::ListingCreated(txid));
                Ok(Event::List { txid, ticker: *ticker, amount: *amount, price: *price, spent })
            }

            Envelope::Take { opening } => {
                let list_txid = *spent_locks.first().ok_or("no ACTIVE listing's lock is spent")?;
                let l = self.listings.get(&list_txid).ok_or("no ACTIVE listing's lock is spent")?;
                if self.tree.room() < 1 {
                    return Err("no room in the tree");
                }
                let (ticker, amount) = (l.ticker, l.amount);
                let outcome =
                    if paid_to(tx, &l.pay_script) >= l.price as u128 { Outcome::Sold } else { Outcome::Cancelled };
                let leaf =
                    public_leaf(ticker.t(), amount, &fr_from_le(opening).ok_or("opening is not a field element")?);
                self.touch(ticker);
                let pos = self.tree.append(leaf);
                self.tokens.get_mut(&ticker).expect("token of a listing").pool += amount;
                self.set_status(
                    list_txid,
                    match outcome {
                        Outcome::Sold => ListingStatus::Sold,
                        Outcome::Cancelled => ListingStatus::Cancelled,
                    },
                );
                Ok(Event::Take { txid, list_txid, outcome, pos })
            }

            Envelope::Claim { list_txid, opening, sig } => {
                let l = self.listings.get(list_txid).ok_or("no such listing")?;
                if l.status != ListingStatus::Closed {
                    return Err("listing is not CLOSED");
                }
                let msg = sha256(&[b"sh20/v0/claim", list_txid, opening]);
                if !bip340_verify(&l.lock_key, &msg, sig) {
                    return Err("bad claim signature");
                }
                if self.tree.room() < 1 {
                    return Err("no room in the tree");
                }
                let (ticker, amount) = (l.ticker, l.amount);
                let leaf =
                    public_leaf(ticker.t(), amount, &fr_from_le(opening).ok_or("opening is not a field element")?);
                self.touch(ticker);
                let pos = self.tree.append(leaf);
                self.tokens.get_mut(&ticker).expect("token of a listing").pool += amount;
                self.set_status(*list_txid, ListingStatus::Claimed);
                Ok(Event::Claim { txid, list_txid: *list_txid, pos })
            }
        }
    }

    fn apply_deploy(&mut self, h: u32, txid: Bytes32, d: &Deploy, raw: &[u8]) -> Result<Event, Reject> {
        if self.tokens.contains_key(&d.ticker) {
            return Err("ticker already deployed");
        }
        if d.max == 0 || d.lim == 0 {
            return Err("max or lim is zero");
        }
        if d.pre >= d.max {
            return Err("no public mint left (pre >= max)");
        }
        if !(d.max - d.pre).is_multiple_of(d.lim) {
            return Err("(max - pre) is not a multiple of lim");
        }
        if d.start <= h {
            return Err("start is not after this block");
        }
        if d.end != 0 && d.end < d.start {
            return Err("end before start");
        }
        if d.unlock < d.start {
            return Err("unlock before start");
        }
        if (d.pay_mode == 0) != (d.price == 0) {
            return Err("payMode 0 goes with price 0, and only with it");
        }
        let burn = self.profile.deploy_burn;
        match (&d.spend, burn) {
            (None, 0) => {}
            (Some(_), 0) => return Err("a spend in a DEPLOY while D = 0"),
            (None, _) => return Err("DEPLOY without the burn of D"),
            (Some(spend), _) => self.check_spend(h, spend, raw, burn, Ticker::SH20.t())?,
        }

        let burn_spent = match &d.spend {
            Some(spend) => {
                self.touch(Ticker::SH20);
                let spent = self.apply_spend(spend);
                let sh20 = self.tokens.get_mut(&Ticker::SH20).expect("pool checked by the spend");
                sh20.burned += burn;
                sh20.pool -= burn;
                Some(spent)
            }
            None => None,
        };
        self.tokens.insert(
            d.ticker,
            Token {
                ticker: d.ticker,
                max: d.max,
                lim: d.lim,
                pre: d.pre,
                start: d.start,
                end: d.end,
                unlock: d.unlock,
                price: d.price,
                pay_mode: d.pay_mode,
                pay_script: d.pay_script.clone(),
                team_opening: d.team_opening,
                mints: 0,
                burned: 0,
                pool: 0,
                team_unlocked: false,
            },
        );
        if d.pre > 0 {
            self.unlocks.entry(d.unlock).or_default().insert(d.ticker);
        }
        self.journal.push(UndoOp::TokenCreated(d.ticker));
        Ok(Event::Deploy { txid, ticker: d.ticker, burn: burn_spent })
    }

    // ---- spends ----

    /// "Every spend" of §5, with the turnstile before the proof.
    fn check_spend(&self, h: u32, spend: &Spend, raw: &[u8], v_pub: u64, t_pub: u32) -> Result<(), Reject> {
        let p = &self.profile;
        let anchor = spend.anchor_height as u64;
        if anchor + p.anchor_min_depth as u64 > h as u64 {
            return Err("anchor too recent");
        }
        if anchor + (p.anchor_window as u64) < h as u64 {
            return Err("anchor too old");
        }
        let root = self.root_at(spend.anchor_height).ok_or("anchor root unknown")?;

        if v_pub > 0 {
            let pool = self.tokens.get(&Ticker(t_pub.to_be_bytes())).map_or(0, |t| t.pool);
            if v_pub > pool {
                return Err("more than the pool holds of this ticker");
            }
        }

        let zero = [0u8; 32];
        if spend.nf[0] == zero || spend.nf[1] == zero {
            return Err("zero nullifier");
        }
        if spend.nf[0] == spend.nf[1] {
            return Err("the two nullifiers are equal");
        }
        if spend.nf.iter().any(|nf| self.nullifiers.contains(nf)) {
            return Err("nullifier already seen");
        }
        if spend.outputs.iter().any(|o| o.leaf == zero) {
            return Err("zero output leaf");
        }
        if self.tree.room() < 3 {
            return Err("no room in the tree");
        }

        let field = |b: &Bytes32| fr_from_le(b).ok_or("not a field element");
        let inputs = PublicInputs {
            root,
            nf: [field(&spend.nf[0])?, field(&spend.nf[1])?],
            leaves: [field(&spend.outputs[0].leaf)?, field(&spend.outputs[1].leaf)?, field(&spend.outputs[2].leaf)?],
            body_hash: body_hash_of(raw),
            v_pub,
            t_pub,
        };
        if !self.verifier.verify_spend(&inputs, &spend.proof) {
            return Err("invalid proof");
        }
        Ok(())
    }

    /// Records the nullifiers and appends the 3 leaves. `check_spend` passed first.
    fn apply_spend(&mut self, spend: &Spend) -> Spent {
        for nf in spend.nf {
            self.nullifiers.insert(nf);
            self.journal.push(UndoOp::Nullifier(nf));
        }
        let mut pos = [0u32; 3];
        for (i, o) in spend.outputs.iter().enumerate() {
            pos[i] = self.tree.append(fr_from_le(&o.leaf).expect("checked by check_spend"));
        }
        Spent { nf: spend.nf, pos }
    }

    // ---- undo bookkeeping ----

    /// Saves a token's counters before they change.
    fn touch(&mut self, ticker: Ticker) {
        if let Some(t) = self.tokens.get(&ticker) {
            self.journal.push(UndoOp::TokenCounters {
                ticker,
                mints: t.mints,
                burned: t.burned,
                pool: t.pool,
                team_unlocked: t.team_unlocked,
            });
        }
    }

    fn set_status(&mut self, list_txid: Bytes32, status: ListingStatus) {
        let l = self.listings.get_mut(&list_txid).expect("listing exists");
        self.journal.push(UndoOp::ListingStatus(list_txid, l.status));
        if l.status == ListingStatus::Active && status != ListingStatus::Active {
            self.locks.remove(&l.lock);
        }
        l.status = status;
    }
}

/// BIP340 verification with libsecp256k1 (the `secp256k1` crate).
pub fn bip340_verify(xonly_key: &Bytes32, msg: &Bytes32, sig: &[u8; 64]) -> bool {
    use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
    let Ok(key) = XOnlyPublicKey::from_byte_array(*xonly_key) else {
        return false;
    };
    let sig = Signature::from_byte_array(*sig);
    Secp256k1::verification_only().verify_schnorr(&sig, msg, &key).is_ok()
}
