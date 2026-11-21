//! Following a chain: one block after the other from a source, back when it reorganises.
//!
//! The follower asks a `Source` for the best chain's block after its own tip and applies it
//! when it builds on that tip. When it does not, the chain has reorganised: the follower rolls
//! back block by block to the last one the source still has, then goes forward again. The
//! indexer keeps 288 blocks of undo; a deeper reorg stops the follower (`docs/API.md`).
//!
//! A source that fails (the node is down, the API refuses) is asked again later: nothing is
//! lost, the follower goes on from its tip. With a block file (`blocks::BlockFile`) it also
//! goes on after a restart, without asking the source for the blocks it had.

use crate::api::Store;
use crate::blocks::BlockFile;
use crate::chain::{carried, Block, Tx};
use crate::field::Bytes32;
use crate::state::{Error, Indexer};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A block as a source gives it: its hash, the hash of the block before it, its transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBlock {
    pub hash: String,
    pub prev: String,
    pub block: Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// Worth asking again later: the source is down, busy, or between two tips.
    Later(String),
    /// Asking again will not help: wrong credentials, a pruned block.
    Fatal(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Later(m) | SourceError::Fatal(m) => f.write_str(m),
        }
    }
}

/// Where blocks come from: Bitcoin Core, an Esplora server, or a test.
pub trait Source {
    /// The hash of the best chain's block at `height`; `None` above its tip.
    fn hash_at(&mut self, height: u32) -> Result<Option<String>, SourceError>;
    /// The block with that hash, with `prev_height` set on input 0 of every transaction that
    /// `state::needs_commit_height` names.
    fn block(&mut self, hash: &str) -> Result<SourceBlock, SourceError>;
    /// The network's name, when the source knows it.
    fn network(&mut self) -> Result<Option<String>, SourceError> {
        Ok(None)
    }
}

/// What one step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Applied the block at this height.
    Applied(u32),
    /// Rolled back the block at this height: it left the best chain.
    RolledBack(u32),
    /// Nothing to do: the tip is the source's tip (or the chain is still below activation).
    AtTip,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FollowError {
    /// The source failed; the step can be tried again.
    Later(String),
    /// The follower must stop: going on would serve a wrong state.
    Fatal(String),
}

impl From<SourceError> for FollowError {
    fn from(e: SourceError) -> FollowError {
        match e {
            SourceError::Later(m) => FollowError::Later(m),
            SourceError::Fatal(m) => FollowError::Fatal(m),
        }
    }
}

impl std::fmt::Display for FollowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FollowError::Later(m) | FollowError::Fatal(m) => f.write_str(m),
        }
    }
}

pub struct Follower<S: Source> {
    source: S,
    indexer: Indexer,
    store: Arc<RwLock<Store>>,
    file: Option<BlockFile>,
    /// The txid of every transaction kept so far for the envelope it carries.
    carriers: HashSet<Bytes32>,
    /// After a rollback: the new tip has not been checked against the source yet.
    unsure: bool,
}

/// Keeps of a block what the rules can read: the transactions that carry an envelope, and
/// those that spend an output of one (a lock is an output of its LIST transaction, so a
/// transaction that closes a listing is among them). §5 gives no effect to any other
/// transaction. Witnesses nobody reads are dropped.
///
/// `carriers` holds the txid of every transaction kept before for its envelope; the second
/// value is what this block adds to it.
pub fn relevant(block: &Block, carriers: &HashSet<Bytes32>) -> (Block, Vec<Bytes32>) {
    let mut txs: Vec<Tx> = Vec::new();
    let mut new: Vec<Bytes32> = Vec::new();
    for tx in &block.txs {
        let carries = !carried(tx).is_empty();
        let known = |txid: &Bytes32| carriers.contains(txid) || new.contains(txid);
        let spends = tx.vin.iter().any(|i| i.prevout.is_some_and(|(txid, _)| known(&txid)));
        if !carries && !spends {
            continue;
        }
        if carries {
            new.push(tx.txid);
        }
        let mut tx = tx.clone();
        for (n, input) in tx.vin.iter_mut().enumerate() {
            if n > 0 || input.coinbase {
                input.witness.clear();
            }
        }
        txs.push(tx);
    }
    (Block { height: block.height, txs }, new)
}

impl<S: Source> Follower<S> {
    /// `store` is shared with the HTTP server. With a block file, the blocks it holds are
    /// applied first: the follower starts where it stopped.
    pub fn new(
        source: S,
        indexer: Indexer,
        store: Arc<RwLock<Store>>,
        file: Option<(BlockFile, Vec<SourceBlock>)>,
    ) -> Result<Follower<S>, FollowError> {
        let mut f = Follower { source, indexer, store, file: None, carriers: HashSet::new(), unsure: false };
        if let Some((file, blocks)) = file {
            for b in &blocks {
                if let Some((height, hash)) = f.tip() {
                    if b.block.height != height + 1 || b.prev != hash {
                        return Err(FollowError::Fatal(format!(
                            "the block file does not hold a chain at block {}: delete it to start again",
                            b.block.height
                        )));
                    }
                }
                f.apply(b)?;
            }
            f.file = Some(file);
        }
        Ok(f)
    }

    pub fn indexer(&self) -> &Indexer {
        &self.indexer
    }

    pub fn source(&mut self) -> &mut S {
        &mut self.source
    }

    /// The last block applied: its height and its hash.
    pub fn tip(&self) -> Option<(u32, String)> {
        self.store.read().expect("store lock").tip().map(|(h, hash)| (h, hash.to_string()))
    }

    /// One block forward, one block back, or nothing.
    pub fn step(&mut self) -> Result<Step, FollowError> {
        let Some((height, hash)) = self.tip() else {
            // nothing applied yet: the activation block comes first
            let a = self.indexer.profile().activation_height;
            let Some(first) = self.source.hash_at(a)? else { return Ok(Step::AtTip) };
            let b = self.source.block(&first)?;
            return self.forward(b, a);
        };
        // in a reorg, roll back to the last block the source still has before any block is
        // fetched: one question for each block undone
        if self.unsure {
            if self.source.hash_at(height)?.as_deref() != Some(hash.as_str()) {
                self.back()?;
                return Ok(Step::RolledBack(height));
            }
            self.unsure = false;
        }
        match self.source.hash_at(height + 1)? {
            Some(next) => {
                let b = self.source.block(&next)?;
                if b.prev == hash {
                    return self.forward(b, height + 1);
                }
            }
            // no block after ours: at the tip, if ours is still the source's
            None => {
                if self.source.hash_at(height)?.as_deref() == Some(hash.as_str()) {
                    return Ok(Step::AtTip);
                }
            }
        }
        // the best chain does not go through our tip
        self.back()?;
        self.unsure = true;
        Ok(Step::RolledBack(height))
    }

    fn forward(&mut self, b: SourceBlock, height: u32) -> Result<Step, FollowError> {
        if b.block.height != height {
            return Err(FollowError::Later(format!(
                "asked for block {height}, the source gave block {}",
                b.block.height
            )));
        }
        let kept = self.apply(&b)?;
        if let Some(file) = &mut self.file {
            file.block(&kept).map_err(|e| FollowError::Fatal(format!("block file: {e}")))?;
        }
        Ok(Step::Applied(height))
    }

    /// Applies a block and returns what was kept of it.
    fn apply(&mut self, b: &SourceBlock) -> Result<SourceBlock, FollowError> {
        let (block, carriers) = relevant(&b.block, &self.carriers);
        let result = self.indexer.apply_block(&block).map_err(|e| match e {
            Error::MissingCommitHeight { .. } => FollowError::Fatal(format!("{e}; the source does not give it")),
            other => FollowError::Fatal(other.to_string()),
        })?;
        self.carriers.extend(carriers);
        self.store.write().expect("store lock").apply(&b.hash, &result, &self.indexer);
        Ok(SourceBlock { hash: b.hash.clone(), prev: b.prev.clone(), block })
    }

    fn back(&mut self) -> Result<(), FollowError> {
        let height = self.indexer.rollback().map_err(|_| {
            FollowError::Fatal(
                "the chain reorganised deeper than the undo history: restart to index it again \
                 from the activation block (and delete the block file first, if there is one)"
                    .into(),
            )
        })?;
        self.store.write().expect("store lock").rollback(&self.indexer);
        if let Some(file) = &mut self.file {
            file.rollback(height).map_err(|e| FollowError::Fatal(format!("block file: {e}")))?;
        }
        Ok(())
    }

    /// Steps until the tip is reached.
    pub fn catch_up(&mut self) -> Result<(), FollowError> {
        while self.step()? != Step::AtTip {}
        Ok(())
    }

    /// Follows for ever: waits `poll` at the tip, and longer and longer (up to a minute)
    /// while the source fails. Returns only with the error that stops it. `report` gets each
    /// step and each failure.
    pub fn run(&mut self, poll: Duration, mut report: impl FnMut(&Self, Result<&Step, &str>)) -> FollowError {
        let mut wait = Duration::from_secs(1);
        loop {
            match self.step() {
                Ok(step) => {
                    report(self, Ok(&step));
                    wait = Duration::from_secs(1);
                    if step == Step::AtTip {
                        std::thread::sleep(poll);
                    }
                }
                Err(FollowError::Later(m)) => {
                    report(self, Err(&m));
                    std::thread::sleep(wait);
                    wait = (wait * 2).min(Duration::from_secs(60));
                }
                Err(fatal) => return fatal,
            }
        }
    }
}
