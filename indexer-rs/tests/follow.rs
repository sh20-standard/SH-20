//! The follower over a chain in memory: the vectors' scenario block after block, its reorg,
//! a source that fails, a reorg too deep, and a restart from the block file.

mod common;

use common::fake::*;
use common::*;
use sh20_indexer::blocks::{BlockFile, FILE_NAME};
use sh20_indexer::chain::{counted, Tx};
use sh20_indexer::field::hex;
use sh20_indexer::follow::{relevant, FollowError, Follower, Source, SourceBlock, Step};
use sh20_indexer::{Indexer, TestVerifier};
use std::collections::HashSet;
use std::path::PathBuf;

fn digests(v: &serde_json::Value, part: &str) -> Vec<String> {
    v[part]["after"].as_array().unwrap().iter().map(|a| a["digest"].as_str().unwrap().to_string()).collect()
}

/// Steps until the tip, whatever fails on the way, and returns the steps taken.
fn follow<S: Source>(f: &mut Follower<S>) -> Vec<Step> {
    let mut steps = Vec::new();
    loop {
        match f.step() {
            Ok(Step::AtTip) => return steps,
            Ok(step) => steps.push(step),
            Err(FollowError::Later(_)) => {}
            Err(FollowError::Fatal(m)) => panic!("{m}"),
        }
    }
}

fn data_dir(name: &str) -> PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A follower that keeps its blocks in `dir`.
fn with_file<S: Source>(v: &serde_json::Value, source: S, dir: &std::path::Path) -> Result<Follower<S>, String> {
    let p = profile(v);
    let file = BlockFile::open(dir, p.activation_height)?;
    let indexer = Indexer::new(p, Box::new(TestVerifier));
    Follower::new(source, indexer, new_store(v), Some(file)).map_err(|e| e.to_string())
}

/// Block after block as the chain grows: the vectors' digest at every height, with
/// transactions that carry nothing all around the scenario's.
#[test]
fn follows_the_scenario() {
    let v = vectors();
    let blocks = scenario(&v, true);
    let want = digests(&v, "scenario");
    let chain = Chain::new(Vec::new());
    let (mut f, store) = follower(&v, chain.clone());
    // the chain is still below the activation block
    assert_eq!(f.step(), Ok(Step::AtTip));
    assert_eq!(get(&store, "/status")["height"], serde_json::Value::Null);

    for (n, b) in blocks.iter().enumerate() {
        chain.state().blocks.push(b.clone());
        let height = b.block.height;
        assert_eq!(f.step(), Ok(Step::Applied(height)));
        assert_eq!(f.step(), Ok(Step::AtTip));
        assert_eq!(f.tip(), Some((height, b.hash.clone())));
        assert_eq!(hex(&f.indexer().digest()), want[n], "digest of block {height}");
        assert_eq!(get(&store, &format!("/digest/{height}"))["digest"], want[n]);
        assert_eq!(get(&store, "/status")["digest"], want[n]);
    }
    assert!(f.indexer().supply_holds());
    // each block was fetched once
    assert_eq!(chain.state().fetched, (1..=17).collect::<Vec<u32>>());
}

/// The vectors' reorg: blocks 16 and 17 give way to two others. The follower undoes them,
/// asking the source one hash for each, applies the new ones, and ends in the state of a
/// follower that never saw the first two.
#[test]
fn reorg_of_the_vectors() {
    let v = vectors();
    let chain = Chain::new(scenario(&v, true));
    let (mut f, store) = follower(&v, chain.clone());
    f.catch_up().unwrap();
    let before = dump(&store);

    chain.set(reorged(&v, true));
    chain.state().fetched.clear();
    assert_eq!(follow(&mut f), [Step::RolledBack(17), Step::RolledBack(16), Step::Applied(16), Step::Applied(17)]);
    // undoing costs hashes only: the two new blocks are the only ones fetched
    assert_eq!(chain.state().fetched, [16, 17]);
    assert_eq!(hex(&f.indexer().digest()), *digests(&v, "reorg").last().unwrap());

    let (mut fresh, fresh_store) = follower(&v, Chain::new(reorged(&v, true)));
    fresh.catch_up().unwrap();
    let after = dump(&store);
    assert_eq!(after, dump(&fresh_store));
    assert_ne!(after, before);

    // and back: the first chain wins again
    chain.set(scenario(&v, true));
    assert_eq!(follow(&mut f).len(), 4);
    assert_eq!(dump(&store), before);
}

/// The source's tip falls below ours (the new branch is still shorter): the follower undoes
/// what is gone and waits. Nothing it serves meanwhile comes from a block that left the chain.
#[test]
fn reorg_to_a_shorter_chain() {
    let v = vectors();
    let blocks = scenario(&v, false);
    let chain = Chain::new(blocks.clone());
    let (mut f, store) = follower(&v, chain.clone());
    f.catch_up().unwrap();
    let full = dump(&store);

    chain.set(blocks[..14].to_vec());
    assert_eq!(follow(&mut f), [Step::RolledBack(17), Step::RolledBack(16), Step::RolledBack(15)]);
    let (mut short, short_store) = follower(&v, Chain::new(blocks[..14].to_vec()));
    short.catch_up().unwrap();
    assert_eq!(dump(&store), dump(&short_store));
    assert_eq!(get(&store, "/status")["height"], 14);
    assert_eq!(status_of(&store, "/block/15"), 404);

    chain.set(blocks);
    assert_eq!(follow(&mut f), [Step::Applied(15), Step::Applied(16), Step::Applied(17)]);
    assert_eq!(dump(&store), full);
}

/// A reorg below the activation block undoes everything, the genesis token included.
#[test]
fn reorg_of_the_activation_block() {
    let v = vectors();
    let blocks = scenario(&v, false);
    let chain = Chain::new(blocks[..2].to_vec());
    let (mut f, store) = follower(&v, chain.clone());
    f.catch_up().unwrap();
    let empty = dump(&follower(&v, Chain::default()).1);

    // another block 1, with nothing in it
    let mut other = blocks[0].clone();
    other.hash = block_hash(1, 9);
    other.block.txs.clear();
    chain.set(vec![other]);
    assert_eq!(follow(&mut f), [Step::RolledBack(2), Step::RolledBack(1), Step::Applied(1)]);
    assert_eq!(get(&store, "/tokens").as_array().unwrap().len(), 1);
    assert_eq!(get(&store, "/notes")["total"], 0);

    chain.set(Vec::new());
    assert_eq!(follow(&mut f), [Step::RolledBack(1)]);
    assert_eq!(dump(&store), empty);
    assert_eq!(get(&store, "/tokens").as_array().unwrap().len(), 0);
}

/// `docs/API.md`: a reorg deeper than the undo history stops the follower with an error.
#[test]
fn reorg_deeper_than_the_undo_history() {
    let v = vectors();
    let store = new_store(&v);
    let indexer = Indexer::new(profile(&v), Box::new(TestVerifier)).with_undo_depth(3);
    let chain = Chain::new(scenario(&v, false));
    let mut f = Follower::new(chain.clone(), indexer, store.clone(), None).unwrap();
    f.catch_up().unwrap();

    // three blocks can be undone
    let mut fork = scenario(&v, false);
    fork.truncate(14);
    chain.set(fork.clone());
    assert_eq!(follow(&mut f).len(), 3);
    // the fourth cannot: the follower stops rather than serve the state of a dead branch
    fork.truncate(13);
    chain.set(fork);
    assert!(matches!(f.step(), Err(FollowError::Fatal(m)) if m.contains("undo history")));
    assert_eq!(get(&store, "/status")["height"], 14);
}

/// A source that fails is asked again: wherever the failure falls, in the scenario or in its
/// reorg, the follower ends in the same state, and no failed step leaves a trace.
#[test]
fn a_source_that_fails_is_asked_again() {
    let v = vectors();
    let (mut calm, calm_store) = follower(&v, Chain::new(scenario(&v, true)));
    calm.catch_up().unwrap();
    let want = dump(&calm_store);
    let calm_chain = Chain::new(scenario(&v, true));
    let (mut counter, _) = follower(&v, calm_chain.clone());
    counter.catch_up().unwrap();
    let calls = calm_chain.state().calls;
    assert!(calls > 34);

    for failing in 0..calls {
        let chain = Chain::new(scenario(&v, true));
        chain.state().fail_call = Some(failing);
        let (mut f, store) = follower(&v, chain.clone());
        let mut failures = 0;
        loop {
            let before = (f.tip(), f.indexer().digest());
            match f.step() {
                Ok(Step::AtTip) => break,
                Ok(_) => {}
                Err(FollowError::Later(_)) => {
                    failures += 1;
                    assert_eq!((f.tip(), f.indexer().digest()), before, "a failed step changes nothing");
                }
                Err(FollowError::Fatal(m)) => panic!("{m}"),
            }
        }
        assert_eq!(failures, 1, "call {failing}");
        assert_eq!(get(&store, "/status"), want["/status"], "call {failing}");
    }

    // down for a while in the middle of a reorg, then back
    let chain = Chain::new(scenario(&v, true));
    let (mut f, store) = follower(&v, chain.clone());
    f.catch_up().unwrap();
    chain.set(reorged(&v, true));
    assert_eq!(f.step(), Ok(Step::RolledBack(17)));
    chain.state().down = true;
    for _ in 0..5 {
        assert!(matches!(f.step(), Err(FollowError::Later(_))));
    }
    assert_eq!(get(&store, "/status")["height"], 16);
    chain.state().down = false;
    assert_eq!(follow(&mut f), [Step::RolledBack(16), Step::Applied(16), Step::Applied(17)]);
    let (mut fresh, fresh_store) = follower(&v, Chain::new(reorged(&v, true)));
    fresh.catch_up().unwrap();
    assert_eq!(dump(&store), dump(&fresh_store));
}

/// SPEC-WIRE §5: without the height of the commit a DEPLOY reveals, an indexer stops. The
/// block is not applied, and what the API serves is the state before it.
#[test]
fn a_missing_commit_height_stops_the_follower() {
    let v = vectors();
    let mut blocks = scenario(&v, true);
    for tx in &mut blocks[3].block.txs {
        tx.vin[0].prev_height = None;
    }
    let (mut f, store) = follower(&v, Chain::new(blocks));
    for height in 1..=3 {
        assert_eq!(f.step(), Ok(Step::Applied(height)));
    }
    let before = dump(&store);
    for _ in 0..2 {
        assert!(matches!(f.step(), Err(FollowError::Fatal(m)) if m.contains("block 4") && m.contains("DEPLOY")));
    }
    assert_eq!(dump(&store), before);
    assert_eq!(get(&store, "/status")["digest"], digests(&v, "scenario")[2]);
}

/// What the follower keeps of a block: the transactions that carry an envelope and those
/// that spend an output of one. The vectors' digests, reached by `follows_the_scenario` with
/// the other transactions left out, show that nothing else is read.
#[test]
fn relevant_keeps_what_the_rules_read() {
    let v = vectors();
    let (plain, noisy) = (scenario(&v, false), scenario(&v, true));
    let mut carriers = HashSet::new();
    let mut bare = 0;
    for (p, n) in plain.iter().zip(&noisy) {
        assert_eq!(n.block.txs.len(), p.block.txs.len() + 3);
        let (kept, new) = relevant(&n.block, &carriers);
        // exactly the scenario's transactions, in their order
        assert_eq!(kept, p.block, "block {}", p.block.height);
        assert_eq!(new, p.block.txs.iter().filter(|t| !counted(t).is_empty()).map(|t| t.txid).collect::<Vec<_>>());
        bare += kept.txs.len() - new.len();
        carriers.extend(new);
    }
    // block 10 has a transaction with no envelope that spends a lock: it is kept
    assert_eq!(bare, 1);

    // a lock spent in the block of its LIST, and a witness nobody reads
    let list = witness_tx(1, &transfer(0, 1));
    let mut spender = Tx { txid: txid(2), vin: vec![input(5), spending(list.txid, 1)], vout: Vec::new() };
    spender.vin[1].witness = vec![vec![7; 64]];
    let other = Tx { txid: txid(3), vin: vec![spending(txid(99), 0)], vout: Vec::new() };
    let (kept, new) = relevant(&block(5, vec![other, list.clone(), spender.clone()]), &HashSet::new());
    spender.vin[1].witness.clear();
    assert_eq!(kept, block(5, vec![list.clone(), spender]));
    assert_eq!(new, [list.txid]);
}

/// With a block file, a follower that starts again goes on from its last block: it asks the
/// source for no block it had, and ends in the state of one that never stopped. A reorg met
/// while following, or one that happened while it was stopped, is undone the same way.
#[test]
fn restart_goes_on_from_the_block_file() {
    let v = vectors();
    let dir = data_dir("follow-restart");
    let (mut whole, whole_store) = follower(&v, Chain::new(scenario(&v, true)));
    whole.catch_up().unwrap();

    // first run: up to block 10
    let chain = Chain::new(scenario(&v, true)[..10].to_vec());
    let mut first = with_file(&v, chain.clone(), &dir).unwrap();
    first.catch_up().unwrap();
    assert_eq!(first.tip().unwrap().0, 10);
    drop(first);

    // second run: starts at block 10 without the source, then follows to 17
    let chain = Chain::new(scenario(&v, true));
    let p = profile(&v);
    let store = new_store(&v);
    let file = BlockFile::open(&dir, p.activation_height).unwrap();
    assert_eq!(file.1.len(), 10);
    let mut second =
        Follower::new(chain.clone(), Indexer::new(p, Box::new(TestVerifier)), store.clone(), Some(file)).unwrap();
    assert_eq!(second.tip(), Some((10, block_hash(10, 0))));
    assert_eq!(chain.state().calls, 0);
    second.catch_up().unwrap();
    assert_eq!(chain.state().fetched, (11..=17).collect::<Vec<u32>>());
    assert_eq!(dump(&store), dump(&whole_store));

    // the file holds what the rules read and no more
    let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
    assert_eq!(text.lines().count(), 1 + 17);
    assert!(!text.contains(&hex(&noise_txid(4, 1))) && !text.contains(&hex(&noise_txid(17, 2))));
    let scenario_txs: usize = scenario(&v, false).iter().map(|b| b.block.txs.len()).sum();
    assert_eq!(text.matches("\"vin\"").count(), scenario_txs);

    // a reorg while following goes to the file as two rollbacks and two blocks
    chain.set(reorged(&v, true));
    assert_eq!(follow(&mut second).len(), 4);
    let after_reorg = dump(&store);
    drop(second);
    let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
    assert_eq!((text.lines().count(), text.matches("\"rollback\"").count()), (1 + 17 + 4, 2));

    // third run, on the reorged chain: the same state from the file alone, and a tidy file
    let chain = Chain::new(reorged(&v, true));
    let store = new_store(&v);
    let file = BlockFile::open(&dir, p.activation_height).unwrap();
    let mut third =
        Follower::new(chain.clone(), Indexer::new(p, Box::new(TestVerifier)), store.clone(), Some(file)).unwrap();
    assert_eq!(third.step(), Ok(Step::AtTip));
    assert!(chain.state().fetched.is_empty());
    assert_eq!(dump(&store), after_reorg);
    let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
    assert_eq!((text.lines().count(), text.matches("\"rollback\"").count()), (1 + 17, 0));
    drop(third);

    // fourth run: the chain reorganised back while the follower was stopped
    let chain = Chain::new(scenario(&v, true));
    let mut fourth = with_file(&v, chain.clone(), &dir).unwrap();
    assert_eq!(follow(&mut fourth), [Step::RolledBack(17), Step::RolledBack(16), Step::Applied(16), Step::Applied(17)]);
    assert_eq!(hex(&fourth.indexer().digest()), *digests(&v, "scenario").last().unwrap());
}

/// What can be wrong with a block file: a last line cut short by a crash (dropped), another
/// activation height, a damaged line, blocks that do not follow one another.
#[test]
fn block_file_damage() {
    use std::io::Write;
    let v = vectors();
    let dir = data_dir("follow-damage");
    let blocks = scenario(&v, false);
    let mut f = with_file(&v, Chain::new(blocks[..6].to_vec()), &dir).unwrap();
    f.catch_up().unwrap();
    drop(f);
    let path = dir.join(FILE_NAME);
    let whole = std::fs::read_to_string(&path).unwrap();

    // a crash in the middle of writing block 7
    let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"{\"height\":7,\"hash\":\"ab").unwrap();
    drop(file);
    let mut f = with_file(&v, Chain::new(blocks.clone()), &dir).unwrap();
    assert_eq!(f.tip().unwrap().0, 6);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), whole);
    assert_eq!(f.step(), Ok(Step::Applied(7)));
    drop(f);

    // written for another activation height
    let err = BlockFile::open(&dir, 2).err().unwrap();
    assert!(err.contains("activation height 1, not 2"), "{err}");

    // a whole line that is not a block
    let good = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, good.replacen("\"txs\"", "\"sxt\"", 1)).unwrap();
    let err = with_file(&v, Chain::default(), &dir).err().unwrap();
    assert!(err.contains("line 2"), "{err}");

    // blocks that are not a chain: block 3 is missing
    let lines: Vec<&str> = good.lines().collect();
    std::fs::write(&path, [&lines[..3], &lines[4..]].concat().join("\n") + "\n").unwrap();
    let err = with_file(&v, Chain::default(), &dir).err().unwrap();
    assert!(err.contains("does not hold a chain at block 4"), "{err}");

    // not a block file at all
    std::fs::write(&path, "{\"hello\":1}\n").unwrap();
    assert!(BlockFile::open(&dir, 1).is_err());

    // an empty file is a new one
    std::fs::write(&path, "").unwrap();
    let (_, held): (BlockFile, Vec<SourceBlock>) = BlockFile::open(&dir, 1).unwrap();
    assert!(held.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
}
