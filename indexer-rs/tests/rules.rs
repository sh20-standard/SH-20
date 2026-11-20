//! Rules the vectors do not exercise: both carriers at their edges, the mint window and its
//! payment, every DEPLOY condition, the anchor window, nullifiers, the life of a listing
//! (CANCELLED, CLOSED, CLAIM), team unlocks, and reorgs.
//!
//! These tests state this implementation's reading of the spec. Where the spec left a choice,
//! `docs/SPEC-GAPS.md` says which one was made.

mod common;

use common::*;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sh20_indexer::chain::{counted, envelopes, is_batch, tapscript as tapscript_of, witness_envelopes, Tx, TxIn};
use sh20_indexer::envelope::{body_hash_of, Deploy, Envelope, Ticker};
use sh20_indexer::events::{Event, Outcome};
use sh20_indexer::field::{fr_to_le, sha256, unhex, unhex32};
use sh20_indexer::json::block_from_vector;
use sh20_indexer::state::{bip340_verify, Error};
use sh20_indexer::tree::Tree;
use sh20_indexer::verifier::{PublicInputs, RejectAll, SpendVerifier, TestVerifier};
use sh20_indexer::{Indexer, ListingStatus, Profile};
use std::cell::RefCell;
use std::rc::Rc;

const PAY: &[u8] = &[0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

// ---------------------------------------------------------------- carriers

#[test]
fn op_return_carrier() {
    let env = mint("SH20", 1, None);
    let tx = op_return_tx(1, &env, 0);
    assert_eq!(envelopes(&tx), vec![env.clone()]);

    let with_script = |script: Vec<u8>| Tx { vout: vec![out(0, &script)], ..tx.clone() };
    // PUSHDATA1 for 42 bytes is not minimal
    let mut s = vec![0x6a, 0x4c, env.len() as u8];
    s.extend_from_slice(&env);
    assert!(envelopes(&with_script(s)).is_empty());
    // PUSHDATA2 for 42 bytes neither
    let mut s = vec![0x6a, 0x4d, env.len() as u8, 0];
    s.extend_from_slice(&env);
    assert!(envelopes(&with_script(s)).is_empty());
    // two pushes
    let mut s = op_return_script(&env);
    s.extend(push(b"more"));
    assert!(envelopes(&with_script(s)).is_empty());
    // an opcode after the push
    let mut s = op_return_script(&env);
    s.push(0x51);
    assert!(envelopes(&with_script(s)).is_empty());
    // a push that runs past the end of the script
    let mut s = op_return_script(&env);
    s.pop();
    assert!(envelopes(&with_script(s)).is_empty());
    // not OP_RETURN first
    assert!(envelopes(&with_script(push(&env))).is_empty());
    // another magic
    assert!(envelopes(&with_script(op_return_script(b"SH21\x00\x02"))).is_empty());
    // 134 bytes need PUSHDATA1, and a direct opcode cannot say it
    let claim = Envelope::Claim { list_txid: [1; 32], opening: fe(1), sig: [2; 64] }.encode();
    let s = op_return_script(&claim);
    assert_eq!(s[1], 0x4c);
    assert_eq!(envelopes(&with_script(s)), vec![claim]);
    // 300 bytes in PUSHDATA2 is minimal; the same in PUSHDATA4 is not
    let mut long = b"SH20".to_vec();
    long.resize(300, 0xaa);
    assert_eq!(envelopes(&with_script(op_return_script(&long))), vec![long.clone()]);
    let mut s = vec![0x6a, 0x4e, 0x2c, 0x01, 0, 0];
    s.extend_from_slice(&long);
    assert!(envelopes(&with_script(s)).is_empty());
    // 65,535 bytes is the longest push of OP_PUSHDATA2; above, the minimal form is OP_PUSHDATA4
    long.resize(65_535, 0xaa);
    long[4] = 0x00; // version 0, so that it counts
    let mut s = vec![0x6a, 0x4d, 0xff, 0xff];
    s.extend_from_slice(&long);
    assert_eq!(envelopes(&with_script(s)), vec![long.clone()]);
    let mut s = vec![0x6a, 0x4e, 0xff, 0xff, 0x00, 0x00];
    s.extend_from_slice(&long);
    assert!(envelopes(&with_script(s)).is_empty());
    long.push(0xaa);
    let mut pushdata4 = vec![0x6a, 0x4e, 0x00, 0x00, 0x01, 0x00];
    pushdata4.extend_from_slice(&long);
    assert_eq!(envelopes(&with_script(pushdata4.clone())), vec![long.clone()]);
    // such an envelope counts: alone it is refused by the decoder, and beside a real one the
    // transaction has two envelopes
    let mut two = op_return_tx(2, &env, 0);
    two.vout.push(out(0, &pushdata4));
    assert_eq!(sh20_indexer::chain::counted_envelopes(&two).len(), 2);
    let mut ix = indexer(1, 0);
    assert_eq!(apply(&mut ix, 1, vec![two]).1, ["more than one envelope"]);
}

#[test]
fn witness_carrier() {
    let env = transfer(1, 1);
    let tx = witness_tx(1, &env);
    assert_eq!(envelopes(&tx), vec![env.clone()]);
    let script = tapscript(&env);

    let with_witness = |w: Vec<Vec<u8>>| Tx { vin: vec![TxIn { witness: w, ..tx.vin[0].clone() }], ..tx.clone() };
    // the annex is ignored
    let w = vec![vec![1; 64], script.clone(), control_block(), vec![0x50, 1, 2]];
    assert_eq!(envelopes(&with_witness(w)), vec![env.clone()]);
    // no signature needed on the stack
    assert_eq!(envelopes(&with_witness(vec![script.clone(), control_block()])), vec![env.clone()]);
    // a longer control block (two path elements)
    let mut control = control_block();
    control.extend_from_slice(&[3; 64]);
    assert_eq!(envelopes(&with_witness(vec![script.clone(), control.clone()])), vec![env.clone()]);
    // odd parity bit in the control byte is still leaf version 0xc0
    control[0] = 0xc1;
    assert_eq!(envelopes(&with_witness(vec![script.clone(), control])), vec![env.clone()]);

    // not a script-path spend of a tapscript
    assert!(envelopes(&with_witness(vec![script.clone()])).is_empty());
    assert!(envelopes(&with_witness(vec![])).is_empty());
    assert!(envelopes(&with_witness(vec![control_block(), script.clone()])).is_empty());
    let mut other_leaf = control_block();
    other_leaf[0] = 0xc2;
    assert!(envelopes(&with_witness(vec![script.clone(), other_leaf])).is_empty());
    let mut short = control_block();
    short.pop();
    assert!(envelopes(&with_witness(vec![script.clone(), short])).is_empty());
    // with an annex, the script is still the one before the control block
    assert!(envelopes(&with_witness(vec![script.clone(), control_block(), vec![0x50], vec![0x50]])).is_empty());

    // input 0 only
    let moved = Tx { vin: vec![input(5), tx.vin[0].clone()], ..tx.clone() };
    assert!(envelopes(&moved).is_empty());
}

#[test]
fn witness_script_shapes() {
    let env = mint("SH20", 1, None);
    let good = envelope_script(&env);
    assert_eq!(witness_envelopes(&good), vec![env.clone()]);
    // anywhere in the script, with anything around it
    let mut s = vec![0x51, 0x75];
    s.extend(&good);
    s.extend([0x51]);
    assert_eq!(witness_envelopes(&s), vec![env.clone()]);

    // the envelope is "SH20" ‖ concat(pushes): any split gives the same bytes
    let mut s = vec![0x00, 0x63];
    s.extend(push(b"SH20"));
    for chunk in env[4..].chunks(7) {
        s.extend(push(chunk));
    }
    s.push(0x00); // an empty push adds nothing
    s.push(0x68);
    assert_eq!(witness_envelopes(&s), vec![env.clone()]);
    // "SH20" alone, with no other push
    let mut s = vec![0x00, 0x63];
    s.extend(push(b"SH20"));
    s.push(0x68);
    assert_eq!(witness_envelopes(&s), vec![b"SH20".to_vec()]);

    // the magic must be its own push
    let mut s = vec![0x00, 0x63];
    s.extend(push(&env));
    s.push(0x68);
    assert!(witness_envelopes(&s).is_empty());
    // no OP_ENDIF
    let mut s = good.clone();
    s.pop();
    assert!(witness_envelopes(&s).is_empty());
    // an opcode among the pushes
    let mut s = good.clone();
    s.insert(s.len() - 1, 0x75);
    assert!(witness_envelopes(&s).is_empty());
    // a non-minimal push among the pushes
    let mut s = vec![0x00, 0x63];
    s.extend(push(b"SH20"));
    s.extend([0x4c, (env.len() - 4) as u8]);
    s.extend(&env[4..]);
    s.push(0x68);
    assert!(witness_envelopes(&s).is_empty());
    // a one-byte push that has its own opcode: `01 05` is not minimal, OP_5 is
    let mut tail = env[4..].to_vec();
    tail.push(5);
    let build = |last: &[u8]| {
        let mut s = vec![0x00, 0x63];
        s.extend(push(b"SH20"));
        s.extend(push(&env[4..]));
        s.extend(last);
        s.push(0x68);
        s
    };
    assert!(witness_envelopes(&build(&[0x01, 0x05])).is_empty());
    let mut with_five = b"SH20".to_vec();
    with_five.extend(&tail);
    assert_eq!(witness_envelopes(&build(&[0x55])), vec![with_five]);
    // OP_1 OP_IF is not the pattern, and neither is OP_0 OP_NOTIF
    let mut s = good.clone();
    s[0] = 0x51;
    assert!(witness_envelopes(&s).is_empty());
    let mut s = good.clone();
    s[1] = 0x64;
    assert!(witness_envelopes(&s).is_empty());
    // the pattern inside the data of a push is not an envelope
    assert!(witness_envelopes(&push(&good)).is_empty());
    // a script that does not parse to its end carries nothing
    let mut s = good.clone();
    s.extend([0x4c, 0x10, 0x01]);
    assert!(witness_envelopes(&s).is_empty());

    // pushes of 520 bytes at most
    let mut long = b"SH20".to_vec();
    long.resize(4 + 521, 0xaa);
    let mut s = vec![0x00, 0x63];
    s.extend(push(b"SH20"));
    s.extend(push(&long[4..]));
    s.push(0x68);
    assert!(witness_envelopes(&s).is_empty());
    long.pop();
    assert_eq!(witness_envelopes(&envelope_script(&long)), vec![long]);

    // two envelopes in one script are two envelopes
    let mut s = good.clone();
    s.extend(&good);
    assert_eq!(witness_envelopes(&s).len(), 2);

    assert!(tapscript_of(&[vec![1], vec![2]]).is_none());
}

#[test]
fn at_most_one_envelope() {
    let mut ix = indexer(1, 0);
    let a = mint("SH20", 1, None);
    let b = mint("SH20", 2, None);

    // two OP_RETURN envelopes: the transaction is rejected, nothing is minted
    let mut two = op_return_tx(1, &a, 0);
    two.vout.push(out(0, &op_return_script(&b)));
    // one OP_RETURN and one witness envelope: rejected too
    let mut mixed = witness_tx(2, &a);
    mixed.vout.push(out(0, &op_return_script(&b)));
    // two envelopes in one tapscript
    let mut twice = witness_tx(3, &a);
    twice.vin[0].witness[1].extend(envelope_script(&b));
    // an envelope and one the decoder refuses (unknown type): still two envelopes
    let mut bad_type = b.clone();
    bad_type[5] = 0x09;
    let mut with_bad = op_return_tx(4, &a, 0);
    with_bad.vout.push(out(0, &op_return_script(&bad_type)));
    let (events, rejected) = apply(&mut ix, 1, vec![two, mixed, twice, with_bad]);
    assert_eq!(events, ["GENESIS"]);
    assert_eq!(rejected, ["more than one envelope"; 4]);
    assert_eq!(ix.tree_size(), 0);

    // an unknown version is ignored: the v0 envelope beside it applies
    let mut v1 = b.clone();
    v1[4] = 0x01;
    let mut with_v1 = op_return_tx(5, &a, 0);
    with_v1.vout.insert(0, out(0, &op_return_script(&v1)));
    // alone, it is neither an event nor a refusal
    let only_v1 = op_return_tx(6, &v1, 0);
    // an OP_RETURN that is not SH-20 beside an envelope changes nothing
    let mut with_other = op_return_tx(7, &b, 0);
    with_other.vout.push(out(0, &op_return_script(b"hello world")));
    let (events, rejected) = apply(&mut ix, 2, vec![with_v1, only_v1, with_other]);
    assert_eq!(events, ["MINT", "MINT"]);
    assert!(rejected.is_empty());
}

#[test]
fn any_transaction_can_carry_an_envelope() {
    // a coinbase has no outpoint to spend, and its outputs are read like any other
    let mut ix = indexer(1, 0);
    let mut coinbase = op_return_tx(1, &mint("SH20", 1, None), 0);
    coinbase.vin = vec![TxIn { prevout: None, coinbase: true, prev_height: None, witness: vec![vec![0; 32]] }];
    // the witness of a coinbase input is not looked at, whatever its shape
    let mut with_witness = witness_tx(8, &mint("SH20", 8, None));
    with_witness.vin[0].prevout = None;
    assert_eq!(envelopes(&with_witness).len(), 1);
    with_witness.vin[0].coinbase = true;
    assert!(envelopes(&with_witness).is_empty());
    let (events, rejected) = apply(&mut ix, 1, vec![coinbase, with_witness]);
    assert_eq!(events, ["GENESIS", "MINT"]);
    assert!(rejected.is_empty());
    // a small envelope may ride in a witness, and a spend in an OP_RETURN
    let (events, rejected) =
        apply(&mut ix, 2, vec![witness_tx(2, &mint("SH20", 2, None)), op_return_tx(3, &transfer(1, 1), 0)]);
    assert_eq!(events, ["MINT", "TRANSFER"]);
    assert!(rejected.is_empty());
}

// ---------------------------------------------------------------- batches

/// A batch (§3): two or more counted envelopes, all in the witness, all of type 0x03. Each
/// applies alone, in the order of the tapscript, and is accepted or refused by itself.
#[test]
fn batch_of_transfers() {
    let mut ix = indexer(1, 0);
    let mut bad_proof = spend(0, 4);
    bad_proof.proof[0] ^= 1;
    let mut cut_short = transfer(0, 5);
    cut_short.pop(); // type byte 0x03, and it does not decode
    let batch = batch_tx(
        1,
        &[
            transfer(0, 1),
            transfer(0, 2),
            transfer(0, 1), // the first one again
            Envelope::Transfer { spend: bad_proof }.encode(),
            cut_short,
            transfer(1, 6), // anchored at this very block
            transfer(0, 7),
        ],
    );
    assert!(is_batch(&counted(&batch)));
    let r = ix.apply_block(&block(1, vec![batch.clone()])).unwrap();
    // the accepted ones, in order, each with the batch's txid and the next free leaves
    let transfers: Vec<([u8; 32], [u32; 3])> = r.events[1..]
        .iter()
        .map(|e| match e {
            Event::Transfer { txid, spent } => (*txid, spent.pos),
            other => panic!("{}", other.name()),
        })
        .collect();
    assert_eq!(transfers, [(batch.txid, [0, 1, 2]), (batch.txid, [3, 4, 5]), (batch.txid, [6, 7, 8])]);
    // the refused ones, each alone, by its index in the transaction
    let refused: Vec<(Option<u32>, &str)> = r.rejected.iter().map(|x| (x.envelope, x.reason)).collect();
    assert_eq!(
        refused,
        [
            (Some(2), "nullifier already seen"),
            (Some(3), "invalid proof"),
            (Some(4), "truncated spend section"),
            (Some(5), "anchor too recent")
        ]
    );
    assert!(r.rejected.iter().all(|x| x.txid == batch.txid));
    assert_eq!(ix.tree_size(), 9);
    // a refused envelope recorded nothing: its nullifiers are still free
    assert!(!ix.nullifier_seen(&spend(0, 4).nf[0]));
    assert_eq!(apply(&mut ix, 2, vec![witness_tx(2, &transfer(0, 4))]).0, ["TRANSFER"]);
}

#[test]
fn what_is_a_batch_and_what_is_not() {
    let (a, b) = (transfer(0, 1), transfer(0, 2));
    let mint_env = mint("SH20", 3, None);
    let outcome = |tx: Tx| {
        let mut ix = indexer(1, 0);
        let r = ix.apply_block(&block(1, vec![tx])).unwrap();
        let events: Vec<&str> = r.events[1..].iter().map(|e| e.name()).collect();
        let refused: Vec<Option<u32>> = r.rejected.iter().map(|x| x.envelope).collect();
        (events, refused)
    };
    let whole = (vec![], vec![None]); // the transaction refused as one

    // two TRANSFERs in the witness: a batch
    assert_eq!(outcome(batch_tx(1, &[a.clone(), b.clone()])), (vec!["TRANSFER", "TRANSFER"], vec![]));
    // one TRANSFER is not a batch: its refusal carries no index
    assert_eq!(outcome(witness_tx(1, &transfer(1, 1))), (vec![], vec![None]));
    // another type among them
    assert_eq!(outcome(batch_tx(1, &[a.clone(), mint_env.clone()])), whole);
    assert_eq!(outcome(batch_tx(1, &[mint_env.clone(), mint("SH20", 4, None)])), whole);
    let burn = Envelope::Burn { ticker: Ticker::SH20, v_pub: 1, spend: spend(0, 5) }.encode();
    assert_eq!(outcome(batch_tx(1, &[a.clone(), burn])), whole);
    // one of them outside the witness
    let mut with_op_return = witness_tx(1, &a);
    with_op_return.vout.push(out(0, &op_return_script(&b)));
    assert_eq!(outcome(with_op_return), whole);
    let mut both_op_return = op_return_tx(1, &a, 0);
    both_op_return.vout.push(out(0, &op_return_script(&b)));
    assert_eq!(outcome(both_op_return), whole);
    let mut batch_and_mint = batch_tx(1, &[a.clone(), b.clone()]);
    batch_and_mint.vout.push(out(0, &op_return_script(&mint_env)));
    assert_eq!(outcome(batch_and_mint), whole);

    // the type byte decides, not the decoding: `SH20 00 03` and nothing else is in the batch,
    // refused alone; an envelope with no type byte keeps the transaction from being a batch
    assert_eq!(outcome(batch_tx(1, &[a.clone(), b"SH20\x00\x03".to_vec()])), (vec!["TRANSFER"], vec![Some(1)]));
    assert_eq!(outcome(batch_tx(1, &[a.clone(), b"SH20\x00".to_vec()])), whole);
    assert_eq!(outcome(batch_tx(1, &[a.clone(), b"SH20".to_vec()])), whole);

    // an envelope of another version is not counted: it neither breaks a batch nor makes one,
    // and the index of a refusal counts the counted envelopes only
    let mut v1 = a.clone();
    v1[4] = 1;
    assert_eq!(outcome(batch_tx(1, &[a.clone(), v1.clone(), b.clone()])), (vec!["TRANSFER", "TRANSFER"], vec![]));
    assert_eq!(outcome(batch_tx(1, &[a.clone(), v1.clone()])), (vec!["TRANSFER"], vec![]));
    assert_eq!(outcome(batch_tx(1, &[v1.clone(), transfer(1, 6), b.clone()])), (vec!["TRANSFER"], vec![Some(0)]));
    let mut with_v1_out = batch_tx(1, &[a.clone(), b.clone()]);
    with_v1_out.vout.push(out(0, &op_return_script(&v1)));
    assert_eq!(outcome(with_v1_out), (vec!["TRANSFER", "TRANSFER"], vec![]));

    // the witness of a coinbase is not read, batch or not
    let mut coinbase = batch_tx(1, &[a.clone(), b.clone()]);
    coinbase.vin[0].coinbase = true;
    assert_eq!(outcome(coinbase), (vec![], vec![]));
}

/// A batch that spends a lock: its envelopes first, then the listing it closes.
#[test]
fn batch_then_closed() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0)]);
    apply(&mut ix, 2, vec![list_tx(10, 400, 5_000, &p2tr(&[3; 32]), 330)]);
    let mut batch = batch_tx(20, &[transfer(2, 20), transfer(2, 20), transfer(2, 21)]);
    batch.vin.push(spending(txid(10), 1));
    let r = ix.apply_block(&block(3, vec![batch])).unwrap();
    let names: Vec<&str> = r.events.iter().map(|e| e.name()).collect();
    assert_eq!(names, ["TRANSFER", "TRANSFER", "CLOSED"]);
    assert_eq!(r.events[2], Event::Closed { txid: txid(20), list_txid: txid(10) });
    assert_eq!(r.rejected.iter().map(|x| x.envelope).collect::<Vec<_>>(), [Some(1)]);
    assert_eq!(ix.listing(&txid(10)).unwrap().status, ListingStatus::Closed);
    assert!(ix.supply_holds());
}

/// A member of a batch is judged against the state the members before it left (§3). One
/// refused for its proof spent nothing, so a later member of the same batch may spend its
/// nullifiers. A TRANSFER already applied alone is refused when a batch carries it again, in
/// the same block or a later one, and the other members still apply.
#[test]
fn batch_members_see_what_the_ones_before_left() {
    let mut ix = indexer(1, 0);
    let mut bad_proof = spend(0, 1);
    bad_proof.proof[0] ^= 1;
    let mut shares_one = spend(0, 2);
    shares_one.nf[0] = bad_proof.nf[0];
    let first = batch_tx(
        1,
        &[
            Envelope::Transfer { spend: bad_proof.clone() }.encode(),
            Envelope::Transfer { spend: shares_one.clone() }.encode(),
        ],
    );
    let alone = witness_tx(2, &transfer(0, 3));
    let copy_first = batch_tx(3, &[transfer(0, 3), transfer(0, 4)]);
    let r = ix.apply_block(&block(1, vec![first, alone, copy_first])).unwrap();
    let transfers: Vec<([u8; 32], [[u8; 32]; 2])> = r.events[1..]
        .iter()
        .map(|e| match e {
            Event::Transfer { txid, spent } => (*txid, spent.nf),
            other => panic!("{}", other.name()),
        })
        .collect();
    assert_eq!(transfers, [(txid(1), shares_one.nf), (txid(2), spend(0, 3).nf), (txid(3), spend(0, 4).nf)]);
    let refused: Vec<([u8; 32], Option<u32>, &str)> =
        r.rejected.iter().map(|x| (x.txid, x.envelope, x.reason)).collect();
    assert_eq!(refused, [(txid(1), Some(0), "invalid proof"), (txid(3), Some(0), "nullifier already seen")]);
    // of the refused proof's nullifiers, only the one the next member spent is spent
    assert!(ix.nullifier_seen(&bad_proof.nf[0]) && !ix.nullifier_seen(&bad_proof.nf[1]));
    assert_eq!(ix.tree_size(), 9);

    // a later block: two copies refused, each alone, around a new TRANSFER that applies
    let again = batch_tx(4, &[transfer(0, 4), transfer(0, 5), transfer(0, 3)]);
    let r = ix.apply_block(&block(2, vec![again])).unwrap();
    assert_eq!(r.events.iter().map(|e| e.name()).collect::<Vec<_>>(), ["TRANSFER"]);
    assert_eq!(r.rejected.iter().map(|x| x.envelope).collect::<Vec<_>>(), [Some(0), Some(2)]);
    assert_eq!(ix.tree_size(), 12);
}

// ---------------------------------------------------------------- blocks and digest

#[test]
fn block_order_and_empty_digest() {
    let mut ix = indexer(10, 0);
    assert_eq!(ix.tip(), None);
    assert_eq!(ix.digest(), sha256(&[b"sh20-v0"]));
    assert_eq!(ix.apply_block(&block(9, vec![])).unwrap_err(), Error::UnexpectedHeight { expected: 10, got: 9 });
    assert_eq!(ix.apply_block(&block(11, vec![])).unwrap_err(), Error::UnexpectedHeight { expected: 10, got: 11 });
    let r10 = ix.apply_block(&block(10, vec![])).unwrap();
    assert_eq!(r10.events.len(), 1);
    assert_eq!(ix.apply_block(&block(10, vec![])).unwrap_err(), Error::UnexpectedHeight { expected: 11, got: 10 });
    assert_eq!(ix.apply_block(&block(12, vec![])).unwrap_err(), Error::UnexpectedHeight { expected: 11, got: 12 });

    // GENESIS: 0x80 ‖ 32 zero bytes ‖ SH20 ‖ max ‖ lim ‖ D ‖ W ‖ K_min ‖ N
    let mut genesis = vec![0x80];
    genesis.extend([0u8; 32]);
    genesis.extend(b"SH20");
    genesis.extend(21_000_000u64.to_le_bytes());
    genesis.extend(1_000u64.to_le_bytes());
    genesis.extend(0u64.to_le_bytes());
    genesis.extend(100u32.to_le_bytes());
    genesis.extend(1u32.to_le_bytes());
    genesis.extend(0u32.to_le_bytes()); // N of this test profile
    assert_eq!(genesis.len(), 73);
    assert_eq!(r10.events_bytes, genesis);
    let empty_root = fr_to_le(&Tree::new().empty_root());
    let d10 = sha256(&[&sha256(&[b"sh20-v0"]), &10u32.to_le_bytes(), &empty_root, &sha256(&[&genesis])]);
    assert_eq!(r10.digest, d10);

    // a block with no event has an empty events_H
    let r11 = ix.apply_block(&block(11, vec![])).unwrap();
    assert!(r11.events_bytes.is_empty());
    assert_eq!(r11.digest, sha256(&[&d10, &11u32.to_le_bytes(), &empty_root, &sha256(&[])]));
    assert_eq!(ix.tip(), Some(11));

    // another profile, another digest from the activation block on
    let mut other = indexer(10, 1);
    assert_ne!(other.apply_block(&block(10, vec![])).unwrap().digest, d10);
}

// ---------------------------------------------------------------- MINT

fn deploy_tx(n: u64, d: Deploy) -> Tx {
    reveal_tx(n, &Envelope::Deploy(d).encode(), 0)
}

#[test]
fn mint_window() {
    let mut ix = indexer(1, 0);
    let d = Deploy { end: 4, ..deploy("WIND", 3) };
    assert_eq!(apply(&mut ix, 1, vec![deploy_tx(1, d)]).0, ["GENESIS", "DEPLOY"]);
    let m = |n: u64| op_return_tx(n, &mint("WIND", n, None), 0);
    assert_eq!(
        apply(&mut ix, 2, vec![m(2), op_return_tx(9, &mint("NONE", 9, None), 0)]).1,
        ["mint not open yet", "ticker not deployed"]
    );
    assert_eq!(apply(&mut ix, 3, vec![m(3)]).0, ["MINT"]);
    assert_eq!(apply(&mut ix, 4, vec![m(4)]).0, ["MINT"]);
    assert_eq!(apply(&mut ix, 5, vec![m(5)]).1, ["mint closed"]);
    assert_eq!(ix.token(&tk("WIND")).unwrap().mints, 2);
    // the genesis token mints from the activation block, with no end and no price
    assert_eq!(apply(&mut ix, 6, vec![op_return_tx(6, &mint("SH20", 6, Some(10)), 0)]).0, ["MINT"]);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 10_000);
}

#[test]
fn mint_payment() {
    let mut ix = indexer(1, 0);
    let burn = Deploy { price: 100, pay_mode: 1, ..deploy("BURN", 2) };
    let pay = Deploy { price: 100, pay_mode: 2, pay_script: PAY.to_vec(), ..deploy("PAYS", 2) };
    assert_eq!(apply(&mut ix, 1, vec![deploy_tx(1, burn), deploy_tx(2, pay)]).0, ["GENESIS", "DEPLOY", "DEPLOY"]);

    let other_script = [0x51u8];
    let mut n = 10;
    let mut tx = |ticker: &str, k: Option<u8>, on_envelope: u64, outs: &[(u64, &[u8])]| {
        n += 1;
        let mut t = op_return_tx(n, &mint(ticker, n, k), on_envelope);
        t.vout.extend(outs.iter().map(|(v, s)| out(*v, s)));
        t
    };
    let burn_script = [0x6au8, 0x01, 0x42];
    let txs = vec![
        // payMode 1: OP_RETURN outputs carry the price
        tx("BURN", None, 100, &[]),                  // on the envelope's own output
        tx("BURN", None, 40, &[(60, &burn_script)]), // summed over OP_RETURN outputs
        tx("BURN", None, 99, &[(1_000, PAY)]),       // a payment elsewhere does not count
        tx("BURN", Some(3), 299, &[]),               // k × price
        tx("BURN", Some(3), 300, &[]),
        // payMode 2: outputs to payScript
        tx("PAYS", None, 0, &[(100, PAY)]),
        tx("PAYS", None, 0, &[(60, PAY), (40, PAY)]),
        tx("PAYS", None, 100, &[(99, PAY), (1_000, &other_script)]), // burning does not pay
        tx("PAYS", Some(2), 0, &[(199, PAY)]),
        tx("PAYS", Some(2), 0, &[(200, PAY)]),
    ];
    let (events, rejected) = apply(&mut ix, 2, txs);
    assert_eq!(events, ["MINT"; 6]);
    assert_eq!(rejected, ["mint not paid"; 4]);
    assert_eq!(ix.token(&tk("BURN")).unwrap().mints, 5);
    assert_eq!(ix.token(&tk("PAYS")).unwrap().mints, 4);
    assert_eq!(ix.token(&tk("PAYS")).unwrap().pool, 4_000);
}

#[test]
fn last_batch_gets_what_is_left() {
    let mut ix = indexer(1, 0);
    // 5 mints in all, 100 sats each
    let d = Deploy {
        max: 6_000,
        pre: 1_000,
        unlock: 50,
        team_opening: Some(fe(1)),
        price: 100,
        pay_mode: 1,
        ..deploy("LAST", 2)
    };
    apply(&mut ix, 1, vec![deploy_tx(1, d)]);
    let m = |n: u64, k: Option<u8>, sats: u64| op_return_tx(n, &mint("LAST", n, k), sats);
    let r = ix
        .apply_block(&block(
            2,
            vec![m(2, Some(3), 300), m(3, Some(10), 199), m(4, Some(10), 200), m(5, None, 100), m(6, Some(2), 200)],
        ))
        .unwrap();
    // 3 minted; then a batch of 10 gets the 2 left and pays for 2; then nothing is left
    let minted: Vec<u64> = r
        .events
        .iter()
        .map(|e| match e {
            Event::Mint { v, .. } => *v,
            _ => panic!(),
        })
        .collect();
    assert_eq!(minted, [3_000, 2_000]);
    let reasons: Vec<&str> = r.rejected.iter().map(|x| x.reason).collect();
    assert_eq!(reasons, ["mint not paid", "minted out", "minted out"]);
    let t = ix.token(&tk("LAST")).unwrap();
    assert_eq!((t.mints, t.pool), (5, 5_000));
    assert!(ix.supply_holds());
}

// ---------------------------------------------------------------- DEPLOY

#[test]
fn deploy_conditions() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![]);
    apply(&mut ix, 2, vec![]);
    let base = deploy("AAAA", 4);
    let bad: Vec<Deploy> = vec![
        Deploy { max: 0, lim: 1, ..base.clone() },
        Deploy { lim: 0, ..base.clone() },
        Deploy { pre: 1_000_000, team_opening: Some(fe(1)), ..base.clone() }, // pre = max: no public mint
        Deploy { pre: 2_000_000, team_opening: Some(fe(1)), ..base.clone() },
        Deploy { pre: 500, team_opening: Some(fe(1)), ..base.clone() }, // (max − pre) mod lim ≠ 0
        Deploy { start: 3, unlock: 3, ..base.clone() },                 // start = H
        Deploy { start: 2, unlock: 4, ..base.clone() },
        Deploy { end: 3, ..base.clone() },      // end < start
        Deploy { unlock: 3, ..base.clone() },   // unlock < start, even with pre = 0
        Deploy { price: 1, ..base.clone() },    // a price with payMode 0
        Deploy { pay_mode: 1, ..base.clone() }, // payMode 1 with price 0
        Deploy { pay_mode: 2, pay_script: PAY.to_vec(), ..base.clone() },
        Deploy { ticker: Ticker::SH20, ..base.clone() }, // the genesis ticker is taken
    ];
    let count = bad.len();
    let txs: Vec<Tx> = bad.into_iter().enumerate().map(|(i, d)| deploy_tx(i as u64, d)).collect();
    let (events, rejected) = apply(&mut ix, 3, txs);
    assert!(events.is_empty(), "{events:?}");
    assert_eq!(rejected.len(), count);
    assert!(ix.token(&tk("AAAA")).is_none());

    let base = deploy("AAAA", 5); // one block later, start must still be after H
    let good: Vec<Deploy> = vec![
        base.clone(),
        Deploy { ticker: tk("BBBB"), end: 5, start: 5, unlock: 5, ..base.clone() }, // end = start
        Deploy { ticker: tk("CCCC"), pre: 999_000, team_opening: Some(fe(1)), unlock: 4_000_000_000, ..base.clone() },
        Deploy { ticker: tk("DDDD"), price: u64::MAX, pay_mode: 2, pay_script: vec![0x51], ..base.clone() },
        Deploy { ticker: tk("0000"), max: u64::MAX, lim: 1, ..base.clone() },
        Deploy { ticker: tk("AAAA"), max: 5, lim: 5, ..base.clone() }, // taken a moment ago
    ];
    let txs: Vec<Tx> = good.into_iter().enumerate().map(|(i, d)| deploy_tx(100 + i as u64, d)).collect();
    let r = ix.apply_block(&block(4, txs)).unwrap();
    assert_eq!(r.events.len(), 5);
    assert_eq!(r.rejected.len(), 1);
    assert_eq!(r.rejected[0].reason, "ticker already deployed");
    assert_eq!(ix.token(&tk("AAAA")).unwrap().max, 1_000_000);
    // DEPLOY without a burn: code ‖ txid ‖ ticker ‖ 0x00
    let mut record = vec![0x01];
    record.extend(txid(100));
    record.extend(b"AAAA");
    record.push(0x00);
    assert_eq!(r.events[0].encode(), record);
}

/// DEPLOY maturity (§5): a DEPLOY is a reveal in the witness of input 0, of a commit confirmed
/// at a height `≤ H − N`. Without that height the indexer stops; it does not refuse.
#[test]
fn deploy_maturity() {
    // the profile's N = 6
    let fresh = || Indexer::new(Profile::new(1, 0), Box::new(TestVerifier));
    assert_eq!(fresh().profile().deploy_maturity, 6);
    let env = |ticker: &str| Envelope::Deploy(deploy(ticker, 50)).encode();

    let mut ix = fresh();
    // below block N no commit is old enough, not even one of block 0
    assert_eq!(
        apply(&mut ix, 1, vec![reveal_tx(1, &env("AAAA"), 0)]).1,
        ["DEPLOY commit confirmed less than N blocks before"]
    );
    for h in 2..=9 {
        apply(&mut ix, h, vec![]);
    }
    // in block 10: a commit of block 4 or earlier is old enough, one of block 5 is not
    let mut op_return = op_return_tx(24, &env("EEEE"), 0);
    op_return.vin[0].prev_height = Some(0);
    let r = ix
        .apply_block(&block(
            10,
            vec![
                reveal_tx(20, &env("AAAA"), 5),
                reveal_tx(21, &env("AAAA"), 4),
                reveal_tx(22, &env("BBBB"), 0),
                reveal_tx(23, &env("CCCC"), 10), // a commit of this very block
                reveal_tx(25, &env("DDDD"), 4_000_000_000),
                op_return, // in an OP_RETURN, whatever the age of what it spends
                op_return_tx(26, &env("FFFF"), 0),
            ],
        ))
        .unwrap();
    let deployed: Vec<&str> = r
        .events
        .iter()
        .map(|e| match e {
            Event::Deploy { ticker, .. } => ticker.as_str(),
            other => panic!("{}", other.name()),
        })
        .collect();
    assert_eq!(deployed, ["AAAA", "BBBB"]);
    let reasons: Vec<&str> = r.rejected.iter().map(|x| x.reason).collect();
    assert_eq!(
        reasons,
        [
            "DEPLOY commit confirmed less than N blocks before",
            "DEPLOY commit confirmed less than N blocks before",
            "DEPLOY commit confirmed less than N blocks before",
            "DEPLOY must use the witness carrier",
            "DEPLOY must use the witness carrier"
        ]
    );
    // the refused reveal of AAAA (tx 20) did not take the ticker from the one that follows it
    assert!(ix.token(&tk("AAAA")).is_some() && ix.token(&tk("CCCC")).is_none());

    // a DEPLOY in a witness without the height of its commit: the indexer stops, and nothing of
    // the block is applied, not even the transactions before it
    let before = (ix.tip(), ix.digest(), ix.tree_size());
    let mint_then_deploy = |deploy: Tx| vec![op_return_tx(30, &mint("SH20", 30, None), 0), deploy];
    let missing = witness_tx(31, &env("GGGG"));
    assert_eq!(
        ix.apply_block(&block(11, mint_then_deploy(missing))).unwrap_err(),
        Error::MissingCommitHeight { height: 11, txid: txid(31) }
    );
    assert_eq!((ix.tip(), ix.digest(), ix.tree_size()), before);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().mints, 0);
    // it stops even when the DEPLOY would be refused anyway (the ticker is taken)
    assert!(ix.apply_block(&block(11, vec![witness_tx(32, &env("AAAA"))])).is_err());
    // the height is not needed where no DEPLOY in a witness can apply
    let mut two = witness_tx(33, &env("HHHH"));
    two.vout.push(out(0, &op_return_script(&mint("SH20", 33, None))));
    let mut broken = env("IIII");
    broken.push(0); // trailing byte: the decoder refuses it
    let (events, rejected) = apply(
        &mut ix,
        11,
        vec![
            two,
            witness_tx(34, &broken),
            op_return_tx(35, &env("JJJJ"), 0),
            witness_tx(36, &mint("SH20", 36, None)),
            reveal_tx(37, &env("GGGG"), 5),
        ],
    );
    assert_eq!(events, ["MINT", "DEPLOY"]);
    assert_eq!(rejected.len(), 3);

    // N is in the GENESIS record: another N, another digest from the activation block on
    let genesis = |n: u32| {
        let mut ix = Indexer::new(Profile { deploy_maturity: n, ..Profile::new(1, 0) }, Box::new(TestVerifier));
        ix.apply_block(&block(1, vec![])).unwrap()
    };
    let (six, three) = (genesis(6), genesis(3));
    assert_eq!(six.events_bytes.len(), 73);
    assert_eq!(six.events_bytes[69..], 6u32.to_le_bytes());
    assert_eq!(three.events_bytes[69..], 3u32.to_le_bytes());
    assert_eq!(six.events_bytes[..69], three.events_bytes[..69]);
    assert_ne!(six.digest, three.digest);
}

/// §4: a `payScript` may not start with OP_RETURN. The decoder refuses the envelope: the DEPLOY
/// takes no ticker and needs no commit height, the LIST spends nothing.
#[test]
fn pay_script_must_not_be_an_op_return() {
    const REFUSED: &str = "payScript starts with OP_RETURN";
    let burn_script: &[u8] = b"\x6a\x04SH20";
    let paid = |script: &[u8]| Deploy { price: 100, pay_mode: 2, pay_script: script.to_vec(), ..deploy("PAYS", 5) };
    let mut ix = indexer(1, 0);
    let (events, rejected) = apply(
        &mut ix,
        1,
        vec![
            deploy_tx(1, paid(burn_script)),
            deploy_tx(2, paid(&[0x6a])),
            // without the height of its commit: an envelope that does not decode needs none (§5)
            witness_tx(3, &Envelope::Deploy(paid(burn_script)).encode()),
            // OP_RETURN after the first byte is not refused: the ticker was still free
            deploy_tx(4, paid(&[0x51, 0x6a])),
            deploy_tx(5, paid(PAY)),
            op_return_tx(6, &mint("SH20", 6, None), 0),
        ],
    );
    assert_eq!(events, ["GENESIS", "DEPLOY", "MINT"]);
    assert_eq!(rejected, [REFUSED, REFUSED, REFUSED, "ticker already deployed"]);
    assert_eq!(ix.token(&tk("PAYS")).unwrap().pay_script, [0x51, 0x6a]);

    // a LIST: refused, and its spend is still free for the same LIST with another payScript
    let list = |n: u64, script: &[u8]| {
        let env = Envelope::List {
            ticker: Ticker::SH20,
            amount: 400,
            price: 5_000,
            lock_vout: 1,
            lock_key: [3; 32],
            pay_script: script.to_vec(),
            spend: spend(1, 10),
        }
        .encode();
        let mut tx = witness_tx(n, &env);
        tx.vout = vec![out(5_000, &[0x51]), out(330, &p2tr(&[3; 32]))];
        tx
    };
    let (events, rejected) = apply(&mut ix, 2, vec![list(10, burn_script), list(11, PAY)]);
    assert_eq!((events, rejected), (vec!["LIST"], vec![REFUSED]));
    assert!(ix.listing(&txid(10)).is_none());
    assert_eq!(ix.listing(&txid(11)).unwrap().status, ListingStatus::Active);

    // why the rule (§4): whoever pays `OP_RETURN <"SH20">` adds a second envelope to their own
    // transaction (§3), which is then refused whole
    let mut mint_tx = op_return_tx(20, &mint("SH20", 20, None), 0);
    mint_tx.vout.push(out(100, burn_script));
    assert_eq!(counted(&mint_tx).len(), 2);
    assert_eq!(apply(&mut ix, 3, vec![mint_tx]).1, ["more than one envelope"]);
}

#[test]
fn deploy_burn() {
    // D = 0: a DEPLOY carries no spend
    let mut ix = indexer(1, 0);
    let with_spend = Envelope::Deploy(Deploy { spend: Some(spend(0, 1)), ..deploy("AAAA", 5) }).encode();
    assert_eq!(apply(&mut ix, 1, vec![reveal_tx(1, &with_spend, 0)]).1, ["a spend in a DEPLOY while D = 0"]);

    // D = 1000: a DEPLOY burns it, and the turnstile holds it back while the pool is short
    let mut ix = indexer(1, 1_000);
    let no_spend = Envelope::Deploy(deploy("AAAA", 5)).encode();
    let (events, rejected) = apply(&mut ix, 1, vec![reveal_tx(1, &no_spend, 0), reveal_tx(2, &with_spend, 0)]);
    assert_eq!(events, ["GENESIS"]);
    assert_eq!(rejected, ["DEPLOY without the burn of D", "more than the pool holds of this ticker"]);
    let (events, _) = apply(&mut ix, 2, vec![op_return_tx(3, &mint("SH20", 3, None), 0), reveal_tx(4, &with_spend, 0)]);
    assert_eq!(events, ["MINT", "DEPLOY"]);
    let sh20 = ix.token(&Ticker::SH20).unwrap();
    assert_eq!((sh20.pool, sh20.burned, sh20.mints), (0, 1_000, 1));
    assert_eq!(ix.token(&tk("AAAA")).unwrap().pool, 0);
    assert_eq!(ix.tree_size(), 4);
}

#[test]
fn team_unlocks_in_ticker_order() {
    let mut ix = indexer(1, 0);
    let team = |ticker: &str, pre: u64, unlock: u32| Deploy {
        pre,
        unlock,
        team_opening: Some(fe(pre)),
        max: 1_000_000 + pre,
        ..deploy(ticker, 3)
    };
    let txs = vec![
        deploy_tx(1, team("ZZZZ", 1, 4)),
        deploy_tx(2, team("AAAA", 2, 4)),
        deploy_tx(3, team("0AAA", 3, 4)),
        deploy_tx(4, team("LATE", 4, 5)),
        deploy_tx(5, deploy("NONE", 3)), // no team: no note at its unlock block
    ];
    assert_eq!(apply(&mut ix, 1, txs).0.len(), 6);
    apply(&mut ix, 2, vec![]);
    assert!(apply(&mut ix, 3, vec![]).0.is_empty());
    // team notes come before the block's transactions, by ticker in byte order
    let r = ix.apply_block(&block(4, vec![op_return_tx(9, &mint("SH20", 9, None), 0)])).unwrap();
    let seen: Vec<(String, u64, u32)> = r
        .events
        .iter()
        .map(|e| match e {
            Event::TeamUnlock { ticker, pre, pos } => (ticker.as_str().to_string(), *pre, *pos),
            Event::Mint { ticker, v, pos, .. } => (ticker.as_str().to_string(), *v, *pos),
            _ => panic!(),
        })
        .collect();
    assert_eq!(seen, [("0AAA".into(), 3, 0), ("AAAA".into(), 2, 1), ("ZZZZ".into(), 1, 2), ("SH20".into(), 1_000, 3)]);
    assert!(r.events[0].encode().starts_with(&[0x81, 0, 0, 0]));
    assert_eq!(r.events[0].encode().len(), 49);
    assert_eq!(ix.token(&tk("AAAA")).unwrap().pool, 2);
    assert!(!ix.token(&tk("LATE")).unwrap().team_unlocked);
    assert_eq!(apply(&mut ix, 5, vec![]).0, ["TEAM_UNLOCK"]);
    assert!(apply(&mut ix, 6, vec![]).0.is_empty());
    assert!(ix.supply_holds());
}

// ---------------------------------------------------------------- spends

#[test]
fn anchor_window() {
    // A = 200, W = 100, K_min = 1
    let mut ix = indexer(200, 0);
    let t = |n: u64, anchor: u32| witness_tx(n, &transfer(anchor, n));
    // in block 200: 100..199 are in the window (all before A: the empty root)
    let (events, rejected) =
        apply(&mut ix, 200, vec![t(1, 99), t(2, 100), t(3, 150), t(4, 199), t(5, 200), t(6, 201), t(7, 0)]);
    assert_eq!(events, ["GENESIS", "TRANSFER", "TRANSFER", "TRANSFER"]);
    assert_eq!(rejected, ["anchor too old", "anchor too recent", "anchor too recent", "anchor too old"]);
    let (events, rejected) = apply(&mut ix, 201, vec![t(8, 100), t(9, 101), t(10, 200), t(11, 201), t(12, u32::MAX)]);
    assert_eq!(events, ["TRANSFER", "TRANSFER"]);
    assert_eq!(rejected, ["anchor too old", "anchor too recent", "anchor too recent"]);

    // a narrow window, so that roots after A fall out of it
    let mut ix =
        Indexer::new(Profile { anchor_window: 3, anchor_min_depth: 2, ..Profile::new(1, 0) }, Box::new(TestVerifier));
    for h in 1..=9 {
        apply(&mut ix, h, vec![]);
    }
    let (events, rejected) = apply(&mut ix, 10, vec![t(1, 6), t(2, 7), t(3, 8), t(4, 9), t(5, 10)]);
    assert_eq!(events, ["TRANSFER", "TRANSFER"]);
    assert_eq!(rejected, ["anchor too old", "anchor too recent", "anchor too recent"]);
}

#[test]
fn nullifiers_leaves_and_proofs() {
    let mut ix = indexer(1, 0);
    let wrap = |n: u64, s: sh20_indexer::envelope::Spend| witness_tx(n, &Envelope::Transfer { spend: s }.encode());
    let base = spend(0, 1);

    let mut zero_nf = spend(0, 2);
    zero_nf.nf[1] = [0; 32];
    let mut same_nf = spend(0, 3);
    same_nf.nf[1] = same_nf.nf[0];
    let mut zero_leaf = spend(0, 4);
    zero_leaf.outputs[2].leaf = [0; 32];
    let mut bad_proof = spend(0, 5);
    bad_proof.proof[479] = 1;
    let mut no_proof = spend(0, 6);
    no_proof.proof = vec![0; 480];
    let mut seen_first = spend(0, 7);
    seen_first.nf[0] = base.nf[1];
    let mut seen_second = spend(0, 8);
    seen_second.nf[1] = base.nf[0];
    // output leaves may repeat, inside a spend and across spends
    let mut same_leaves = spend(0, 9);
    same_leaves.outputs[1].leaf = base.outputs[0].leaf;
    same_leaves.outputs[2].leaf = base.outputs[0].leaf;

    let (events, rejected) = apply(
        &mut ix,
        1,
        vec![
            wrap(1, base.clone()),
            wrap(2, zero_nf),
            wrap(3, same_nf),
            wrap(4, zero_leaf),
            wrap(5, bad_proof),
            wrap(6, no_proof),
            wrap(7, seen_first),
            wrap(8, seen_second),
            wrap(9, same_leaves),
            wrap(10, base.clone()),
        ],
    );
    assert_eq!(events, ["GENESIS", "TRANSFER", "TRANSFER"]);
    assert_eq!(
        rejected,
        [
            "zero nullifier",
            "the two nullifiers are equal",
            "zero output leaf",
            "invalid proof",
            "invalid proof",
            "nullifier already seen",
            "nullifier already seen",
            "nullifier already seen"
        ]
    );
    assert_eq!(ix.tree_size(), 6);
    assert!(ix.nullifier_seen(&base.nf[0]) && ix.nullifier_seen(&base.nf[1]));
    // a rejected spend records nothing
    assert!(!ix.nullifier_seen(&spend(0, 5).nf[0]));
    // nullifiers stay spent in later blocks
    assert_eq!(apply(&mut ix, 2, vec![wrap(11, base)]).1, ["nullifier already seen"]);
}

#[test]
fn without_a_verifier_no_spend_is_accepted() {
    let mut ix = Indexer::new(Profile::new(1, 0), Box::new(RejectAll));
    let (events, rejected) =
        apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0), witness_tx(2, &transfer(0, 1))]);
    assert_eq!(events, ["GENESIS", "MINT"]);
    assert_eq!(rejected, ["invalid proof"]);
}

/// A verifier that keeps what it was asked, then answers like the test verifier.
struct Recording(Rc<RefCell<Vec<PublicInputs>>>);

impl SpendVerifier for Recording {
    fn verify_spend(&self, inputs: &PublicInputs, proof: &[u8]) -> bool {
        self.0.borrow_mut().push(inputs.clone());
        TestVerifier.verify_spend(inputs, proof)
    }
}

#[test]
fn verifier_inputs() {
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut ix = Indexer::new(Profile::new(5, 1_000), Box::new(Recording(asked.clone())));
    let empty_root = Tree::new().empty_root();

    apply(&mut ix, 5, vec![op_return_tx(1, &mint("SH20", 1, Some(10)), 0)]);
    let r5 = ix.root_at(5).unwrap();
    assert_ne!(r5, empty_root);

    let t_env = transfer(4, 1); // anchored before activation: the empty root
    let b_env = Envelope::Burn { ticker: Ticker::SH20, v_pub: 7, spend: spend(5, 2) }.encode();
    let l_env = Envelope::List {
        ticker: Ticker::SH20,
        amount: 50,
        price: 9,
        lock_vout: 0,
        lock_key: [3; 32],
        pay_script: PAY.to_vec(),
        spend: spend(5, 3),
    }
    .encode();
    let d_env = Envelope::Deploy(Deploy { spend: Some(spend(5, 4)), ..deploy("AAAA", 9) }).encode();
    let mut list = witness_tx(4, &l_env);
    list.vout = vec![out(330, &p2tr(&[3; 32]))];
    let (events, rejected) =
        apply(&mut ix, 6, vec![witness_tx(2, &t_env), witness_tx(3, &b_env), list, reveal_tx(5, &d_env, 0)]);
    assert_eq!(events, ["TRANSFER", "BURN", "LIST", "DEPLOY"]);
    assert!(rejected.is_empty());

    let sh20 = Ticker::SH20.t();
    let asked_now = asked.borrow().clone();
    let summary: Vec<_> = asked_now.iter().map(|i| (i.root, i.v_pub, i.t_pub)).collect();
    assert_eq!(summary, [(empty_root, 0, 0), (r5, 7, sh20), (r5, 50, sh20), (r5, 1_000, sh20)]);
    for (inputs, env) in asked_now.iter().zip([&t_env, &b_env, &l_env, &d_env]) {
        assert_eq!(inputs.body_hash, body_hash_of(env));
        let s = Envelope::decode(env).unwrap().spend().unwrap().clone();
        assert_eq!(fr_to_le(&inputs.nf[0]), s.nf[0]);
        assert_eq!(fr_to_le(&inputs.nf[1]), s.nf[1]);
        for i in 0..3 {
            assert_eq!(fr_to_le(&inputs.leaves[i]), s.outputs[i].leaf);
        }
        assert_eq!(inputs.as_fields().len(), 9);
    }

    // the turnstile comes before the proof: the verifier is not even asked
    let pool = ix.token(&Ticker::SH20).unwrap().pool;
    assert_eq!(pool, 10_000 - 7 - 50 - 1_000);
    let over = Envelope::Burn { ticker: Ticker::SH20, v_pub: pool + 1, spend: spend(6, 5) }.encode();
    let exact = Envelope::Burn { ticker: Ticker::SH20, v_pub: pool, spend: spend(6, 6) }.encode();
    let (events, rejected) = apply(&mut ix, 7, vec![witness_tx(6, &over), witness_tx(7, &exact)]);
    assert_eq!(events, ["BURN"]);
    assert_eq!(rejected, ["more than the pool holds of this ticker"]);
    assert_eq!(asked.borrow().len(), 5);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 0);
}

#[test]
fn burn_conditions() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0), deploy_tx(2, deploy("AAAA", 2))]);
    let burn = |n: u64, ticker: &str, v_pub: u64| {
        witness_tx(n, &Envelope::Burn { ticker: tk(ticker), v_pub, spend: spend(1, n) }.encode())
    };
    let (events, rejected) = apply(
        &mut ix,
        2,
        vec![burn(3, "SH20", 0), burn(4, "NONE", 1), burn(5, "AAAA", 1), burn(6, "SH20", 1_001), burn(7, "SH20", 400)],
    );
    assert_eq!(events, ["BURN"]);
    assert_eq!(
        rejected,
        [
            "vPub is zero",
            "ticker not deployed",
            "more than the pool holds of this ticker",
            "more than the pool holds of this ticker"
        ]
    );
    let t = ix.token(&Ticker::SH20).unwrap();
    assert_eq!((t.pool, t.burned), (600, 400));
}

// ---------------------------------------------------------------- listings

/// A LIST whose `lockKey` is the key of `lock_script` when that is P2TR, and `[3; 32]` otherwise.
fn list_tx(n: u64, amount: u64, price: u64, lock_script: &[u8], lock_sats: u64) -> Tx {
    let lock_key: [u8; 32] = if lock_script.len() == 34 && lock_script[..2] == [0x51, 0x20] {
        lock_script[2..].try_into().unwrap()
    } else {
        [3; 32]
    };
    let env = Envelope::List {
        ticker: Ticker::SH20,
        amount,
        price,
        lock_vout: 1,
        lock_key,
        pay_script: PAY.to_vec(),
        spend: spend(1, n),
    }
    .encode();
    let mut tx = witness_tx(n, &env);
    tx.vout = vec![out(5_000, &[0x51]), out(lock_sats, lock_script)];
    tx
}

fn take_tx(n: u64, locks: &[u64], outs: &[(u64, &[u8])]) -> Tx {
    let mut tx = op_return_tx(n, &Envelope::Take { opening: fe(n) }.encode(), 0);
    tx.vin = locks.iter().map(|l| spending(txid(*l), 1)).collect();
    tx.vout.extend(outs.iter().map(|(v, s)| out(*v, s)));
    tx
}

fn claim_tx(n: u64, list: u64, opening: [u8; 32], keys: &Keypair) -> Tx {
    let msg = sha256(&[b"sh20/v0/claim", &txid(list), &opening]);
    let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, keys);
    op_return_tx(n, &Envelope::Claim { list_txid: txid(list), opening, sig: sig.to_byte_array() }.encode(), 0)
}

fn keypair(seed: u8) -> (Keypair, [u8; 32]) {
    let keys = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_byte_array([seed; 32]).unwrap());
    let key = keys.x_only_public_key().0.serialize();
    (keys, key)
}

#[test]
fn bip340_vector_0() {
    // BIP340 test vector 0 (secret key 3)
    let key = unhex32("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap();
    let sig: [u8; 64] = unhex(
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    )
    .unwrap()
    .try_into()
    .unwrap();
    assert!(bip340_verify(&key, &[0; 32], &sig));
    assert!(!bip340_verify(&key, &[1; 32], &sig));
    let mut bad = sig;
    bad[63] ^= 1;
    assert!(!bip340_verify(&key, &[0; 32], &bad));
    // a key that is not on the curve verifies nothing
    assert!(!bip340_verify(&[0; 32], &[0; 32], &sig));
}

#[test]
fn list_conditions() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0)]);
    let lock = p2tr(&[3; 32]);
    let mut no_output = list_tx(14, 10, 1, &lock, 330);
    no_output.vout.truncate(1);
    let mut other_ticker = list_tx(15, 10, 1, &lock, 330);
    other_ticker.vin[0].witness[1] = tapscript(
        &Envelope::List {
            ticker: tk("NONE"),
            amount: 10,
            price: 1,
            lock_vout: 1,
            lock_key: [3; 32],
            pay_script: PAY.to_vec(),
            spend: spend(1, 15),
        }
        .encode(),
    );
    // P2TR, 330 sats, but to another key than the envelope's lockKey
    let mut other_key = list_tx(9, 10, 1, &lock, 330);
    other_key.vout[1] = out(330, &p2tr(&[4; 32]));
    let (events, rejected) = apply(
        &mut ix,
        2,
        vec![
            other_key,
            list_tx(10, 0, 1, &lock, 330),
            list_tx(11, 1_001, 1, &lock, 330),
            list_tx(12, 10, 0, &lock, 330),
            list_tx(13, 10, 1, &lock, 329),
            no_output,
            other_ticker,
            list_tx(
                16,
                10,
                1,
                &[
                    0x00, 0x20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                    3, 3, 3,
                ],
                330,
            ), // P2WSH
            list_tx(17, 10, 1, &lock[..33], 330),
            list_tx(18, 1_000, 1, &lock, 330), // the whole pool
            list_tx(19, 1, 1, &lock, 330),     // nothing left
        ],
    );
    assert_eq!(events, ["LIST"]);
    assert_eq!(
        rejected,
        [
            "lock output is not P2TR to lockKey",
            "amount is zero",
            "more than the pool holds of this ticker",
            "price is zero",
            "lock output below 330 sats",
            "no output at lockVout",
            "ticker not deployed",
            "lock output is not P2TR to lockKey",
            "lock output is not P2TR to lockKey",
            "more than the pool holds of this ticker"
        ]
    );
    let l = ix.listing(&txid(18)).unwrap();
    assert_eq!((l.status, l.amount, l.lock), (ListingStatus::Active, 1_000, (txid(18), 1)));
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 0);
    assert!(ix.supply_holds());
}

#[test]
fn life_of_a_listing() {
    let (keys, key) = keypair(1);
    let (other_keys, _) = keypair(2);
    let lock = p2tr(&key);
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, Some(10)), 0)]);
    let lists: Vec<Tx> = (10..16).map(|n| list_tx(n, 1_000, 5_000, &lock, 330)).collect();
    assert_eq!(apply(&mut ix, 2, lists).0, ["LIST"; 6]);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 4_000);

    // 10: paid in two outputs → SOLD.  11: one sat short → CANCELLED.  12: lock spent with no
    // envelope → CLOSED.  13 and 14: one TAKE spends both locks → the first in input order is
    // taken, the other is CLOSED.  15: the lock is spent by a transaction whose envelope is refused.
    let mut plain = op_return_tx(22, b"not sh20", 0);
    plain.vin = vec![input(22), spending(txid(12), 1)];
    let mut refused = op_return_tx(24, &mint("NONE", 24, None), 0);
    refused.vin = vec![spending(txid(15), 1)];
    let r = ix
        .apply_block(&block(
            3,
            vec![
                take_tx(20, &[10], &[(3_000, PAY), (2_000, PAY)]),
                take_tx(21, &[11], &[(4_999, PAY), (9_000, &[0x51])]),
                plain,
                take_tx(23, &[14, 13], &[]),
                refused,
                take_tx(25, &[], &[(5_000, PAY)]),   // spends no lock
                take_tx(26, &[10], &[(5_000, PAY)]), // that lock is not ACTIVE any more
            ],
        ))
        .unwrap();
    let names: Vec<&str> = r.events.iter().map(|e| e.name()).collect();
    assert_eq!(names, ["TAKE", "TAKE", "CLOSED", "TAKE", "CLOSED", "CLOSED"]);
    let reasons: Vec<&str> = r.rejected.iter().map(|x| x.reason).collect();
    assert_eq!(
        reasons,
        ["ticker not deployed", "no ACTIVE listing's lock is spent", "no ACTIVE listing's lock is spent"]
    );
    let status = |ix: &Indexer, n: u64| ix.listing(&txid(n)).unwrap().status;
    assert_eq!(status(&ix, 10), ListingStatus::Sold);
    assert_eq!(status(&ix, 11), ListingStatus::Cancelled);
    assert_eq!(status(&ix, 12), ListingStatus::Closed);
    assert_eq!(status(&ix, 13), ListingStatus::Closed);
    assert_eq!(status(&ix, 14), ListingStatus::Cancelled);
    assert_eq!(status(&ix, 15), ListingStatus::Closed);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 7_000);
    assert!(ix.supply_holds());

    // the records
    assert_eq!(r.events[0], Event::Take { txid: txid(20), list_txid: txid(10), outcome: Outcome::Sold, pos: 19 });
    let mut take = vec![0x06];
    take.extend(txid(21));
    take.extend(txid(11));
    take.push(2); // CANCELLED
    take.extend(20u32.to_le_bytes());
    assert_eq!(r.events[1].encode(), take);
    let mut closed = vec![0x82];
    closed.extend(txid(22)); // the transaction that spent the lock
    closed.extend(txid(12));
    assert_eq!(r.events[2].encode(), closed);
    assert_eq!(r.events[3], Event::Take { txid: txid(23), list_txid: txid(14), outcome: Outcome::Cancelled, pos: 21 });
    assert_eq!(r.events[4], Event::Closed { txid: txid(23), list_txid: txid(13) });
    assert_eq!(r.events[5], Event::Closed { txid: txid(24), list_txid: txid(15) });

    // CLAIM: only a CLOSED listing, only with the lock key's signature over (listTxid, npk)
    let opening = fe(77);
    let wrong_npk = {
        let mut tx = claim_tx(31, 12, fe(78), &keys);
        // signed for another npk than the one in the envelope
        let Envelope::Claim { list_txid, sig, .. } = Envelope::decode(&envelopes(&tx)[0]).unwrap() else { panic!() };
        tx.vout[0].script = op_return_script(&Envelope::Claim { list_txid, opening, sig }.encode());
        tx
    };
    let wrong_listing = {
        let mut tx = claim_tx(32, 13, opening, &keys);
        // signed for listing 13, sent for listing 12
        let Envelope::Claim { sig, .. } = Envelope::decode(&envelopes(&tx)[0]).unwrap() else { panic!() };
        tx.vout[0].script = op_return_script(&Envelope::Claim { list_txid: txid(12), opening, sig }.encode());
        tx
    };
    let r = ix
        .apply_block(&block(
            4,
            vec![
                claim_tx(30, 12, opening, &other_keys),
                wrong_npk,
                wrong_listing,
                claim_tx(33, 10, opening, &keys), // SOLD
                claim_tx(34, 11, opening, &keys), // CANCELLED
                claim_tx(35, 99, opening, &keys), // no such listing
                claim_tx(36, 12, opening, &keys),
                claim_tx(37, 12, opening, &keys), // CLAIMED already
                claim_tx(38, 13, opening, &keys), // the same npk may be used again
            ],
        ))
        .unwrap();
    let reasons: Vec<&str> = r.rejected.iter().map(|x| x.reason).collect();
    assert_eq!(
        reasons,
        [
            "bad claim signature",
            "bad claim signature",
            "bad claim signature",
            "listing is not CLOSED",
            "listing is not CLOSED",
            "no such listing",
            "listing is not CLOSED"
        ]
    );
    let mut claim = vec![0x07];
    claim.extend(txid(36));
    claim.extend(txid(12));
    claim.extend(22u32.to_le_bytes());
    assert_eq!(r.events_bytes[..69], claim);
    assert_eq!(r.events.len(), 2);
    assert_eq!(status(&ix, 12), ListingStatus::Claimed);
    assert_eq!(status(&ix, 13), ListingStatus::Claimed);
    assert_eq!(status(&ix, 15), ListingStatus::Closed);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 9_000);
    assert!(ix.supply_holds());

    // a CLAIM in the transaction that spends the lock comes too early: the listing is ACTIVE
    // when the envelope applies, and CLOSED after it
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0)]);
    apply(&mut ix, 2, vec![list_tx(10, 1_000, 5_000, &lock, 330)]);
    let mut early = claim_tx(40, 10, opening, &keys);
    early.vin = vec![spending(txid(10), 1)];
    let (events, rejected) = apply(&mut ix, 3, vec![early, claim_tx(41, 10, opening, &keys)]);
    assert_eq!(events, ["CLOSED", "CLAIM"]);
    assert_eq!(rejected, ["listing is not CLOSED"]);
}

#[test]
fn list_and_take_in_one_block() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, None), 0)]);
    let lock = p2tr(&[3; 32]);
    // spending another output of the LIST transaction is not spending the lock
    let mut not_the_lock = take_tx(19, &[], &[(5_000, PAY)]);
    not_the_lock.vin = vec![spending(txid(10), 0)];
    let (events, rejected) =
        apply(&mut ix, 2, vec![list_tx(10, 400, 5_000, &lock, 330), not_the_lock, take_tx(20, &[10], &[(5_000, PAY)])]);
    assert_eq!(events, ["LIST", "TAKE"]);
    assert_eq!(rejected, ["no ACTIVE listing's lock is spent"]);
    assert_eq!(ix.listing(&txid(10)).unwrap().status, ListingStatus::Sold);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 1_000);
}

/// A LIST names the key of its lock inside the signed body (`lockKey`), and the lock output must
/// be `OP_1 <lockKey>`. An envelope copied into a transaction with another lock is refused; a
/// copy that keeps the lock only does what the original would have done.
#[test]
fn a_copied_list_is_refused() {
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, Some(2)), 0)]);
    let sellers = list_tx(10, 1_000, 5_000, &p2tr(&[3; 32]), 330);
    // the same envelope, byte for byte, in another transaction whose lock the copier holds
    let mut copy = sellers.clone();
    copy.txid = txid(66);
    copy.vout[1] = out(330, &p2tr(&[6; 32]));
    // the refused copy records nothing: the seller's own transaction still goes through
    let (events, rejected) = apply(&mut ix, 2, vec![copy, sellers.clone()]);
    assert_eq!(events, ["LIST"]);
    assert_eq!(rejected, ["lock output is not P2TR to lockKey"]);
    assert!(ix.listing(&txid(66)).is_none());
    assert_eq!(ix.listing(&txid(10)).unwrap().lock_key, [3; 32]);
    // spending the copier's output takes nothing
    let (events, rejected) = apply(&mut ix, 3, vec![take_tx(67, &[66], &[])]);
    assert!(events.is_empty());
    assert_eq!(rejected, ["no ACTIVE listing's lock is spent"]);
    assert_eq!(ix.listing(&txid(10)).unwrap().status, ListingStatus::Active);
    assert_eq!(ix.token(&Ticker::SH20).unwrap().pool, 1_000);

    // a copy that confirms first with the seller's lock makes the same listing under another
    // txid: the lock still belongs to the seller's key, and the seller's transaction is the one refused
    let mut ix = indexer(1, 0);
    apply(&mut ix, 1, vec![op_return_tx(1, &mint("SH20", 1, Some(2)), 0)]);
    let mut same_lock = sellers.clone();
    same_lock.txid = txid(66);
    let (events, rejected) = apply(&mut ix, 2, vec![same_lock, sellers]);
    assert_eq!(events, ["LIST"]);
    assert_eq!(rejected, ["nullifier already seen"]);
    assert_eq!(ix.listing(&txid(66)).unwrap().lock_key, [3; 32]);
    assert!(ix.listing(&txid(10)).is_none());
}

// ---------------------------------------------------------------- reorgs

fn vector_blocks() -> (Profile, Vec<sh20_indexer::Block>, Vec<String>) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let sc = &v["scenario"];
    let profile = Profile {
        activation_height: sc["profile"]["activationHeight"].as_u64().unwrap() as u32,
        deploy_burn: sc["profile"]["deployBurn"].as_str().unwrap().parse().unwrap(),
        anchor_window: sc["profile"]["anchorWindow"].as_u64().unwrap() as u32,
        anchor_min_depth: sc["profile"]["anchorMinDepth"].as_u64().unwrap() as u32,
        deploy_maturity: sc["profile"]["deployMaturity"].as_u64().unwrap() as u32,
    };
    let blocks = sc["blocks"].as_array().unwrap().iter().map(|b| block_from_vector(b).unwrap()).collect();
    let digests = sc["after"].as_array().unwrap().iter().map(|a| a["digest"].as_str().unwrap().to_string()).collect();
    (profile, blocks, digests)
}

/// What two indexers must agree on to be in the same state.
fn fingerprint(ix: &Indexer) -> String {
    let mut listings: Vec<String> = ix
        .listings()
        .map(|(id, l)| format!("{}:{}:{}", sh20_indexer::field::hex(id), l.status.name(), l.amount))
        .collect();
    listings.sort();
    let tokens: Vec<String> = ix
        .tokens()
        .map(|t| format!("{}:{}:{}:{}:{}", t.ticker.as_str(), t.mints, t.burned, t.pool, t.team_unlocked))
        .collect();
    format!(
        "{:?} {} {} {:?} {:?} {:?}",
        ix.tip(),
        sh20_indexer::field::hex(&ix.digest()),
        ix.tree_size(),
        ix.tip().and_then(|h| ix.root_at(h)),
        tokens,
        listings
    )
}

#[test]
fn reorg_replays_to_the_same_state() {
    let (profile, blocks, digests) = vector_blocks();
    let fresh = || Indexer::new(profile, Box::new(TestVerifier));

    // the state after each block, from a straight run
    let mut straight = fresh();
    let mut prints = vec![fingerprint(&straight)];
    for b in &blocks {
        straight.apply_block(b).unwrap();
        prints.push(fingerprint(&straight));
    }

    // roll back to every fork point, check the state is the one of that block, replay
    for fork in 0..=blocks.len() {
        let mut ix = fresh();
        for b in &blocks {
            ix.apply_block(b).unwrap();
        }
        ix.rollback_to(fork as u32).unwrap();
        assert_eq!(fingerprint(&ix), prints[fork], "after rolling back to block {fork}");
        for (b, want) in blocks.iter().zip(&digests).skip(fork) {
            let r = ix.apply_block(b).unwrap();
            assert_eq!(&sh20_indexer::field::hex(&r.digest), want, "block {} replayed from {fork}", b.height);
        }
        assert_eq!(fingerprint(&ix), prints[blocks.len()]);
    }

    // one block at a time, all the way down, and back
    let mut ix = fresh();
    for b in &blocks {
        ix.apply_block(b).unwrap();
    }
    for h in (1..=blocks.len()).rev() {
        assert_eq!(ix.rollback().unwrap(), h as u32);
        assert_eq!(fingerprint(&ix), prints[h - 1]);
    }
    assert_eq!(ix.rollback().unwrap_err(), Error::NoUndo);
    assert_eq!(fingerprint(&ix), fingerprint(&fresh()));
}

#[test]
fn reorg_onto_another_branch() {
    let (profile, blocks, _) = vector_blocks();
    // branch B: the same first three blocks, then the scenario's block 7 mints arrive early
    // (GENE is not deployed on this branch: they are refused) and a transfer reuses nothing
    let branch = |ix: &mut Indexer| {
        let mut b4 = blocks[6].clone();
        b4.height = 4;
        b4.txs.push(witness_tx(900, &transfer(3, 900)));
        let r = ix.apply_block(&b4).unwrap();
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.rejected.len(), 2);
        ix.apply_block(&block(5, vec![op_return_tx(901, &mint("SH20", 901, None), 0)])).unwrap();
    };

    let mut reorged = Indexer::new(profile, Box::new(TestVerifier));
    for b in &blocks {
        reorged.apply_block(b).unwrap();
    }
    reorged.rollback_to(3).unwrap();
    branch(&mut reorged);

    let mut direct = Indexer::new(profile, Box::new(TestVerifier));
    for b in &blocks[..3] {
        direct.apply_block(b).unwrap();
    }
    branch(&mut direct);

    assert_eq!(fingerprint(&reorged), fingerprint(&direct));
    assert!(reorged.token(&tk("GENE")).is_none());
    assert!(reorged.supply_holds());
    // nullifiers of the abandoned branch are free again, those before the fork are not
    let Envelope::Burn { spend: burned, .. } = Envelope::decode(&envelopes(&blocks[5].txs[0])[0]).unwrap() else {
        panic!()
    };
    assert!(!reorged.nullifier_seen(&burned.nf[0]));
    let Envelope::Transfer { spend: kept } = Envelope::decode(&envelopes(blocks[1].txs.last().unwrap())[0]).unwrap()
    else {
        panic!()
    };
    assert!(reorged.nullifier_seen(&kept.nf[0]));
}

#[test]
fn undo_log_has_a_depth() {
    let mut ix = indexer(1, 0).with_undo_depth(2);
    for h in 1..=5 {
        apply(&mut ix, h, vec![op_return_tx(h as u64, &mint("SH20", h as u64, None), 0)]);
    }
    assert_eq!(ix.rollback_to(2).unwrap_err(), Error::NoUndo);
    assert_eq!(ix.tip(), Some(3));
    assert_eq!(ix.token(&Ticker::SH20).unwrap().mints, 3);
    // and the indexer goes on from there
    apply(&mut ix, 4, vec![]);
}
