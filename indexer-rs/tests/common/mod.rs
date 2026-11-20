//! Builders shared by the tests: transactions, carriers, spends.
#![allow(dead_code)]

use sh20_indexer::chain::{Block, Tx, TxIn, TxOut};
use sh20_indexer::envelope::{Deploy, Envelope, Spend, SpendOutput, Ticker, CT_LEN};
use sh20_indexer::field::sha256;
use sh20_indexer::verifier::TestVerifier;
use sh20_indexer::{Indexer, Profile};

pub fn tk(s: &str) -> Ticker {
    Ticker::parse(s).unwrap()
}

/// A txid that depends on `n` only.
pub fn txid(n: u64) -> [u8; 32] {
    sha256(&[b"test txid", &n.to_le_bytes()])
}

/// A canonical field element (little-endian, top byte cleared) that depends on `n` only.
pub fn fe(n: u64) -> [u8; 32] {
    let mut b = sha256(&[b"test field element", &n.to_le_bytes()]);
    b[31] = 0;
    b
}

/// The minimal push of `data` (4 bytes or more).
pub fn push(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    match data.len() {
        n if n <= 75 => s.push(n as u8),
        n if n <= 255 => s.extend_from_slice(&[0x4c, n as u8]),
        n => {
            s.push(0x4d);
            s.extend_from_slice(&(n as u16).to_le_bytes());
        }
    }
    s.extend_from_slice(data);
    s
}

pub fn op_return_script(envelope: &[u8]) -> Vec<u8> {
    let mut s = vec![0x6a];
    s.extend(push(envelope));
    s
}

/// `<key> OP_CHECKSIG OP_0 OP_IF <"SH20"> <chunks of 520 bytes> OP_ENDIF`.
pub fn tapscript(envelope: &[u8]) -> Vec<u8> {
    let mut s = push(&[7u8; 32]);
    s.push(0xac);
    s.extend(envelope_script(envelope));
    s
}

pub fn envelope_script(envelope: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00, 0x63];
    s.extend(push(&envelope[..4]));
    for chunk in envelope[4..].chunks(520) {
        s.extend(push(chunk));
    }
    s.push(0x68);
    s
}

pub fn control_block() -> Vec<u8> {
    let mut c = vec![0xc0];
    c.extend_from_slice(&[9u8; 32]);
    c
}

pub fn input(n: u64) -> TxIn {
    TxIn { prevout: Some((txid(1_000_000 + n), 0)), coinbase: false, prev_height: None, witness: Vec::new() }
}

pub fn spending(prev: [u8; 32], vout: u32) -> TxIn {
    TxIn { prevout: Some((prev, vout)), coinbase: false, prev_height: None, witness: Vec::new() }
}

/// A transaction with the envelope in an OP_RETURN output carrying `value` sats.
pub fn op_return_tx(n: u64, envelope: &[u8], value: u64) -> Tx {
    Tx { txid: txid(n), vin: vec![input(n)], vout: vec![TxOut { value, script: op_return_script(envelope) }] }
}

/// A transaction with the envelope in the tapscript of input 0.
pub fn witness_tx(n: u64, envelope: &[u8]) -> Tx {
    let mut i = input(n);
    i.witness = vec![vec![1u8; 64], tapscript(envelope), control_block()];
    Tx { txid: txid(n), vin: vec![i], vout: Vec::new() }
}

/// A transaction whose tapscript holds several envelopes, one after the other.
pub fn batch_tx(n: u64, envelopes: &[Vec<u8>]) -> Tx {
    let mut script = push(&[7u8; 32]);
    script.push(0xac);
    for e in envelopes {
        script.extend(envelope_script(e));
    }
    let mut i = input(n);
    i.witness = vec![vec![1u8; 64], script, control_block()];
    Tx { txid: txid(n), vin: vec![i], vout: Vec::new() }
}

pub fn p2tr(key: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(key);
    s
}

pub fn out(value: u64, script: &[u8]) -> TxOut {
    TxOut { value, script: script.to_vec() }
}

pub fn block(height: u32, txs: Vec<Tx>) -> Block {
    Block { height, txs }
}

/// A spend with fresh nullifiers and leaves (from `seed`) and the proof the test verifier accepts.
pub fn spend(anchor_height: u32, seed: u64) -> Spend {
    let o = |i: u64| SpendOutput { leaf: fe(seed * 16 + 2 + i), pk_eph: [0xee; 32], ct: [0xcc; CT_LEN] };
    Spend {
        anchor_height,
        nf: [fe(seed * 16), fe(seed * 16 + 1)],
        outputs: [o(0), o(1), o(2)],
        proof: TestVerifier::valid_proof(),
    }
}

pub fn mint(ticker: &str, seed: u64, k: Option<u8>) -> Vec<u8> {
    Envelope::Mint { ticker: tk(ticker), opening: fe(seed), k }.encode()
}

pub fn transfer(anchor: u32, seed: u64) -> Vec<u8> {
    Envelope::Transfer { spend: spend(anchor, seed) }.encode()
}

/// A plain deploy: 1,000,000 max, 1,000 per mint, free, no team.
pub fn deploy(ticker: &str, start: u32) -> Deploy {
    Deploy {
        ticker: tk(ticker),
        max: 1_000_000,
        lim: 1_000,
        pre: 0,
        start,
        end: 0,
        unlock: start,
        price: 0,
        pay_mode: 0,
        pay_script: Vec::new(),
        team_opening: None,
        spend: None,
    }
}

/// An indexer with the vectors' test verifier and `N = 0`: a DEPLOY may reveal a commit of any
/// block up to its own, so that the other rules can be tested from block 1. The maturity rule
/// has its own test, with the profile's `N = 6`.
pub fn indexer(activation: u32, deploy_burn: u64) -> Indexer {
    let profile = Profile { deploy_maturity: 0, ..Profile::new(activation, deploy_burn) };
    Indexer::new(profile, Box::new(TestVerifier))
}

/// A DEPLOY as §5 wants it: revealed in the witness of input 0, which spends a commit
/// confirmed at `commit_height`.
pub fn reveal_tx(n: u64, envelope: &[u8], commit_height: u32) -> Tx {
    let mut tx = witness_tx(n, envelope);
    tx.vin[0].prev_height = Some(commit_height);
    tx
}

/// Applies a block and returns the names of its events and the reasons of its refusals.
pub fn apply(ix: &mut Indexer, height: u32, txs: Vec<Tx>) -> (Vec<&'static str>, Vec<&'static str>) {
    let r = ix.apply_block(&block(height, txs)).unwrap();
    assert!(ix.supply_holds(), "supply identity after block {height}");
    (r.events.iter().map(|e| e.name()).collect(), r.rejected.iter().map(|x| x.reason).collect())
}
