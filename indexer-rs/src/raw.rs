//! Bitcoin's serialized block, as `GET /block/:hash/raw` of an Esplora server gives it: one
//! request for a block of any size, where the pages of `/block/:hash/txs/:start` hold 25
//! transactions each.
//!
//! Written from Bitcoin's own formats: the block header and the transaction serialization, the
//! witness form of BIP 144, the transaction merkle tree, and the witness commitment of BIP 141.
//! What the bytes say about themselves is checked: the header hashes to the block's hash, the
//! txids to the header's merkle root, and the witnesses to the commitment in the coinbase. So a
//! block read this way is the block that was asked for, or it is refused; a page of JSON says
//! nothing of the kind.

use crate::chain::{Tx, TxIn, TxOut};
use crate::field::Bytes32;
use sha2::{Digest, Sha256};

/// A block read from its serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlock {
    /// The hash of the header, in display (RPC) byte order.
    pub hash: Bytes32,
    /// The hash of the block before, in display byte order.
    pub prev: Bytes32,
    pub txs: Vec<Tx>,
}

const HEADER_LEN: usize = 80;
/// The shortest transaction: a version, one input with an empty script, one output with an
/// empty script, a lock time.
const MIN_TX_LEN: usize = 4 + 1 + MIN_INPUT_LEN + 1 + MIN_OUTPUT_LEN + 4;
/// An outpoint, an empty script, a sequence.
const MIN_INPUT_LEN: usize = 36 + 1 + 4;
/// A value, an empty script.
const MIN_OUTPUT_LEN: usize = 8 + 1;
/// The output of a coinbase that commits to the witnesses starts with these bytes (BIP 141):
/// `OP_RETURN`, a push of 36 bytes, the tag `aa21a9ed`.
const COMMITMENT_HEAD: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

fn sha256d(parts: &[&[u8]]) -> Bytes32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Sha256::digest(h.finalize()).into()
}

fn reversed(mut bytes: Bytes32) -> Bytes32 {
    bytes.reverse();
    bytes
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.left() {
            return Err(format!(
                "the bytes end at {}, inside a field of {n} bytes that starts at {}",
                self.bytes.len(),
                self.at
            ));
        }
        let field = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(field)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    /// Bitcoin's variable-length integer, in its shortest form only (a longer one is not what
    /// a node serializes, and would give the same transaction two serializations).
    fn compact_size(&mut self) -> Result<u64, String> {
        let at = self.at;
        let (n, least) = match self.take(1)?[0] {
            0xfd => (u64::from(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes"))), 0xfd),
            0xfe => (u64::from(self.u32()?), 0x1_0000),
            0xff => (self.u64()?, 0x1_0000_0000),
            n => (u64::from(n), 0),
        };
        if n < least {
            return Err(format!("the length at {at} is not in its shortest form"));
        }
        Ok(n)
    }

    /// A count of things of at least `each` bytes: one the bytes left can hold, so that no
    /// count read from the wire is believed before the bytes are there.
    fn count(&mut self, each: usize) -> Result<usize, String> {
        let at = self.at;
        let n = self.compact_size()?;
        match usize::try_from(n) {
            Ok(n) if n <= self.left() / each => Ok(n),
            _ => Err(format!("the count at {at} is {n}, more than the bytes left can hold")),
        }
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.count(1)?;
        self.take(n)
    }
}

/// A transaction, its wtxid (the hash of the whole serialization, in the byte order of the
/// hash), and whether it is in the witness form.
struct Parsed {
    tx: Tx,
    /// The txid in the byte order of the hash, as the merkle tree takes it.
    txid: Bytes32,
    wtxid: Bytes32,
    has_witness: bool,
}

fn transaction(r: &mut Reader) -> Result<Parsed, String> {
    let start = r.at;
    let version = r.take(4)?;
    // BIP 144: a marker 0x00 where the input count would be (never zero in a block), then the
    // flag 0x01
    let has_witness = r.bytes.get(r.at) == Some(&0x00);
    if has_witness {
        let flag = r.take(2)?[1];
        if flag != 0x01 {
            return Err(format!("the transaction at {start} has the witness marker and the flag {flag:#04x}"));
        }
    }
    let body = r.at;
    let inputs = r.count(MIN_INPUT_LEN)?;
    if inputs == 0 {
        return Err(format!("the transaction at {start} has no input"));
    }
    let mut vin = Vec::with_capacity(inputs);
    for _ in 0..inputs {
        let spent: Bytes32 = r.take(32)?.try_into().expect("32 bytes");
        let index = r.u32()?;
        r.var_bytes()?; // scriptSig: nothing of SH-20 is there
        r.take(4)?; // sequence
                    // the input of a coinbase spends the null outpoint
        let coinbase = spent == [0; 32] && index == u32::MAX;
        let prevout = if coinbase { None } else { Some((reversed(spent), index)) };
        vin.push(TxIn { prevout, coinbase, prev_height: None, witness: Vec::new() });
    }
    let outputs = r.count(MIN_OUTPUT_LEN)?;
    let mut vout = Vec::with_capacity(outputs);
    for _ in 0..outputs {
        let value = r.u64()?;
        vout.push(TxOut { value, script: r.var_bytes()?.to_vec() });
    }
    let body_end = r.at;
    if has_witness {
        for input in &mut vin {
            for _ in 0..r.count(1)? {
                input.witness.push(r.var_bytes()?.to_vec());
            }
        }
        // a node refuses the witness form around no witness at all: the plain form says the same
        if vin.iter().all(|i| i.witness.is_empty()) {
            return Err(format!("the transaction at {start} is in the witness form and has no witness"));
        }
    }
    let lock_time = r.take(4)?;
    let whole = &r.bytes[start..r.at];
    let wtxid = sha256d(&[whole]);
    // the txid is the hash of the plain form: the same bytes without marker, flag and witnesses
    let txid = if has_witness { sha256d(&[version, &r.bytes[body..body_end], lock_time]) } else { wtxid };
    Ok(Parsed { tx: Tx { txid: reversed(txid), vin, vout }, txid, wtxid, has_witness })
}

/// The root of Bitcoin's merkle tree over `leaves` (not empty): pairs hashed level by level,
/// the last one with itself where a level has an odd count.
fn merkle_root(mut level: Vec<Bytes32>) -> Bytes32 {
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| sha256d(&[&pair[0], pair.last().expect("a chunk is not empty")])).collect();
    }
    level[0]
}

/// The witness commitment (BIP 141). Where a transaction of the block has a witness, the
/// coinbase commits to all of them: its last output that starts with `COMMITMENT_HEAD` holds
/// `SHA256d(witness root ‖ reserved value)`, the reserved value being the one witness item, of 32
/// bytes, of the coinbase's input, and the witness root the merkle root of the wtxids with
/// zeros for the coinbase's. This is the rule of every block since segwit activated (mainnet
/// block 481,824; from the first block on signet and regtest).
fn check_witness_commitment(txs: &[Parsed]) -> Result<(), String> {
    let coinbase = &txs[0].tx;
    let is_commitment = |o: &&TxOut| o.script.len() >= 38 && o.script[..6] == COMMITMENT_HEAD;
    let Some(output) = coinbase.vout.iter().rev().find(is_commitment) else {
        return match txs.iter().any(|t| t.has_witness) {
            true => Err("a transaction has a witness and the coinbase commits to none".into()),
            false => Ok(()),
        };
    };
    let reserved = match coinbase.vin[0].witness.as_slice() {
        [one] if one.len() == 32 => one,
        _ => return Err("the coinbase commits to the witnesses without the reserved value in its own".into()),
    };
    let mut wtxids: Vec<Bytes32> = txs.iter().map(|t| t.wtxid).collect();
    wtxids[0] = [0; 32];
    if sha256d(&[&merkle_root(wtxids), reserved]) != output.script[6..38] {
        return Err("the witnesses are not the ones the coinbase commits to".into());
    }
    Ok(())
}

/// Reads a serialized block and checks it against itself: nothing after the last transaction,
/// a coinbase first and nowhere else, the header's merkle root, the witness commitment. The
/// caller compares `hash` with the hash it asked for.
pub fn block_from_raw(bytes: &[u8]) -> Result<RawBlock, String> {
    let mut r = Reader { bytes, at: 0 };
    let header = r.take(HEADER_LEN).map_err(|_| format!("{} bytes are not a block header", bytes.len()))?;
    let hash = reversed(sha256d(&[header]));
    let prev = reversed(header[4..36].try_into().expect("32 bytes"));
    let count = r.count(MIN_TX_LEN)?;
    if count == 0 {
        return Err("a block with no transaction".into());
    }
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        txs.push(transaction(&mut r)?);
    }
    if r.left() != 0 {
        return Err(format!("{} bytes after the last transaction", r.left()));
    }
    let is_coinbase = |t: &Parsed| t.tx.vin.len() == 1 && t.tx.vin[0].coinbase;
    if !is_coinbase(&txs[0]) || txs[1..].iter().any(|t| t.tx.vin.iter().any(|i| i.coinbase)) {
        return Err("the coinbase is not the first transaction and that one alone".into());
    }
    if merkle_root(txs.iter().map(|t| t.txid).collect()) != header[36..68] {
        return Err("the transactions are not the ones the header commits to (merkle root)".into());
    }
    check_witness_commitment(&txs)?;
    Ok(RawBlock { hash, prev, txs: txs.into_iter().map(|t| t.tx).collect() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{hex, unhex};

    /// Bitcoin's first block: 285 bytes that every node holds.
    const GENESIS: &str = "\
        0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e\
        67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000\
        00000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f\
        4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066\
        6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a6\
        7962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    fn genesis() -> Vec<u8> {
        unhex(&GENESIS.replace(char::is_whitespace, "")).unwrap()
    }

    #[test]
    fn the_first_block_of_bitcoin() {
        let bytes = genesis();
        assert_eq!(bytes.len(), 285);
        let b = block_from_raw(&bytes).unwrap();
        assert_eq!(hex(&b.hash), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert_eq!(b.prev, [0; 32]);
        assert_eq!(b.txs.len(), 1);
        let tx = &b.txs[0];
        assert_eq!(hex(&tx.txid), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        assert_eq!(tx.vin, [TxIn { prevout: None, coinbase: true, prev_height: None, witness: Vec::new() }]);
        assert_eq!((tx.vout.len(), tx.vout[0].value, tx.vout[0].script.len()), (1, 5_000_000_000, 67));
        assert_eq!((tx.vout[0].script[0], tx.vout[0].script[66]), (0x41, 0xac));
    }

    #[test]
    fn bytes_that_are_not_the_block() {
        let good = genesis();
        let refused = |bytes: &[u8], why: &str| match block_from_raw(bytes) {
            Err(e) => assert!(e.contains(why), "{e}"),
            Ok(b) => panic!("taken, with the hash {}: {why}", hex(&b.hash)),
        };
        // cut anywhere: never a block, never a panic
        for n in 0..good.len() {
            assert!(block_from_raw(&good[..n]).is_err(), "{n} bytes");
        }
        refused(&good[..79], "not a block header");
        refused(&[&good[..], &[0][..]].concat(), "1 bytes after the last transaction");
        // one bit anywhere in the transaction: the header no longer commits to it, or it no
        // longer reads as a transaction
        for at in 81..good.len() {
            let mut bad = good.clone();
            bad[at] ^= 1;
            assert!(block_from_raw(&bad).is_err(), "bit flipped at {at}");
        }
        let mut bad = good.clone();
        bad[good.len() - 1] ^= 1; // the lock time
        refused(&bad, "merkle root");
        // one bit in the header: another block, by its hash
        let mut other = good.clone();
        other[0] ^= 2;
        assert_ne!(block_from_raw(&other).unwrap().hash, block_from_raw(&good).unwrap().hash);
        // counts the bytes cannot hold
        let mut bad = good.clone();
        bad[80] = 5;
        refused(&bad, "more than the bytes left can hold");
        refused(&[&good[..80], &[0xff; 9][..]].concat(), "more than the bytes left can hold");
        refused(&[&good[..80], &[0][..]].concat(), "no transaction");
        // a length in a longer form than it needs
        refused(&[&good[..80], &[0xfd, 0x01, 0x00][..], &good[81..]].concat(), "shortest form");
    }

    #[test]
    fn the_merkle_tree() {
        let leaf = |n: u8| sha256d(&[&[n]]);
        let pair = |a: &Bytes32, b: &Bytes32| sha256d(&[a, b]);
        assert_eq!(merkle_root(vec![leaf(1)]), leaf(1));
        assert_eq!(merkle_root(vec![leaf(1), leaf(2)]), pair(&leaf(1), &leaf(2)));
        // an odd level repeats its last hash
        let (ab, cc) = (pair(&leaf(1), &leaf(2)), pair(&leaf(3), &leaf(3)));
        assert_eq!(merkle_root(vec![leaf(1), leaf(2), leaf(3)]), pair(&ab, &cc));
        let five: Vec<Bytes32> = (1..=5).map(leaf).collect();
        let (cd, ee) = (pair(&leaf(3), &leaf(4)), pair(&leaf(5), &leaf(5)));
        let (abcd, eeee) = (pair(&ab, &cd), pair(&ee, &ee));
        assert_eq!(merkle_root(five), pair(&abcd, &eeee));
    }
}
