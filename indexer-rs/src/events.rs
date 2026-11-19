//! The byte encoding of the events inside the digest (SPEC-WIRE §6).
//!
//! Every record is `code(1) ‖ txid(32) ‖ payload`.

use crate::envelope::Ticker;
use crate::field::Bytes32;

/// `nf0 ‖ nf1 ‖ pos0 ‖ pos1 ‖ pos2` (76 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spent {
    pub nf: [Bytes32; 2],
    pub pos: [u32; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Sold = 1,
    Cancelled = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Deploy {
        txid: Bytes32,
        ticker: Ticker,
        burn: Option<Spent>,
    },
    Mint {
        txid: Bytes32,
        ticker: Ticker,
        v: u64,
        pos: u32,
    },
    Transfer {
        txid: Bytes32,
        spent: Spent,
    },
    Burn {
        txid: Bytes32,
        ticker: Ticker,
        v_pub: u64,
        spent: Spent,
    },
    List {
        txid: Bytes32,
        ticker: Ticker,
        amount: u64,
        price: u64,
        spent: Spent,
    },
    Take {
        txid: Bytes32,
        list_txid: Bytes32,
        outcome: Outcome,
        pos: u32,
    },
    Claim {
        txid: Bytes32,
        list_txid: Bytes32,
        pos: u32,
    },
    Genesis {
        ticker: Ticker,
        max: u64,
        lim: u64,
        deploy_burn: u64,
        window: u32,
        min_depth: u32,
    },
    TeamUnlock {
        ticker: Ticker,
        pre: u64,
        pos: u32,
    },
    /// `txid` is the transaction that spent the lock.
    Closed {
        txid: Bytes32,
        list_txid: Bytes32,
    },
}

const NO_TXID: Bytes32 = [0u8; 32];

fn put_spent(out: &mut Vec<u8>, s: &Spent) {
    out.extend_from_slice(&s.nf[0]);
    out.extend_from_slice(&s.nf[1]);
    for p in s.pos {
        out.extend_from_slice(&p.to_le_bytes());
    }
}

impl Event {
    pub fn code(&self) -> u8 {
        match self {
            Event::Deploy { .. } => 0x01,
            Event::Mint { .. } => 0x02,
            Event::Transfer { .. } => 0x03,
            Event::Burn { .. } => 0x04,
            Event::List { .. } => 0x05,
            Event::Take { .. } => 0x06,
            Event::Claim { .. } => 0x07,
            Event::Genesis { .. } => 0x80,
            Event::TeamUnlock { .. } => 0x81,
            Event::Closed { .. } => 0x82,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Event::Deploy { .. } => "DEPLOY",
            Event::Mint { .. } => "MINT",
            Event::Transfer { .. } => "TRANSFER",
            Event::Burn { .. } => "BURN",
            Event::List { .. } => "LIST",
            Event::Take { .. } => "TAKE",
            Event::Claim { .. } => "CLAIM",
            Event::Genesis { .. } => "GENESIS",
            Event::TeamUnlock { .. } => "TEAM_UNLOCK",
            Event::Closed { .. } => "CLOSED",
        }
    }

    pub fn txid(&self) -> &Bytes32 {
        match self {
            Event::Deploy { txid, .. }
            | Event::Mint { txid, .. }
            | Event::Transfer { txid, .. }
            | Event::Burn { txid, .. }
            | Event::List { txid, .. }
            | Event::Take { txid, .. }
            | Event::Claim { txid, .. }
            | Event::Closed { txid, .. } => txid,
            Event::Genesis { .. } | Event::TeamUnlock { .. } => &NO_TXID,
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.code());
        out.extend_from_slice(self.txid());
        match self {
            Event::Deploy { ticker, burn, .. } => {
                out.extend_from_slice(&ticker.0);
                match burn {
                    None => out.push(0x00),
                    Some(s) => {
                        out.push(0x01);
                        put_spent(out, s);
                    }
                }
            }
            Event::Mint { ticker, v, pos, .. } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&v.to_le_bytes());
                out.extend_from_slice(&pos.to_le_bytes());
            }
            Event::Transfer { spent, .. } => put_spent(out, spent),
            Event::Burn { ticker, v_pub, spent, .. } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&v_pub.to_le_bytes());
                put_spent(out, spent);
            }
            Event::List { ticker, amount, price, spent, .. } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&price.to_le_bytes());
                put_spent(out, spent);
            }
            Event::Take { list_txid, outcome, pos, .. } => {
                out.extend_from_slice(list_txid);
                out.push(*outcome as u8);
                out.extend_from_slice(&pos.to_le_bytes());
            }
            Event::Claim { list_txid, pos, .. } => {
                out.extend_from_slice(list_txid);
                out.extend_from_slice(&pos.to_le_bytes());
            }
            Event::Genesis { ticker, max, lim, deploy_burn, window, min_depth } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&max.to_le_bytes());
                out.extend_from_slice(&lim.to_le_bytes());
                out.extend_from_slice(&deploy_burn.to_le_bytes());
                out.extend_from_slice(&window.to_le_bytes());
                out.extend_from_slice(&min_depth.to_le_bytes());
            }
            Event::TeamUnlock { ticker, pre, pos } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&pre.to_le_bytes());
                out.extend_from_slice(&pos.to_le_bytes());
            }
            Event::Closed { list_txid, .. } => out.extend_from_slice(list_txid),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
}

/// `events_H`: the records of a block, concatenated.
pub fn encode_all(events: &[Event]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in events {
        e.write(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record sizes of the table in §6.
    #[test]
    fn record_sizes() {
        let txid = [7u8; 32];
        let t = Ticker::SH20;
        let spent = Spent { nf: [[1; 32], [2; 32]], pos: [1, 2, 3] };
        let sizes = [
            (Event::Deploy { txid, ticker: t, burn: None }, 38),
            (Event::Deploy { txid, ticker: t, burn: Some(spent.clone()) }, 114),
            (Event::Mint { txid, ticker: t, v: 1, pos: 0 }, 49),
            (Event::Transfer { txid, spent: spent.clone() }, 109),
            (Event::Burn { txid, ticker: t, v_pub: 1, spent: spent.clone() }, 121),
            (Event::List { txid, ticker: t, amount: 1, price: 1, spent }, 129),
            (Event::Take { txid, list_txid: txid, outcome: Outcome::Cancelled, pos: 0 }, 70),
            (Event::Claim { txid, list_txid: txid, pos: 0 }, 69),
            (Event::Genesis { ticker: t, max: 1, lim: 1, deploy_burn: 0, window: 100, min_depth: 1 }, 69),
            (Event::TeamUnlock { ticker: t, pre: 1, pos: 0 }, 49),
            (Event::Closed { txid, list_txid: txid }, 65),
        ];
        for (e, n) in sizes {
            assert_eq!(e.encode().len(), n, "{}", e.name());
        }
    }
}
