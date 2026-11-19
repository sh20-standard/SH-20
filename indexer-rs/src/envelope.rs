//! Strict codec for the 7 envelopes (SPEC-WIRE §4).
//!
//! `decode` accepts exactly the byte strings the spec describes: after parsing, re-serialising
//! gives the same bytes, and trailing bytes are rejected.

use crate::field::{body_hash, is_canonical, Bytes32};
use ark_bn254::Fr;

pub const MAGIC: &[u8; 4] = b"SH20";
pub const VERSION: u8 = 0x00;
pub const HEADER_LEN: usize = 6;
pub const PROOF_LEN: usize = 480;
pub const CT_LEN: usize = 28;
/// `anchorHeight(4) ‖ nf0(32) ‖ nf1(32) ‖ 3 × [leaf(32) ‖ pk_eph(32) ‖ ct(28)] ‖ proof(480)`.
pub const SPEND_LEN: usize = 4 + 32 + 32 + 3 * (32 + 32 + CT_LEN) + PROOF_LEN;
pub const PAY_SCRIPT_MAX: usize = 34;
pub const MINT_BATCH_MAX: u8 = 10;

pub const TYPE_DEPLOY: u8 = 0x01;
pub const TYPE_MINT: u8 = 0x02;
pub const TYPE_TRANSFER: u8 = 0x03;
pub const TYPE_BURN: u8 = 0x04;
pub const TYPE_LIST: u8 = 0x05;
pub const TYPE_TAKE: u8 = 0x06;
pub const TYPE_CLAIM: u8 = 0x07;

/// 4 ASCII characters `[A-Z0-9]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticker(pub [u8; 4]);

impl Ticker {
    pub const SH20: Ticker = Ticker(*b"SH20");

    pub fn new(b: [u8; 4]) -> Option<Ticker> {
        if b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            Some(Ticker(b))
        } else {
            None
        }
    }

    pub fn parse(s: &str) -> Option<Ticker> {
        Ticker::new(s.as_bytes().try_into().ok()?)
    }

    /// `tickerT`: the 4 ASCII bytes read as a big-endian u32.
    pub fn t(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("ASCII by construction")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendOutput {
    pub leaf: Bytes32,
    pub pk_eph: Bytes32,
    pub ct: [u8; CT_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub anchor_height: u32,
    pub nf: [Bytes32; 2],
    pub outputs: [SpendOutput; 3],
    pub proof: Vec<u8>, // exactly PROOF_LEN bytes
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deploy {
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
    /// Present exactly when `pre > 0`.
    pub team_opening: Option<Bytes32>,
    /// The burn of `D` (required or forbidden by the profile, not by the codec).
    pub spend: Option<Spend>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    Deploy(Deploy),
    /// `k` is `None` for a single mint, `Some(2..=10)` for a batch.
    Mint {
        ticker: Ticker,
        opening: Bytes32,
        k: Option<u8>,
    },
    Transfer {
        spend: Spend,
    },
    Burn {
        ticker: Ticker,
        v_pub: u64,
        spend: Spend,
    },
    List {
        ticker: Ticker,
        amount: u64,
        price: u64,
        lock_vout: u8,
        pay_script: Vec<u8>,
        spend: Spend,
    },
    Take {
        opening: Bytes32,
    },
    /// `list_txid` in display (RPC) byte order.
    Claim {
        list_txid: Bytes32,
        opening: Bytes32,
        sig: [u8; 64],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes do not start with `SH20`: not an envelope at all.
    NotSh20,
    /// `SH20` followed by a version other than `0x00`: ignored (SPEC-GAPS §2.2).
    UnknownVersion(u8),
    /// An SH-20 v0 envelope the spec rejects.
    Rejected(&'static str),
}

use DecodeError::Rejected;

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.b.len() - self.at
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.left() < n {
            return Err(Rejected("truncated envelope"));
        }
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes32(&mut self) -> Result<Bytes32, DecodeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// A field element: 32 bytes, little-endian, below `r`.
    fn field(&mut self, what: &'static str) -> Result<Bytes32, DecodeError> {
        let b = self.bytes32()?;
        if is_canonical(&b) {
            Ok(b)
        } else {
            Err(Rejected(what))
        }
    }
    fn ticker(&mut self) -> Result<Ticker, DecodeError> {
        let b: [u8; 4] = self.take(4)?.try_into().unwrap();
        Ticker::new(b).ok_or(Rejected("ticker is not 4 characters of [A-Z0-9]"))
    }
    fn pay_script(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u8()? as usize;
        if n > PAY_SCRIPT_MAX {
            return Err(Rejected("payScript longer than 34 bytes"));
        }
        Ok(self.take(n)?.to_vec())
    }
    fn spend(&mut self) -> Result<Spend, DecodeError> {
        if self.left() < SPEND_LEN {
            return Err(Rejected("truncated spend section"));
        }
        let anchor_height = self.u32()?;
        let nf = [self.field("nullifier is not a field element")?, self.field("nullifier is not a field element")?];
        let mut out = || -> Result<SpendOutput, DecodeError> {
            Ok(SpendOutput {
                leaf: self.field("output leaf is not a field element")?,
                pk_eph: self.bytes32()?,
                ct: self.take(CT_LEN)?.try_into().unwrap(),
            })
        };
        let outputs = [out()?, out()?, out()?];
        let proof = self.take(PROOF_LEN)?.to_vec();
        Ok(Spend { anchor_height, nf, outputs, proof })
    }
    fn end(&self) -> Result<(), DecodeError> {
        if self.left() == 0 {
            Ok(())
        } else {
            Err(Rejected("trailing bytes"))
        }
    }
}

impl Spend {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.anchor_height.to_le_bytes());
        out.extend_from_slice(&self.nf[0]);
        out.extend_from_slice(&self.nf[1]);
        for o in &self.outputs {
            out.extend_from_slice(&o.leaf);
            out.extend_from_slice(&o.pk_eph);
            out.extend_from_slice(&o.ct);
        }
        out.extend_from_slice(&self.proof);
    }
}

impl Envelope {
    pub fn type_code(&self) -> u8 {
        match self {
            Envelope::Deploy(_) => TYPE_DEPLOY,
            Envelope::Mint { .. } => TYPE_MINT,
            Envelope::Transfer { .. } => TYPE_TRANSFER,
            Envelope::Burn { .. } => TYPE_BURN,
            Envelope::List { .. } => TYPE_LIST,
            Envelope::Take { .. } => TYPE_TAKE,
            Envelope::Claim { .. } => TYPE_CLAIM,
        }
    }

    pub fn spend(&self) -> Option<&Spend> {
        match self {
            Envelope::Deploy(d) => d.spend.as_ref(),
            Envelope::Transfer { spend } | Envelope::Burn { spend, .. } | Envelope::List { spend, .. } => Some(spend),
            _ => None,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, DecodeError> {
        if bytes.len() < 4 || &bytes[..4] != MAGIC {
            return Err(DecodeError::NotSh20);
        }
        if bytes.len() < HEADER_LEN {
            if bytes.len() == 5 && bytes[4] != VERSION {
                return Err(DecodeError::UnknownVersion(bytes[4]));
            }
            return Err(Rejected("truncated header"));
        }
        if bytes[4] != VERSION {
            return Err(DecodeError::UnknownVersion(bytes[4]));
        }
        let mut r = Reader { b: bytes, at: HEADER_LEN };
        let env = match bytes[5] {
            TYPE_DEPLOY => {
                let ticker = r.ticker()?;
                let max = r.u64()?;
                let lim = r.u64()?;
                let pre = r.u64()?;
                let start = r.u32()?;
                let end = r.u32()?;
                let unlock = r.u32()?;
                let price = r.u64()?;
                let pay_mode = r.u8()?;
                if pay_mode > 2 {
                    return Err(Rejected("unknown payMode"));
                }
                let pay_script = r.pay_script()?;
                if pay_mode != 2 && !pay_script.is_empty() {
                    return Err(Rejected("payScript without payMode 2"));
                }
                let team_opening = if pre > 0 { Some(r.field("team opening is not a field element")?) } else { None };
                let spend = if r.left() > 0 { Some(r.spend()?) } else { None };
                Envelope::Deploy(Deploy {
                    ticker,
                    max,
                    lim,
                    pre,
                    start,
                    end,
                    unlock,
                    price,
                    pay_mode,
                    pay_script,
                    team_opening,
                    spend,
                })
            }
            TYPE_MINT => {
                let ticker = r.ticker()?;
                let opening = r.field("opening is not a field element")?;
                let k = if r.left() > 0 {
                    let k = r.u8()?;
                    if !(2..=MINT_BATCH_MAX).contains(&k) {
                        return Err(Rejected("k outside 2..10"));
                    }
                    Some(k)
                } else {
                    None
                };
                Envelope::Mint { ticker, opening, k }
            }
            TYPE_TRANSFER => Envelope::Transfer { spend: r.spend()? },
            TYPE_BURN => {
                let ticker = r.ticker()?;
                let v_pub = r.u64()?;
                Envelope::Burn { ticker, v_pub, spend: r.spend()? }
            }
            TYPE_LIST => {
                let ticker = r.ticker()?;
                let amount = r.u64()?;
                let price = r.u64()?;
                let lock_vout = r.u8()?;
                let pay_script = r.pay_script()?;
                Envelope::List { ticker, amount, price, lock_vout, pay_script, spend: r.spend()? }
            }
            TYPE_TAKE => Envelope::Take { opening: r.field("opening is not a field element")? },
            TYPE_CLAIM => {
                let list_txid = r.bytes32()?;
                let opening = r.field("opening is not a field element")?;
                let sig: [u8; 64] = r.take(64)?.try_into().unwrap();
                Envelope::Claim { list_txid, opening, sig }
            }
            _ => return Err(Rejected("unknown type")),
        };
        r.end()?;
        // "After parsing, re-serialising must give the same bytes."
        if env.encode() != bytes {
            return Err(Rejected("not the canonical serialisation"));
        }
        Ok(env)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.type_code());
        match self {
            Envelope::Deploy(d) => {
                out.extend_from_slice(&d.ticker.0);
                out.extend_from_slice(&d.max.to_le_bytes());
                out.extend_from_slice(&d.lim.to_le_bytes());
                out.extend_from_slice(&d.pre.to_le_bytes());
                out.extend_from_slice(&d.start.to_le_bytes());
                out.extend_from_slice(&d.end.to_le_bytes());
                out.extend_from_slice(&d.unlock.to_le_bytes());
                out.extend_from_slice(&d.price.to_le_bytes());
                out.push(d.pay_mode);
                out.push(d.pay_script.len() as u8);
                out.extend_from_slice(&d.pay_script);
                if let Some(o) = &d.team_opening {
                    out.extend_from_slice(o);
                }
                if let Some(s) = &d.spend {
                    s.write(&mut out);
                }
            }
            Envelope::Mint { ticker, opening, k } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(opening);
                if let Some(k) = k {
                    out.push(*k);
                }
            }
            Envelope::Transfer { spend } => spend.write(&mut out),
            Envelope::Burn { ticker, v_pub, spend } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&v_pub.to_le_bytes());
                spend.write(&mut out);
            }
            Envelope::List { ticker, amount, price, lock_vout, pay_script, spend } => {
                out.extend_from_slice(&ticker.0);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&price.to_le_bytes());
                out.push(*lock_vout);
                out.push(pay_script.len() as u8);
                out.extend_from_slice(pay_script);
                spend.write(&mut out);
            }
            Envelope::Take { opening } => out.extend_from_slice(opening),
            Envelope::Claim { list_txid, opening, sig } => {
                out.extend_from_slice(list_txid);
                out.extend_from_slice(opening);
                out.extend_from_slice(sig);
            }
        }
        out
    }
}

/// `bodyHash` of a serialized envelope that ends with a spend section:
/// `SHA256("sh20/v0/body" ‖ every envelope byte before the proof) mod r`.
pub fn body_hash_of(envelope_bytes: &[u8]) -> Fr {
    let body_len = envelope_bytes.len().saturating_sub(PROOF_LEN);
    body_hash(&envelope_bytes[..body_len])
}
