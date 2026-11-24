//! The bytes of proof-carrying envelopes a wallet builds (docs/SPEC-WIRE.md §4, wire v0.3): the body
//! that `bodyHash` covers, and the envelope once the 480-byte proof is attached.

use crate::model::{N_IN, N_OUT};
use crate::plonk::{fr_to_bytes, PROOF_BYTES};
use ark_bn254::Fr;

pub const MAGIC: &[u8; 4] = b"SH20";
pub const VERSION: u8 = 0x00;
pub const TYPE_DEPLOY: u8 = 0x01;
pub const TYPE_TRANSFER: u8 = 0x03;
pub const TYPE_BURN: u8 = 0x04;
pub const TYPE_LIST: u8 = 0x05;

/// One output of a spend as published: the leaf and the sealed note for its recipient.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub leaf: Fr,
    /// X25519 public key of the output (docs/SPEC-NOTES.md §3).
    pub pk_eph: [u8; 32],
    pub ct: [u8; 28],
}

/// anchorHeight ‖ nf0 ‖ nf1 ‖ 3 × (leaf ‖ pk_eph ‖ ct), without the proof.
fn spend_section(out: &mut Vec<u8>, anchor_height: u32, nf: &[Fr; N_IN], outs: &[Output; N_OUT]) {
    out.extend_from_slice(&anchor_height.to_le_bytes());
    for x in nf {
        out.extend_from_slice(&fr_to_bytes(x));
    }
    for o in outs {
        out.extend_from_slice(&fr_to_bytes(&o.leaf));
        out.extend_from_slice(&o.pk_eph);
        out.extend_from_slice(&o.ct);
    }
}

fn header(ty: u8) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&[VERSION, ty]);
    out
}

/// Body of a TRANSFER: every envelope byte before the proof.
pub fn transfer_body(anchor_height: u32, nf: &[Fr; N_IN], outs: &[Output; N_OUT]) -> Vec<u8> {
    let mut out = header(TYPE_TRANSFER);
    spend_section(&mut out, anchor_height, nf, outs);
    out
}

/// Body of a BURN of `v_pub` units of `ticker` (4 characters of `[A-Z0-9]`, see `model::ticker_t`).
pub fn burn_body(ticker: &[u8; 4], v_pub: u64, anchor_height: u32, nf: &[Fr; N_IN], outs: &[Output; N_OUT]) -> Vec<u8> {
    let mut out = header(TYPE_BURN);
    out.extend_from_slice(ticker);
    out.extend_from_slice(&v_pub.to_le_bytes());
    spend_section(&mut out, anchor_height, nf, outs);
    out
}

/// What a LIST says of its sale, in the order its body writes it.
#[derive(Clone, Copy, Debug)]
pub struct Listing<'a> {
    pub ticker: &'a [u8; 4],
    /// units leaving the pool: `vPub` of the spend
    pub amount: u64,
    /// sats
    pub price: u64,
    /// the output of the LIST transaction that is the lock
    pub lock_vout: u8,
    /// the x-only key that output pays (`OP_1 <lock_key>`): in the body, so the signature covers it
    pub lock_key: &'a [u8; 32],
    /// 1 to 34 bytes, never an OP_RETURN
    pub pay_script: &'a [u8],
}

/// Body of a LIST: the spend has `vPub = amount` and `tPub` the asset id of `ticker`.
pub fn list_body(l: &Listing, anchor_height: u32, nf: &[Fr; N_IN], outs: &[Output; N_OUT]) -> Vec<u8> {
    let mut out = header(TYPE_LIST);
    out.extend_from_slice(l.ticker);
    out.extend_from_slice(&l.amount.to_le_bytes());
    out.extend_from_slice(&l.price.to_le_bytes());
    out.push(l.lock_vout);
    out.extend_from_slice(l.lock_key);
    pay_script(&mut out, l.pay_script);
    spend_section(&mut out, anchor_height, nf, outs);
    out
}

/// What a DEPLOY says of its token, in the order its body writes it.
#[derive(Clone, Copy, Debug)]
pub struct Deploy<'a> {
    pub ticker: &'a [u8; 4],
    pub max: u64,
    pub lim: u64,
    pub pre: u64,
    pub start: u32,
    pub end: u32,
    pub unlock: u32,
    /// sats for each mint
    pub price: u64,
    /// 0 none, 1 burn, 2 pay to `pay_script`
    pub pay_mode: u8,
    /// empty unless `pay_mode` is 2
    pub pay_script: &'a [u8],
    /// the team's public opening (its npk): written when `pre > 0`, and only then
    pub team: Fr,
}

/// Body of a DEPLOY that burns genesis units: the spend has `vPub = D` (the profile's deploy burn)
/// and `tPub` the asset id of the genesis ticker. Where `D = 0` a DEPLOY has no spend, and no body.
pub fn deploy_body(d: &Deploy, anchor_height: u32, nf: &[Fr; N_IN], outs: &[Output; N_OUT]) -> Vec<u8> {
    let mut out = header(TYPE_DEPLOY);
    out.extend_from_slice(d.ticker);
    for x in [d.max, d.lim, d.pre] {
        out.extend_from_slice(&x.to_le_bytes());
    }
    for x in [d.start, d.end, d.unlock] {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.extend_from_slice(&d.price.to_le_bytes());
    out.push(d.pay_mode);
    pay_script(&mut out, d.pay_script);
    if d.pre > 0 {
        out.extend_from_slice(&fr_to_bytes(&d.team));
    }
    spend_section(&mut out, anchor_height, nf, outs);
    out
}

/// psLen ‖ payScript. The length is one byte: a script is at most 34 bytes.
fn pay_script(out: &mut Vec<u8>, script: &[u8]) {
    out.push(u8::try_from(script.len()).expect("a payScript is at most 34 bytes"));
    out.extend_from_slice(script);
}

/// body ‖ proof. The proof has a fixed size and no length field.
pub fn envelope(mut body: Vec<u8>, proof: &[u8; PROOF_BYTES]) -> Vec<u8> {
    body.extend_from_slice(proof);
    body
}

#[cfg(feature = "wallet")]
impl From<crate::notes::Sealed> for Output {
    fn from(o: crate::notes::Sealed) -> Output {
        Output { leaf: o.leaf, pk_eph: o.pk_eph, ct: o.ct }
    }
}
