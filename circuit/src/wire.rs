//! The bytes of proof-carrying envelopes a wallet builds (docs/SPEC-WIRE.md §4): the body that
//! `bodyHash` covers, and the envelope once the proof is attached.

use crate::model::{N_IN, N_OUT};
use crate::plonk::fr_to_bytes;
use ark_bn254::Fr;

pub const MAGIC: &[u8; 4] = b"SH20";
pub const VERSION: u8 = 0x00;
pub const TYPE_TRANSFER: u8 = 0x03;
pub const TYPE_BURN: u8 = 0x04;

/// One output of a spend as published: the leaf and the sealed note for its recipient.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub leaf: Fr,
    /// Compressed secp256k1 point (prefix 02 or 03).
    pub pk_eph: [u8; 33],
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

/// Body of a TRANSFER: every envelope byte before `proofLen`.
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

/// body ‖ proofLen (u16) ‖ proof.
pub fn envelope(mut body: Vec<u8>, proof: &[u8]) -> Vec<u8> {
    body.extend_from_slice(&(proof.len() as u16).to_le_bytes());
    body.extend_from_slice(proof);
    body
}
