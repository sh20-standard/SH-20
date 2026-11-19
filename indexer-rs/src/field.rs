//! The field `Fr`, Poseidon and the hashes built on them (SPEC-WIRE §1, §2).
//!
//! Poseidon comes from `light-poseidon` (circom parameters) and SHA-256 from `sha2`:
//! nothing here is shared with the reference indexer.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

pub type Bytes32 = [u8; 32];

/// A wire field element: 32 bytes, little-endian, value below `r`. `None` for anything else.
pub fn fr_from_le(b: &Bytes32) -> Option<Fr> {
    let f = Fr::from_le_bytes_mod_order(b);
    if fr_to_le(&f) == *b {
        Some(f)
    } else {
        None
    }
}

/// True when the 32 bytes are a canonical field element (little-endian, below `r`).
pub fn is_canonical(b: &Bytes32) -> bool {
    fr_from_le(b).is_some()
}

pub fn fr_to_le(f: &Fr) -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_le());
    out
}

pub fn fr_to_be(f: &Fr) -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_be());
    out
}

pub fn sha256(parts: &[&[u8]]) -> Bytes32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `SHA256(tag ‖ data) mod r`, the digest read as a big-endian integer (see SPEC-GAPS §1.1).
pub fn sha256_mod_r(parts: &[&[u8]]) -> Fr {
    Fr::from_be_bytes_mod_order(&sha256(parts))
}

thread_local! {
    static POSEIDON2: RefCell<Poseidon<Fr>> =
        RefCell::new(Poseidon::<Fr>::new_circom(2).expect("circom Poseidon, 2 inputs"));
    static TAG_LEAF: Fr = sha256_mod_r(&[b"sh20/v0/leaf"]);
}

/// `H(a, b)`: Poseidon with 2 inputs, circomlib parameters.
pub fn h2(a: &Fr, b: &Fr) -> Fr {
    POSEIDON2.with(|p| p.borrow_mut().hash(&[*a, *b]).expect("two inputs"))
}

/// `TAG_LEAF = SHA256("sh20/v0/leaf") mod r`.
pub fn tag_leaf() -> Fr {
    TAG_LEAF.with(|t| *t)
}

/// `leaf = H( H( H(TAG_LEAF, t), v ), H(npk, rho) )`.
pub fn note_leaf(t: u32, v: u64, npk: &Fr, rho: &Fr) -> Fr {
    let a = h2(&tag_leaf(), &Fr::from(t));
    let b = h2(&a, &Fr::from(v));
    h2(&b, &h2(npk, rho))
}

/// The leaf of a public note (`rho = 0`).
pub fn public_leaf(t: u32, v: u64, npk: &Fr) -> Fr {
    note_leaf(t, v, npk, &Fr::zero())
}

/// `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r`.
pub fn body_hash(body: &[u8]) -> Fr {
    sha256_mod_r(&[b"sh20/v0/body", body])
}

// ---- hex ----

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
}

pub fn unhex32(s: &str) -> Option<Bytes32> {
    let v = unhex(s)?;
    v.try_into().ok()
}
