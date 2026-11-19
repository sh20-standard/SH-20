//! Reference model of the SH-20 spend relation over BN254 Fr: BabyJubJub, note keys, the note leaf,
//! the nullifier, EdDSA-Poseidon, the tree and the spend witness. The circuit (`spend`) constrains
//! exactly what this module computes.
//!
//! Keys, nullifier and EdDSA-Poseidon are derived from Tacit's Bitcoin shielded pool
//! (contracts/sp1/confidential/btc-pool-halo2/src/model.rs), MIT License, Copyright (c) 2026 ross.
//! The note leaf, the public inputs and the absence of a transparent boundary are SH-20's
//! (docs/SPEC-WIRE.md §2 and §4).

use crate::poseidon::{h2, hash};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const TREE_DEPTH: usize = 32;
pub const N_IN: usize = 2;
pub const N_OUT: usize = 3;
/// root, nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub.
pub const N_PUBLIC: usize = 9;

pub const TAG_LEAF: &str = "sh20/v0/leaf";
pub const TAG_BODY: &str = "sh20/v0/body";
/// Domain of the signing nonce (`sign`). A wallet convention, not a rule: any nonce gives a valid signature.
pub const TAG_NONCE: &str = "sh20/v0/eddsa-nonce";

/// BabyJubJub: a·x² + y² = 1 + d·x²·y² over Fr.
pub const BJJ_A: u64 = 168700;
pub const BJJ_D: u64 = 168696;
/// Order l of the prime subgroup.
pub const L_DEC: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";
/// circomlib's Base8, the generator of the prime subgroup used for keys and signatures.
pub const BASE8: [&str; 2] = [
    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    "16950150798460657717958625567821834550301663161624707787222815936182638968203",
];

pub type Pt = [Fr; 2];

// ── field / integer helpers ──

pub fn big(dec: &str) -> BigUint {
    BigUint::parse_bytes(dec.as_bytes(), 10).expect("decimal")
}
pub fn p_big() -> BigUint {
    BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le())
}
pub fn l_big() -> &'static BigUint {
    static V: OnceLock<BigUint> = OnceLock::new();
    V.get_or_init(|| big(L_DEC))
}
/// Reduces modulo the field.
pub fn fr(x: &BigUint) -> Fr {
    Fr::from_le_bytes_mod_order(&x.to_bytes_le())
}
pub fn fr_dec(dec: &str) -> Fr {
    fr(&big(dec))
}
pub fn to_big(x: &Fr) -> BigUint {
    BigUint::from_bytes_le(&x.into_bigint().to_bytes_le())
}
/// Bit i of the canonical integer of x.
pub fn bit(x: &Fr, i: usize) -> bool {
    x.into_bigint().get_bit(i)
}

// ── BabyJubJub ──

pub fn identity() -> Pt {
    [Fr::zero(), Fr::one()]
}
pub fn base8() -> Pt {
    [fr_dec(BASE8[0]), fr_dec(BASE8[1])]
}
fn inv0(x: Fr) -> Fr {
    x.inverse().unwrap_or(Fr::zero())
}

/// The unified addition law (circomlib BabyAdd). A zero denominator yields 0.
pub fn add(p: &Pt, q: &Pt) -> Pt {
    let (a, d) = (Fr::from(BJJ_A), Fr::from(BJJ_D));
    let tau = p[0] * q[0] * p[1] * q[1];
    [(p[0] * q[1] + p[1] * q[0]) * inv0(Fr::one() + d * tau), (p[1] * q[1] - a * p[0] * q[0]) * inv0(Fr::one() - d * tau)]
}

/// k·P by double-and-add over the bits of k (no reduction).
pub fn mul(p: &Pt, k: &BigUint) -> Pt {
    let mut r = identity();
    let mut acc = *p;
    for i in 0..k.bits() {
        if k.bit(i) {
            r = add(&r, &acc);
        }
        acc = add(&acc, &acc);
    }
    r
}
pub fn mul_b8(k: &BigUint) -> Pt {
    mul(&base8(), &(k % l_big()))
}
pub fn on_curve(p: &Pt) -> bool {
    let (x2, y2) = (p[0].square(), p[1].square());
    Fr::from(BJJ_A) * x2 + y2 == Fr::one() + Fr::from(BJJ_D) * x2 * y2
}

// ── hashing ──

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// TAG_LEAF = SHA256("sh20/v0/leaf") mod r.
pub fn tag_leaf() -> Fr {
    static V: OnceLock<Fr> = OnceLock::new();
    *V.get_or_init(|| Fr::from_be_bytes_mod_order(&sha(&[TAG_LEAF.as_bytes()])))
}

/// bodyHash = SHA256("sh20/v0/body" ‖ body) mod r.
pub fn body_hash(body: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&sha(&[TAG_BODY.as_bytes(), body]))
}

/// SHA256(tag ‖ parts ‖ 0x00) ‖ SHA256(tag ‖ parts ‖ 0x01), read as a big-endian integer and reduced
/// modulo l (never 0).
pub fn hash_to_scalar(tag: &str, parts: &[&[u8]]) -> BigUint {
    let mut m: Vec<u8> = tag.as_bytes().to_vec();
    for p in parts {
        m.extend_from_slice(p);
    }
    let wide = [sha(&[&m, &[0u8]]), sha(&[&m, &[1u8]])].concat();
    let x = BigUint::from_bytes_be(&wide) % l_big();
    assert!(!x.is_zero(), "zero scalar");
    x
}

/// 32 bytes, big-endian.
pub fn be32(x: &BigUint) -> [u8; 32] {
    let v = x.to_bytes_be();
    let mut b = [0u8; 32];
    b[32 - v.len()..].copy_from_slice(&v);
    b
}

// ── notes ──

/// The asset id inside notes and proofs: the ticker's 4 ASCII characters `[A-Z0-9]` read as a
/// big-endian u32 ("GENE" = 0x47454e45), as `tickerT` in indexer/src/notes.js. `None` for anything
/// that is not a ticker. 0 is reserved for native BTC and no ticker maps to it.
pub fn ticker_t(ticker: &[u8]) -> Option<u32> {
    let t: [u8; 4] = ticker.try_into().ok()?;
    t.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).then(|| u32::from_be_bytes(t))
}

/// head = H(TAG_LEAF, t): the part of a leaf that depends on the asset id.
pub fn leaf_head(t: &Fr) -> Fr {
    h2(tag_leaf(), *t)
}

/// leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))    (indexer/src/notes.js)
pub fn note_leaf(t: &Fr, v: &Fr, npk: &Fr, rho: &Fr) -> Fr {
    h2(h2(leaf_head(t), *v), h2(*npk, *rho))
}

/// npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y).
pub fn npk_of(ak: &Pt, nk_pub: &Pt) -> Fr {
    hash(&[ak[0], ak[1], nk_pub[0], nk_pub[1]])
}

/// nf = Poseidon(nk, leaf, index).
pub fn nullifier(nk: &BigUint, leaf: &Fr, index: u64) -> Fr {
    assert!(nk < l_big() && index < (1u64 << TREE_DEPTH));
    hash(&[fr(nk), *leaf, Fr::from(index)])
}

/// The keys of one note: `sk` signs spends, `nk` derives the nullifier.
#[derive(Clone, Debug)]
pub struct NoteKeys {
    pub sk: BigUint,
    pub nk: BigUint,
    pub ak: Pt,
    pub nk_pub: Pt,
    pub npk: Fr,
}

pub fn note_keys(sk: &BigUint, nk: &BigUint) -> NoteKeys {
    let (sk, nk) = (sk % l_big(), nk % l_big());
    assert!(!sk.is_zero() && !nk.is_zero());
    let (ak, nk_pub) = (mul_b8(&sk), mul_b8(&nk));
    NoteKeys { npk: npk_of(&ak, &nk_pub), sk, nk, ak, nk_pub }
}

// ── tree ──

pub fn zeros() -> &'static [Fr; TREE_DEPTH + 1] {
    static Z: OnceLock<[Fr; TREE_DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [Fr::zero(); TREE_DEPTH + 1];
        for i in 1..=TREE_DEPTH {
            z[i] = h2(z[i - 1], z[i - 1]);
        }
        z
    })
}

/// The shared note tree, kept whole (for tests and small wallets).
pub struct Tree {
    layers: Vec<Vec<Fr>>,
    pub root: Fr,
}

impl Tree {
    pub fn new(leaves: &[Fr]) -> Tree {
        let z = zeros();
        let mut layers = vec![leaves.to_vec()];
        for d in 0..TREE_DEPTH {
            let next: Vec<Fr> = layers[d].chunks(2).map(|c| h2(c[0], if c.len() > 1 { c[1] } else { z[d] })).collect();
            layers.push(next);
        }
        let root = layers[TREE_DEPTH].first().copied().unwrap_or(z[TREE_DEPTH]);
        Tree { layers, root }
    }
    pub fn path(&self, index: usize) -> [Fr; TREE_DEPTH] {
        assert!(index < self.layers[0].len());
        let z = zeros();
        let mut out = [Fr::zero(); TREE_DEPTH];
        let mut i = index;
        for (d, slot) in out.iter_mut().enumerate() {
            *slot = self.layers[d].get(i ^ 1).copied().unwrap_or(z[d]);
            i >>= 1;
        }
        out
    }
}

pub fn root_from_path(leaf: &Fr, index: u64, path: &[Fr; TREE_DEPTH]) -> Fr {
    let mut cur = *leaf;
    for (d, sib) in path.iter().enumerate() {
        cur = if (index >> d) & 1 == 1 { h2(*sib, cur) } else { h2(cur, *sib) };
    }
    cur
}

// ── EdDSA-Poseidon ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sig {
    pub r8: Pt,
    pub s: Fr,
}

/// S·B8 = R8 + h·8·A with h = Poseidon(R8, A, m) and A = sk·B8. The nonce is derived from the key
/// and the message: r = hash_to_scalar(TAG_NONCE, be32(sk) ‖ be32(m)).
pub fn sign(sk: &BigUint, m: &Fr) -> Sig {
    let k = sk % l_big();
    let a = mul_b8(&k);
    let r = hash_to_scalar(TAG_NONCE, &[&be32(&k), &be32(&to_big(m))]);
    let r8 = mul_b8(&r);
    let h = to_big(&hash(&[r8[0], r8[1], a[0], a[1], *m]));
    Sig { r8, s: fr(&((r + BigUint::from(8u8) * h * k) % l_big())) }
}

/// What the circuit accepts: A and R8 on the curve, 0 ≤ S < l, 4·A with a non-zero x (A is not a
/// small-order point), and the equation with h as the integer of the hash.
pub fn verify_sig(a: &Pt, m: &Fr, sig: &Sig) -> bool {
    if &to_big(&sig.s) >= l_big() || !on_curve(a) || !on_curve(&sig.r8) {
        return false;
    }
    if mul(a, &BigUint::from(4u8))[0].is_zero() {
        return false;
    }
    let h = to_big(&hash(&[sig.r8[0], sig.r8[1], a[0], a[1], *m]));
    let a8 = mul(a, &BigUint::from(8u8));
    mul_b8(&to_big(&sig.s)) == add(&sig.r8, &mul(&a8, &h))
}

// ── witness ──

/// The assignment of the spend relation: nine public inputs, then the private part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendWitness {
    pub root: Fr,
    pub nf: [Fr; N_IN],
    pub out_leaf: [Fr; N_OUT],
    pub body_hash: Fr,
    pub v_pub: Fr,
    pub t_pub: Fr,

    pub t: Fr,
    pub in_v: [Fr; N_IN],
    pub in_rho: [Fr; N_IN],
    pub in_nk: [Fr; N_IN],
    pub in_ak: [Pt; N_IN],
    pub in_index: [Fr; N_IN],
    pub in_path: [[Fr; TREE_DEPTH]; N_IN],
    pub sig_r8: [Pt; N_IN],
    pub sig_s: [Fr; N_IN],
    pub out_v: [Fr; N_OUT],
    pub out_npk: [Fr; N_OUT],
    pub out_rho: [Fr; N_OUT],
}

impl Default for SpendWitness {
    fn default() -> Self {
        let z = Fr::zero();
        SpendWitness {
            root: z,
            nf: [z; N_IN],
            out_leaf: [z; N_OUT],
            body_hash: z,
            v_pub: z,
            t_pub: z,
            t: z,
            in_v: [z; N_IN],
            in_rho: [z; N_IN],
            in_nk: [Fr::one(); N_IN],
            in_ak: [base8(); N_IN],
            in_index: [z; N_IN],
            in_path: [[z; TREE_DEPTH]; N_IN],
            sig_r8: [base8(); N_IN],
            sig_s: [z; N_IN],
            out_v: [z; N_OUT],
            out_npk: [z; N_OUT],
            out_rho: [z; N_OUT],
        }
    }
}

/// Field elements in a serialized witness.
pub const WITNESS_ELEMENTS: usize = N_PUBLIC + 1 + N_IN * (7 + TREE_DEPTH + 2) + N_OUT * 3;
/// Bytes of a serialized witness.
pub const WITNESS_BYTES: usize = WITNESS_ELEMENTS * 32;

impl SpendWitness {
    /// The public inputs, in the order the verifier takes them.
    pub fn publics(&self) -> [Fr; N_PUBLIC] {
        [self.root, self.nf[0], self.nf[1], self.out_leaf[0], self.out_leaf[1], self.out_leaf[2], self.body_hash, self.v_pub, self.t_pub]
    }

    /// Every field in declaration order (arrays flattened, points as x then y).
    fn elements(&self) -> Vec<Fr> {
        let mut v = self.publics().to_vec();
        v.push(self.t);
        v.extend(self.in_v);
        v.extend(self.in_rho);
        v.extend(self.in_nk);
        v.extend(self.in_ak.iter().flatten());
        v.extend(self.in_index);
        v.extend(self.in_path.iter().flatten());
        v.extend(self.sig_r8.iter().flatten());
        v.extend(self.sig_s);
        v.extend(self.out_v);
        v.extend(self.out_npk);
        v.extend(self.out_rho);
        v
    }

    /// The witness as 32-byte little-endian field elements, in declaration order.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.elements().iter().flat_map(|x| x.into_bigint().to_bytes_le()).collect()
    }

    /// Strict inverse of `to_bytes` (canonical field elements, exact length).
    pub fn from_bytes(b: &[u8]) -> Option<SpendWitness> {
        if b.len() != WITNESS_BYTES {
            return None;
        }
        let mut it = b.chunks(32).map(crate::plonk::fr_from_bytes);
        let mut next = || it.next().flatten();
        let mut w = SpendWitness { root: next()?, ..SpendWitness::default() };
        for x in w.nf.iter_mut().chain(w.out_leaf.iter_mut()) {
            *x = next()?;
        }
        w.body_hash = next()?;
        w.v_pub = next()?;
        w.t_pub = next()?;
        w.t = next()?;
        for x in w.in_v.iter_mut().chain(w.in_rho.iter_mut()).chain(w.in_nk.iter_mut()).chain(w.in_ak.iter_mut().flatten()).chain(w.in_index.iter_mut()) {
            *x = next()?;
        }
        for x in w.in_path.iter_mut().flatten().chain(w.sig_r8.iter_mut().flatten()).chain(w.sig_s.iter_mut()) {
            *x = next()?;
        }
        for x in w.out_v.iter_mut().chain(w.out_npk.iter_mut()).chain(w.out_rho.iter_mut()) {
            *x = next()?;
        }
        Some(w)
    }
}

/// An input note of a spend under construction.
#[derive(Clone, Debug)]
pub struct InputNote {
    pub keys: NoteKeys,
    pub v: u64,
    pub rho: Fr,
    /// Position and sibling path in the tree; ignored (any value) for a dummy with v = 0.
    pub index: u64,
    pub path: [Fr; TREE_DEPTH],
}

/// An output note: the recipient's note public key, the amount and a fresh rho.
#[derive(Clone, Copy, Debug)]
pub struct OutputNote {
    pub npk: Fr,
    pub v: u64,
    pub rho: Fr,
}

/// Builds the witness of a spend of asset `t` (`ticker_t`) and signs `body_hash` with each input's
/// key. `t_pub` is `t` when value leaves the pool (BURN, LIST, DEPLOY) and 0 for a TRANSFER.
pub fn build_spend(t: u32, root: Fr, inputs: &[InputNote; N_IN], outputs: &[OutputNote; N_OUT], v_pub: u64, t_pub: u32, body_hash: Fr) -> SpendWitness {
    let tf = Fr::from(t as u64);
    let mut w = SpendWitness { root, body_hash, v_pub: Fr::from(v_pub), t_pub: Fr::from(t_pub as u64), t: tf, ..SpendWitness::default() };
    for (i, n) in inputs.iter().enumerate() {
        let leaf = note_leaf(&tf, &Fr::from(n.v), &n.keys.npk, &n.rho);
        let sig = sign(&n.keys.sk, &body_hash);
        w.nf[i] = nullifier(&n.keys.nk, &leaf, n.index);
        w.in_v[i] = Fr::from(n.v);
        w.in_rho[i] = n.rho;
        w.in_nk[i] = fr(&n.keys.nk);
        w.in_ak[i] = n.keys.ak;
        w.in_index[i] = Fr::from(n.index);
        w.in_path[i] = n.path;
        w.sig_r8[i] = sig.r8;
        w.sig_s[i] = sig.s;
    }
    for (k, o) in outputs.iter().enumerate() {
        w.out_leaf[k] = note_leaf(&tf, &Fr::from(o.v), &o.npk, &o.rho);
        w.out_v[k] = Fr::from(o.v);
        w.out_npk[k] = o.npk;
        w.out_rho[k] = o.rho;
    }
    w
}
