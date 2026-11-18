//! The wallet side of notes, as specified in docs/SPEC-NOTES.md: keys from a master secret, the
//! address, sealing an output to an address, scanning with the leaf check, and public notes.
//!
//! This is the model that writes the reference vectors (`vectors`); `circuit/js` restates it with
//! Node's own X25519, HKDF and AES-GCM, so the two share no cryptographic code. It is not a wallet:
//! nothing here is constant-time or zeroized.

use crate::model::{self, Pt};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const TAG_SEED: &[u8] = b"sh20/v0/seed";
pub const TAG_ASK: &str = "sh20/v0/key/ask";
pub const TAG_NSK: &str = "sh20/v0/key/nsk";
pub const TAG_IVK: &[u8] = b"sh20/v0/key/ivk";
pub const TAG_NOTE: &[u8] = b"sh20/v0/note";
pub const TAG_TWEAK_A: &str = "sh20/v0/note/tweak-a";
pub const TAG_TWEAK_N: &str = "sh20/v0/note/tweak-n";
pub const TAG_RHO: &str = "sh20/v0/note/rho";
pub const TAG_AEAD: &[u8] = b"sh20/v0/note/aead";
pub const TAG_SELF: &[u8] = b"sh20/v0/self";

/// Version byte of an address.
pub const ADDRESS_VERSION: u8 = 0x00;
/// Bytes of an address before bech32m: version ‖ IVK ‖ pack(A) ‖ pack(N).
pub const ADDRESS_BYTES: usize = 1 + 32 + 32 + 32;

// ── hashing ──

/// The two halves SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01).
fn wide(tag: &str, x: &[u8; 32]) -> [u8; 64] {
    let half = |last: u8| Sha256::new().chain_update(tag.as_bytes()).chain_update(x).chain_update([last]).finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&half(0));
    out[32..].copy_from_slice(&half(1));
    out
}

/// hs(tag, x): a BabyJubJub scalar. `None` for the value 0, which a wallet treats as invalid.
pub fn hs(tag: &str, x: &[u8; 32]) -> Option<BigUint> {
    let v = BigUint::from_bytes_be(&wide(tag, x)) % model::l_big();
    (v != BigUint::from(0u8)).then_some(v)
}

/// hr(tag, x): a field element.
pub fn hr(tag: &str, x: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(&wide(tag, x))
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out).expect("output length");
}

/// 32 bytes, little-endian: a field element as on the wire.
pub fn fr_le(x: &Fr) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().expect("32 bytes")
}

// ── points in addresses ──

/// circomlib's packPoint: y little-endian, the top bit set when x > (r − 1) / 2.
pub fn pack_point(p: &Pt) -> [u8; 32] {
    let mut b = fr_le(&p[1]);
    if p[0].into_bigint() > Fr::MODULUS_MINUS_ONE_DIV_TWO {
        b[31] |= 0x80;
    }
    b
}

/// The inverse of `pack_point`, strict: y below r, x recovered from the curve equation with the
/// stated sign, and no second encoding of a point with x = 0.
pub fn unpack_point(b: &[u8; 32]) -> Option<Pt> {
    let mut y_bytes = *b;
    let sign = y_bytes[31] & 0x80 != 0;
    y_bytes[31] &= 0x7f;
    let y = crate::plonk::fr_from_bytes(&y_bytes)?;
    // a·x² + y² = 1 + d·x²·y²  ⇒  x² = (1 − y²) / (a − d·y²)
    let y2 = y.square();
    let x2 = (Fr::one() - y2) * (Fr::from(model::BJJ_A) - Fr::from(model::BJJ_D) * y2).inverse()?;
    let mut x = x2.sqrt()?;
    if (x.into_bigint() > Fr::MODULUS_MINUS_ONE_DIV_TWO) != sign {
        x = -x;
    }
    if x.is_zero() && sign {
        return None;
    }
    Some([x, y])
}

/// A point a wallet accepts as a key: on the curve, in the subgroup of order l, not the identity.
pub fn is_key_point(p: &Pt) -> bool {
    model::on_curve(p) && *p != model::identity() && model::mul(p, model::l_big()) == model::identity()
}

// ── keys ──

/// m = the first 32 bytes of HMAC-SHA512(key = "sh20/v0/seed", data = the 64-byte BIP39 seed).
pub fn master_secret(bip39_seed: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(TAG_SEED).expect("any key length");
    mac.update(bip39_seed);
    mac.finalize().into_bytes()[..32].try_into().expect("32 bytes")
}

/// Everything a wallet derives from its master secret.
#[derive(Clone, Debug)]
pub struct WalletKeys {
    pub ask: BigUint,
    pub nsk: BigUint,
    pub ivk: [u8; 32],
    pub address: Address,
}

/// The public part of a wallet: what a payer needs, and with `ivk` what a viewer needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// X25519 public key.
    pub ivk_pub: [u8; 32],
    /// ask·B8.
    pub a: Pt,
    /// nsk·B8.
    pub n: Pt,
}

pub fn wallet_keys(m: &[u8; 32]) -> Option<WalletKeys> {
    let (ask, nsk) = (hs(TAG_ASK, m)?, hs(TAG_NSK, m)?);
    let ivk: [u8; 32] = Sha256::new().chain_update(TAG_IVK).chain_update(m).finalize().into();
    let address = Address { ivk_pub: x25519(ivk, X25519_BASEPOINT_BYTES), a: model::mul_b8(&ask), n: model::mul_b8(&nsk) };
    Some(WalletKeys { ask, nsk, ivk, address })
}

// ── address ──

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2bc8_30a3;

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    hrp.bytes().map(|c| c >> 5).chain(std::iter::once(0)).chain(hrp.bytes().map(|c| c & 31)).collect()
}

/// Bech32m (BIP-350) of arbitrary bytes, without the 90-character limit of BIP-173.
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let mut fives = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            fives.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        fives.push(((acc << (5 - bits)) & 31) as u8);
    }
    let pm = polymod(hrp_expand(hrp).into_iter().chain(fives.iter().copied()).chain([0u8; 6])) ^ BECH32M;
    let checksum = (0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8);
    let body: String = fives.iter().copied().chain(checksum).map(|v| CHARSET[v as usize] as char).collect();
    format!("{hrp}1{body}")
}

/// Strict inverse: one case throughout, a valid checksum, and padding of fewer than 5 zero bits.
pub fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), String> {
    if s.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err("address: invalid character".into());
    }
    let (lower, upper) = (s.to_ascii_lowercase(), s.to_ascii_uppercase());
    if s != lower && s != upper {
        return Err("address: mixed case".into());
    }
    let (hrp, body) = lower.rsplit_once('1').ok_or("address: no separator")?;
    if hrp.is_empty() || body.len() < 6 {
        return Err("address: too short".into());
    }
    let fives: Vec<u8> = body.bytes().map(|c| CHARSET.iter().position(|x| *x == c).map(|i| i as u8).ok_or("address: invalid character")).collect::<Result<_, _>>()?;
    if polymod(hrp_expand(hrp).into_iter().chain(fives.iter().copied())) != BECH32M {
        return Err("address: wrong checksum".into());
    }
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut data = Vec::new();
    for v in &fives[..fives.len() - 6] {
        acc = ((acc << 5) | *v as u32) & 0x0fff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            data.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return Err("address: invalid padding".into());
    }
    Ok((hrp.to_string(), data))
}

/// address = bech32m(hrp, 0x00 ‖ IVK ‖ pack(A) ‖ pack(N)).
pub fn encode_address(hrp: &str, a: &Address) -> String {
    let mut data = vec![ADDRESS_VERSION];
    data.extend_from_slice(&a.ivk_pub);
    data.extend_from_slice(&pack_point(&a.a));
    data.extend_from_slice(&pack_point(&a.n));
    bech32m_encode(hrp, &data)
}

/// Decodes and validates an address: the expected network, version 0, A and N key points, and an
/// IVK that is not a low-order point (one for which every shared secret is zero).
pub fn decode_address(expected_hrp: &str, s: &str) -> Result<Address, String> {
    let (hrp, data) = bech32m_decode(s)?;
    if hrp != expected_hrp {
        return Err("address: for another network".into());
    }
    if data.len() != ADDRESS_BYTES || data[0] != ADDRESS_VERSION {
        return Err("address: unknown version or length".into());
    }
    let ivk_pub: [u8; 32] = data[1..33].try_into().unwrap();
    let a = unpack_point(data[33..65].try_into().unwrap()).filter(is_key_point).ok_or("address: A is not a key")?;
    let n = unpack_point(data[65..97].try_into().unwrap()).filter(is_key_point).ok_or("address: N is not a key")?;
    // a low-order point gives the all-zero secret with any private key
    if x25519([0x42; 32], ivk_pub) == [0u8; 32] {
        return Err("address: IVK is a low-order point".into());
    }
    Ok(Address { ivk_pub, a, n })
}

// ── notes ──

/// What follows from a note's 32-byte secret `s`: the two key tweaks and rho.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSecrets {
    pub tau_a: BigUint,
    pub tau_n: BigUint,
    pub rho: Fr,
}

pub fn note_secrets(s: &[u8; 32]) -> Option<NoteSecrets> {
    Some(NoteSecrets { tau_a: hs(TAG_TWEAK_A, s)?, tau_n: hs(TAG_TWEAK_N, s)?, rho: hr(TAG_RHO, s) })
}

/// Ak = A + τa·B8, NK = N + τn·B8, npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y).
pub fn note_npk(address: &Address, secrets: &NoteSecrets) -> Fr {
    let ak = model::add(&address.a, &model::mul_b8(&secrets.tau_a));
    let nk = model::add(&address.n, &model::mul_b8(&secrets.tau_n));
    model::npk_of(&ak, &nk)
}

/// An output as published: leaf ‖ pk_eph ‖ ct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub leaf: Fr,
    pub pk_eph: [u8; 32],
    pub ct: [u8; 28],
}

fn shared_secret(z: &[u8; 32], pk_eph: &[u8; 32], ivk_pub: &[u8; 32]) -> [u8; 32] {
    let mut s = [0u8; 32];
    hkdf(TAG_NOTE, z, &[pk_eph.as_slice(), ivk_pub.as_slice()].concat(), &mut s);
    s
}

fn aead(s: &[u8; 32], leaf: &[u8; 32]) -> (Aes256Gcm, [u8; 12]) {
    let mut okm = [0u8; 44];
    hkdf(TAG_AEAD, s, leaf, &mut okm);
    (Aes256Gcm::new_from_slice(&okm[..32]).expect("32-byte key"), okm[32..].try_into().unwrap())
}

/// Seals `v` units of `ticker` to `address` with the fresh X25519 private key `e` (§3). Also returns
/// the note's secrets, which the sender needs to put the note in its proof.
pub fn seal(address: &Address, ticker: &[u8; 4], v: u64, e: &[u8; 32]) -> Result<(Sealed, NoteSecrets, Fr), String> {
    let t = model::ticker_t(ticker).ok_or("not a ticker")?;
    let pk_eph = x25519(*e, X25519_BASEPOINT_BYTES);
    let z = x25519(*e, address.ivk_pub);
    if z == [0u8; 32] {
        return Err("address: IVK is a low-order point".into());
    }
    let s = shared_secret(&z, &pk_eph, &address.ivk_pub);
    let secrets = note_secrets(&s).ok_or("zero tweak")?;
    let npk = note_npk(address, &secrets);
    let leaf = model::note_leaf(&Fr::from(t as u64), &Fr::from(v), &npk, &secrets.rho);
    let leaf_bytes = fr_le(&leaf);
    let (cipher, nonce) = aead(&s, &leaf_bytes);
    let plaintext = [v.to_le_bytes().as_slice(), ticker.as_slice()].concat();
    let ct = cipher.encrypt(&nonce.into(), Payload { msg: &plaintext, aad: &leaf_bytes }).map_err(|_| "encryption failed")?;
    Ok((Sealed { leaf, pk_eph, ct: ct.try_into().map_err(|_| "ciphertext length")? }, secrets, npk))
}

/// A note found by scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub ticker: [u8; 4],
    pub v: u64,
    pub secrets: NoteSecrets,
    pub npk: Fr,
}

/// Tries to open an output with an incoming viewing key (§4). `None` unless the tag verifies, the
/// plaintext names a ticker, and the leaf is the one this wallet computes for it.
pub fn scan(ivk: &[u8; 32], address: &Address, sealed: &Sealed) -> Option<Opened> {
    let z = x25519(*ivk, sealed.pk_eph);
    if z == [0u8; 32] {
        return None;
    }
    let s = shared_secret(&z, &sealed.pk_eph, &address.ivk_pub);
    let leaf_bytes = fr_le(&sealed.leaf);
    let (cipher, nonce) = aead(&s, &leaf_bytes);
    let plaintext = cipher.decrypt(&nonce.into(), Payload { msg: &sealed.ct, aad: &leaf_bytes }).ok()?;
    let v = u64::from_le_bytes(plaintext[..8].try_into().ok()?);
    let ticker: [u8; 4] = plaintext[8..].try_into().ok()?;
    let t = model::ticker_t(&ticker)?;
    let secrets = note_secrets(&s)?;
    let npk = note_npk(address, &secrets);
    (model::note_leaf(&Fr::from(t as u64), &Fr::from(v), &npk, &secrets.rho) == sealed.leaf).then_some(Opened { ticker, v, secrets, npk })
}

/// The keys that spend a note: sk = ask + τa, nk = nsk + τn (mod l). `None` if either is zero.
pub fn spend_keys(keys: &WalletKeys, secrets: &NoteSecrets) -> Option<model::NoteKeys> {
    let l = model::l_big();
    let (sk, nk) = ((&keys.ask + &secrets.tau_a) % l, (&keys.nsk + &secrets.tau_n) % l);
    let zero = BigUint::from(0u8);
    (sk != zero && nk != zero).then(|| model::note_keys(&sk, &nk))
}

/// The secret of the wallet's i-th public note (§5): HKDF(salt "sh20/v0/self", ikm = ivk, info = u32le(i)).
pub fn self_secret(ivk: &[u8; 32], i: u32) -> [u8; 32] {
    let mut s = [0u8; 32];
    hkdf(TAG_SELF, ivk, &i.to_le_bytes(), &mut s);
    s
}

/// The opening `npk` a wallet publishes for its i-th public note, with the note's secrets. A public
/// note has rho = 0 (docs/SPEC-WIRE.md §2), so the returned secrets carry rho = 0, not hr(s_i).
pub fn public_opening(ivk: &[u8; 32], address: &Address, i: u32) -> Option<(Fr, NoteSecrets)> {
    let s = self_secret(ivk, i);
    let secrets = NoteSecrets { tau_a: hs(TAG_TWEAK_A, &s)?, tau_n: hs(TAG_TWEAK_N, &s)?, rho: Fr::zero() };
    Some((note_npk(address, &secrets), secrets))
}
