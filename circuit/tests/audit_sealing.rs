//! Tests written by the audit of the part `sealing` (docs/audit/2026-11-24-sealing.md), on the Rust
//! model of docs/SPEC-NOTES.md (src/notes.rs): X25519 on every encoding, what a scan does with an
//! output made to mislead it, and the addresses a payer refuses. The same questions are put to the
//! two JavaScript entry points in circuit/js/test/audit-sealing.test.js.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use num_bigint::BigUint;
use sh20_circuit::notes::{self, Sealed};

fn p() -> BigUint {
    (BigUint::from(1u8) << 255) - BigUint::from(19u8)
}

/// X25519 written again from RFC 7748 §5: the Montgomery ladder over big integers.
fn rfc7748(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let p = p();
    let (mut scalar, mut point) = (*k, *u);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    point[31] &= 127; // bit 255 is masked; a value of p and above is taken modulo p
    let kk = BigUint::from_bytes_le(&scalar);
    let x1 = BigUint::from_bytes_le(&point) % &p;
    let sub = |a: &BigUint, b: &BigUint| (a + &p - b) % &p;
    let (mut x2, mut z2, mut x3, mut z3) = (BigUint::from(1u8), BigUint::from(0u8), x1.clone(), BigUint::from(1u8));
    let mut swap = false;
    for t in (0..255).rev() {
        let bit = kk.bit(t);
        if swap ^ bit {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;
        let (a, b, c, d) = ((&x2 + &z2) % &p, sub(&x2, &z2), (&x3 + &z3) % &p, sub(&x3, &z3));
        let (aa, bb, da, cb) = (&a * &a % &p, &b * &b % &p, &d * &a % &p, &c * &b % &p);
        let e = sub(&aa, &bb);
        let (sum, diff) = ((&da + &cb) % &p, sub(&da, &cb));
        x3 = &sum * &sum % &p;
        z3 = &x1 * (&diff * &diff % &p) % &p;
        x2 = &aa * &bb % &p;
        z2 = &e * ((&aa + BigUint::from(121665u32) * &e) % &p) % &p;
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    let out = x2 * z2.modpow(&(&p - BigUint::from(2u8)), &p) % &p;
    let mut bytes = out.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

fn unhex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// The seven encodings of a point of low order (docs/SPEC-NOTES.md §4).
fn low_order() -> Vec<[u8; 32]> {
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]
    .iter()
    .map(|s| unhex32(s))
    .collect()
}

fn top_bit(mut u: [u8; 32]) -> [u8; 32] {
    u[31] |= 0x80;
    u
}

fn le32(x: &BigUint) -> [u8; 32] {
    let mut b = x.to_bytes_le();
    b.resize(32, 0);
    b.try_into().unwrap()
}

/// Every encoding a sender or an address may hold that is not an ordinary key.
fn odd_encodings() -> Vec<[u8; 32]> {
    let mut odd = low_order();
    odd.extend(low_order().into_iter().map(top_bit));
    for k in 2u32..=18 {
        let second = le32(&(p() + BigUint::from(k))); // p + k: the second encoding of k
        odd.extend([second, top_bit(second)]);
    }
    for u in [BigUint::from(2u8), BigUint::from(9u8), p() - BigUint::from(2u8), (BigUint::from(1u8) << 255) - BigUint::from(1u8)] {
        odd.extend([le32(&u), top_bit(le32(&u))]);
    }
    odd.push([0xff; 32]);
    odd
}

/// Property 3. The model's X25519 (x25519-dalek) is the function of the RFC on every encoding: bit
/// 255 ignored, a value of p and above taken modulo p, zeros for the fourteen encodings of a point
/// of low order and for no other.
#[test]
fn audit_sealing_x25519_is_rfc7748_on_every_encoding() {
    let rfc = rfc7748(
        &unhex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        &unhex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    );
    assert_eq!(hex::encode(rfc), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "RFC 7748 §5.2");
    let mut rng = StdRng::seed_from_u64(1);
    let mut cases: Vec<([u8; 32], [u8; 32])> = odd_encodings().into_iter().map(|u| ([7u8; 32], u)).collect();
    for _ in 0..200 {
        let (mut k, mut u) = ([0u8; 32], [0u8; 32]);
        rng.fill_bytes(&mut k);
        rng.fill_bytes(&mut u);
        cases.push((k, u));
    }
    let low: Vec<[u8; 32]> = low_order();
    let mut zeros = 0;
    for (k, u) in cases {
        let want = rfc7748(&k, &u);
        assert_eq!(x25519_dalek::x25519(k, u), want, "u = {}", hex::encode(u));
        let mut masked = u;
        masked[31] &= 0x7f;
        assert_eq!(want == [0u8; 32], low.contains(&masked), "u = {}", hex::encode(u));
        zeros += (want == [0u8; 32]) as usize;
    }
    assert_eq!(zeros, 14);
}

fn wallet(byte: u8) -> notes::WalletKeys {
    notes::wallet_keys(&[byte; 32]).expect("keys")
}

/// Properties 5, 6 and 9. No output makes the model's scan panic or find a note that is not there:
/// an ephemeral key of low order, every other odd encoding, random outputs, and each bit of a real
/// output flipped.
#[test]
fn audit_sealing_no_output_misleads_the_scan() {
    let me = wallet(1);
    let (good, _, _) = notes::seal(&me.address, b"GENE", 700, &[9u8; 32]).unwrap();
    assert_eq!(notes::scan(&me.ivk, &me.address, &good).unwrap().v, 700);
    for u in odd_encodings() {
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { pk_eph: u, ..good }), None, "pk_eph {}", hex::encode(u));
    }
    let mut rng = StdRng::seed_from_u64(2);
    for _ in 0..2_000 {
        let (mut leaf, mut pk_eph, mut ct) = ([0u8; 32], [0u8; 32], [0u8; 28]);
        rng.fill_bytes(&mut leaf);
        rng.fill_bytes(&mut pk_eph);
        rng.fill_bytes(&mut ct);
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { leaf: Fr::from_le_bytes_mod_order(&leaf), pk_eph, ct }), None);
    }
    for bit in 0..256 {
        let mut pk_eph = good.pk_eph;
        pk_eph[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { pk_eph, ..good }), None, "pk_eph bit {bit}");
    }
    for bit in 0..224 {
        let mut ct = good.ct;
        ct[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { ct, ..good }), None, "ct bit {bit}");
    }
    let leaf = notes::fr_le(&good.leaf);
    for bit in 0..256 {
        let mut moved = leaf;
        moved[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { leaf: Fr::from_le_bytes_mod_order(&moved), ..good }), None, "leaf bit {bit}");
    }
    // the same ephemeral key, another amount: the 28 bytes of one do not open under the leaf of the other
    let (other, _, _) = notes::seal(&me.address, b"GENE", 701, &[9u8; 32]).unwrap();
    assert_eq!(other.pk_eph, good.pk_eph);
    assert_ne!(other.leaf, good.leaf);
    assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { ct: other.ct, ..good }), None);
    // and nobody else opens it
    let stranger = wallet(2);
    assert_eq!(notes::scan(&stranger.ivk, &stranger.address, &good), None);
    assert_eq!(notes::scan(&stranger.ivk, &me.address, &good), None);
}

/// Property 2. The model refuses an address whose IVK is any of the fourteen encodings of a point
/// of low order, and sealing to such keys is refused too, for a caller that skipped the address.
#[test]
fn audit_sealing_a_low_order_ivk_is_refused() {
    let me = wallet(3);
    let ok = notes::encode_address("tsh20", &me.address);
    assert_eq!(notes::decode_address("tsh20", &ok).unwrap(), me.address);
    assert!(notes::decode_address("sh20", &ok).is_err(), "another network");
    for u in low_order().into_iter().flat_map(|u| [u, top_bit(u)]) {
        let address = notes::Address { ivk_pub: u, ..me.address };
        assert!(notes::decode_address("tsh20", &notes::encode_address("tsh20", &address)).is_err(), "IVK {}", hex::encode(u));
        assert!(notes::seal(&address, b"GENE", 1, &[9u8; 32]).is_err(), "IVK {}", hex::encode(u));
    }
}

/// Finding sealing-4, fixed, in the model: the network is in the derivation of a wallet's keys.
/// One seed gives one master secret on mainnet and another on the test networks, and with them
/// other keys, another address payload and another sequence of public openings: nothing written on
/// a test chain is found again on mainnet.
#[test]
fn audit_sealing_the_network_is_in_every_key() {
    let seed = [7u8; 64];
    let (main, test) = (notes::master_secret(&seed, notes::HRP_MAINNET).unwrap(), notes::master_secret(&seed, notes::HRP_TEST).unwrap());
    assert_ne!(main, test, "the same master secret on both networks");
    let (w_main, w_test) = (notes::wallet_keys(&main).unwrap(), notes::wallet_keys(&test).unwrap());
    assert_ne!(w_main.ivk, w_test.ivk);
    assert_ne!(w_main.address.ivk_pub, w_test.address.ivk_pub);
    assert_ne!(w_main.address.a, w_test.address.a);
    assert_ne!(w_main.address.n, w_test.address.n);
    assert_ne!((&w_main.ask, &w_main.nsk), (&w_test.ask, &w_test.nsk));
    for i in 0..4 {
        let opening = |w: &notes::WalletKeys| notes::public_opening(&w.ivk, &w.address, i).unwrap().0;
        assert_ne!(opening(&w_main), opening(&w_test), "public opening {i}");
    }
    // an address is read on its own network only
    let address = notes::encode_address(notes::HRP_MAINNET, &w_main.address);
    assert_eq!(notes::decode_address(notes::HRP_MAINNET, &address).unwrap(), w_main.address);
    assert!(notes::decode_address(notes::HRP_TEST, &address).is_err());
    // the derivation is HMAC-SHA512("sh20/v0/seed", seed ‖ prefix), and takes nothing else for a network or a seed
    assert_eq!((notes::HRP_MAINNET, notes::HRP_TEST), ("sh20", "tsh20"));
    for other in ["", "bc", "SH20", "sh20 ", "signet"] {
        assert!(notes::master_secret(&seed, other).is_err(), "{other:?} taken for a network");
    }
    assert!(notes::master_secret(&seed[..63], notes::HRP_TEST).is_err());
    assert!(notes::master_secret(&[seed.as_slice(), b"t"].concat(), notes::HRP_MAINNET).is_err(), "a seed that runs into the prefix");
}

/// Finding sealing-2, in the model: the five values that Firefox refuses as an ephemeral key are
/// ordinary points for x25519-dalek, as for RFC 7748, OpenSSL and Chrome. The scan of an output
/// that carries one answers "not for this wallet", with no error.
#[test]
fn audit_sealing_the_five_values_firefox_refuses_are_ordinary_points() {
    let me = wallet(5);
    let (good, _, _) = notes::seal(&me.address, b"GENE", 1, &[9u8; 32]).unwrap();
    for u in [
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let u = unhex32(u);
        let z = x25519_dalek::x25519(me.ivk, u);
        assert_ne!(z, [0u8; 32], "{}", hex::encode(u));
        assert_eq!(z, rfc7748(&me.ivk, &u));
        assert_eq!(notes::scan(&me.ivk, &me.address, &Sealed { pk_eph: u, ..good }), None);
    }
}

/// Finding sealing-6, fixed, in the model: an address has one encoding of IVK. Written with bit
/// 255 set, or with p added, the same key is refused where an address is read, and a note is not
/// sealed to an address built by hand with such bytes.
#[test]
fn audit_sealing_a_second_encoding_of_ivk_is_refused() {
    let me = wallet(6);
    assert!(notes::is_canonical_u(&me.address.ivk_pub));
    assert_eq!(notes::decode_address("tsh20", &notes::encode_address("tsh20", &me.address)).unwrap(), me.address);
    let twin = notes::Address { ivk_pub: top_bit(me.address.ivk_pub), ..me.address };
    assert_eq!(x25519_dalek::x25519([7; 32], twin.ivk_pub), x25519_dalek::x25519([7; 32], me.address.ivk_pub), "one key for X25519");
    assert!(!notes::is_canonical_u(&twin.ivk_pub));
    assert!(notes::decode_address("tsh20", &notes::encode_address("tsh20", &twin)).is_err(), "the second encoding is read as an address");
    assert!(notes::seal(&twin, b"GENE", 700, &[9u8; 32]).is_err());
    // every writing of a key that is not its first: p + k for k < 19, each of them again with bit 255
    for k in 0u32..19 {
        let second = le32(&(p() + BigUint::from(k)));
        for u in [second, top_bit(second)] {
            assert!(!notes::is_canonical_u(&u), "p + {k}");
            assert!(notes::decode_address("tsh20", &notes::encode_address("tsh20", &notes::Address { ivk_pub: u, ..me.address })).is_err(), "p + {k}");
        }
    }
    // and the largest value that is one: p − 1 is read as a key's bytes (it is of low order, and refused for that)
    assert!(notes::is_canonical_u(&le32(&(p() - BigUint::from(1u8)))));
    assert!(notes::is_canonical_u(&le32(&(p() - BigUint::from(20u8)))));
}
