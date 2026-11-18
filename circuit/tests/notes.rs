//! The wallet model of docs/SPEC-NOTES.md: keys, addresses, sealing, scanning, public notes.
//! The vectors it writes are checked byte for byte by circuit/js with Node's own cryptography.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use num_bigint::BigUint;
use sh20_circuit::model::{self, InputNote, OutputNote, Tree};
use sh20_circuit::notes::{self, Sealed};
use sh20_circuit::{spend, wire};

fn wallet(tag: u8) -> notes::WalletKeys {
    notes::wallet_keys(&[tag; 32]).unwrap()
}
fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn x25519_is_rfc_7748() {
    // section 6.1
    let a = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert_eq!(x25519_dalek::x25519(a, b_pub), hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
}

#[test]
fn bech32m_is_bip_350() {
    for s in ["A1LQFN3A", "a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"] {
        assert!(notes::bech32m_decode(s).is_ok(), "{s}");
    }
    // a bech32 (not bech32m) checksum, a bad character, mixed case, no separator, an empty hrp, a short checksum
    for s in ["A12UEL5L", "a1b2qfn3a", "A1lqfn3a", "qyrz8wqd2c9m", "1p2gdwpf", "a1qfn3a"] {
        assert!(notes::bech32m_decode(s).is_err(), "{s}");
    }
    let data = hex::decode("00112233445566778899aabbccddeeff0102").unwrap();
    assert_eq!(notes::bech32m_decode(&notes::bech32m_encode("sh20", &data)).unwrap(), ("sh20".to_string(), data));
}

#[test]
fn points_pack_one_way_only() {
    let p = model::mul_b8(&BigUint::from(12345u32));
    let minus = [-p[0], p[1]];
    for q in [p, minus, model::base8()] {
        assert_eq!(notes::unpack_point(&notes::pack_point(&q)), Some(q));
        assert!(notes::is_key_point(&q));
    }
    assert_ne!(notes::pack_point(&p), notes::pack_point(&minus));
    // the identity and the point of order 2 decode, and are not keys
    for q in [model::identity(), [Fr::zero(), -Fr::one()]] {
        assert_eq!(notes::unpack_point(&notes::pack_point(&q)), Some(q));
        assert!(!notes::is_key_point(&q));
    }
    // a point outside the prime-order subgroup
    let shifted = model::add(&p, &[Fr::zero(), -Fr::one()]);
    assert!(model::on_curve(&shifted) && !notes::is_key_point(&shifted));
    // y not below r, and the second encoding of x = 0
    let mut big = [0xffu8; 32];
    big[31] = 0x7f;
    assert_eq!(notes::unpack_point(&big), None);
    let mut twice = notes::pack_point(&model::identity());
    twice[31] |= 0x80;
    assert_eq!(notes::unpack_point(&twice), None);
}

#[test]
fn addresses_round_trip_and_bad_ones_are_refused() {
    let w = wallet(1);
    let s = notes::encode_address("sh20", &w.address);
    assert_eq!(s.len(), 167);
    assert_eq!(notes::decode_address("sh20", &s), Ok(w.address));
    assert_eq!(notes::decode_address("sh20", &s.to_uppercase()), Ok(w.address));
    assert!(notes::decode_address("tsh20", &s).is_err());
    // every single-character change is caught (the checksum) or decodes to an address that is refused or different
    let mut changed = 0;
    for i in 5..s.len() {
        let mut b = s.clone().into_bytes();
        b[i] = if b[i] == b'q' { b'p' } else { b'q' };
        let t = String::from_utf8(b).unwrap();
        if t != s {
            assert!(notes::decode_address("sh20", &t).is_err(), "position {i}");
            changed += 1;
        }
    }
    assert!(changed > 150);
}

#[test]
fn seal_then_scan() {
    let (alice, bob) = (wallet(1), wallet(2));
    for (ticker, v) in [(b"GENE", 700u64), (b"ZZ99", 0), (b"0000", u64::MAX)] {
        let (out, secrets, npk) = notes::seal(&bob.address, ticker, v, &[9; 32]).unwrap();
        let found = notes::scan(&bob.ivk, &bob.address, &out).expect("bob opens it");
        assert_eq!((found.ticker, found.v, &found.secrets, found.npk), (*ticker, v, &secrets, npk));
        assert_eq!(notes::scan(&alice.ivk, &alice.address, &out), None);
        // the tweaked keys are the note's keys
        assert_eq!(notes::spend_keys(&bob, &found.secrets).unwrap().npk, npk);

        // anything altered is not a note
        for i in 0..28 {
            let mut ct = out.ct;
            ct[i] ^= 1;
            assert_eq!(notes::scan(&bob.ivk, &bob.address, &Sealed { ct, ..out }), None);
        }
        let mut pk_eph = out.pk_eph;
        pk_eph[0] ^= 1;
        assert_eq!(notes::scan(&bob.ivk, &bob.address, &Sealed { pk_eph, ..out }), None);
        assert_eq!(notes::scan(&bob.ivk, &bob.address, &Sealed { leaf: out.leaf + Fr::one(), ..out }), None);
        assert_eq!(notes::scan(&bob.ivk, &bob.address, &Sealed { pk_eph: [0; 32], ..out }), None);
        // bob's ivk with other spend keys in the address: the tag verifies, the leaf does not
        let mixed = notes::Address { a: alice.address.a, ..bob.address };
        assert_eq!(notes::scan(&bob.ivk, &mixed, &out), None);
    }
    assert!(notes::seal(&bob.address, b"gene", 1, &[9; 32]).is_err());
    assert!(notes::seal(&notes::Address { ivk_pub: [0; 32], ..bob.address }, b"GENE", 1, &[9; 32]).is_err());
}

#[test]
fn public_notes_have_rho_zero_and_a_viewing_key_finds_them() {
    let w = wallet(3);
    let (npk0, s0) = notes::public_opening(&w.ivk, &w.address, 0).unwrap();
    let (npk1, _) = notes::public_opening(&w.ivk, &w.address, 1).unwrap();
    assert!(s0.rho.is_zero());
    assert_ne!(npk0, npk1);
    assert_eq!(notes::spend_keys(&w, &s0).unwrap().npk, npk0);
    // derived from ivk alone (and the public A, N): no spend secret is involved
    let viewer = notes::WalletKeys { ask: BigUint::from(1u8), nsk: BigUint::from(1u8), ..w.clone() };
    assert_eq!(notes::public_opening(&viewer.ivk, &viewer.address, 0).unwrap().0, npk0);
}

/// A whole wallet flow satisfies the circuit: public notes in, sealed notes out, found by scanning,
/// spent again with the keys the scan gives.
#[test]
fn a_scanned_note_can_be_spent() {
    let (alice, bob) = (wallet(4), wallet(5));
    let ticker = b"GENE";
    let t = model::ticker_t(ticker).unwrap();
    let tf = Fr::from(t as u64);

    let minted: Vec<_> = (0..2).map(|i| notes::public_opening(&alice.ivk, &alice.address, i).unwrap()).collect();
    let mut leaves: Vec<Fr> = minted.iter().map(|(npk, _)| model::note_leaf(&tf, &Fr::from(1000u64), npk, &Fr::zero())).collect();
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: notes::spend_keys(&alice, &minted[i].1).unwrap(), v: 1000, rho: Fr::zero(), index: i as u64, path: tree.path(i) });
    let pay = [(&bob.address, 1500u64), (&bob.address, 400), (&alice.address, 100)];
    let sealed: Vec<_> = pay.iter().enumerate().map(|(k, (to, v))| notes::seal(to, ticker, *v, &[10 + k as u8; 32]).unwrap()).collect();
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: sealed[k].2, v: pay[k].1, rho: sealed[k].1.rho });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[i], i as u64));
    let body = wire::transfer_body(2, &nf, &std::array::from_fn(|k| sealed[k].0.into()));
    assert_eq!(body.len() + sh20_circuit::PROOF_BYTES, 830);
    let w = model::build_spend(t, tree.root, &inputs, &outputs, 0, 0, model::body_hash(&body));
    assert_eq!(spend::synthesize(&w).unsatisfied(), None);
    leaves.extend(sealed.iter().map(|o| o.0.leaf));

    // bob finds positions 2 and 3, and burns them
    let found: Vec<(usize, notes::Opened)> = (0..3).filter_map(|k| notes::scan(&bob.ivk, &bob.address, &sealed[k].0).map(|o| (2 + k, o))).collect();
    assert_eq!(found.iter().map(|(pos, o)| (*pos, o.v)).collect::<Vec<_>>(), vec![(2, 1500), (3, 400)]);
    let tree = Tree::new(&leaves);
    let inputs: [InputNote; 2] = std::array::from_fn(|i| InputNote { keys: notes::spend_keys(&bob, &found[i].1.secrets).unwrap(), v: found[i].1.v, rho: found[i].1.secrets.rho, index: found[i].0 as u64, path: tree.path(found[i].0) });
    let keep: Vec<_> = [1000u64, 0, 0].iter().enumerate().map(|(k, v)| (notes::seal(&bob.address, ticker, *v, &[20 + k as u8; 32]).unwrap(), *v)).collect();
    let outputs: [OutputNote; 3] = std::array::from_fn(|k| OutputNote { npk: keep[k].0 .2, v: keep[k].1, rho: keep[k].0 .1.rho });
    let nf: [Fr; 2] = std::array::from_fn(|i| model::nullifier(&inputs[i].keys.nk, &leaves[found[i].0], found[i].0 as u64));
    let body = wire::burn_body(ticker, 900, 3, &nf, &std::array::from_fn(|k| keep[k].0 .0.into()));
    assert_eq!(body.len() + sh20_circuit::PROOF_BYTES, 842);
    let w = model::build_spend(t, tree.root, &inputs, &outputs, 900, t, model::body_hash(&body));
    assert_eq!(spend::synthesize(&w).unsatisfied(), None);

    // with alice's keys instead, the same notes do not satisfy the circuit
    let mut stolen = w.clone();
    stolen.in_ak[0] = notes::spend_keys(&alice, &found[0].1.secrets).unwrap().ak;
    assert!(spend::synthesize(&stolen).unsatisfied().is_some());
}
