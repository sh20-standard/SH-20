//! Tests written by the audit of the part `verifier` (docs/audit/2026-11-24-verifier.md): the
//! proof's encoding, what the verifier binds, the key, the C interface, and the prover's blinding.
//! Each test holds a property of that report, or shows one of its findings as the code stands.

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use sh20_circuit::cs::Cs;
use sh20_circuit::plonk::{self, fr_from_bytes, fr_to_bytes, g1_from_bytes, g1_to_bytes, Proof, Srs, VerifyingKey};
use sh20_circuit::{ffi, fixture, load_key, prove, spend, verify, ProvingKey, SpendWitness, PROOF_BYTES, VK_DIGEST};
use std::sync::OnceLock;

fn repo(path: &str) -> String {
    format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))
}

fn keys() -> &'static ProvingKey {
    static K: OnceLock<ProvingKey> = OnceLock::new();
    K.get_or_init(|| load_key(&std::fs::read(repo("artifacts/spend.pk")).expect("artifacts/spend.pk")).unwrap())
}

/// One honest spend: its witness, its nine public inputs and its proof.
fn honest(seed: u64) -> (SpendWitness, [Fr; 9], [u8; PROOF_BYTES]) {
    let mut rng = StdRng::seed_from_u64(seed);
    let w = fixture::spend(&mut rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2);
    let proof = prove(keys(), &w, &mut rng).unwrap();
    let publics = w.publics();
    assert!(verify(&keys().vk, &publics, &proof));
    (w, publics, proof)
}

/// The same for all tests that only read it.
fn sample() -> &'static (SpendWitness, [Fr; 9], [u8; PROOF_BYTES]) {
    static S: OnceLock<(SpendWitness, [Fr; 9], [u8; PROOF_BYTES])> = OnceLock::new();
    S.get_or_init(|| honest(1))
}

fn q_le() -> [u8; 32] {
    Fq::MODULUS.to_bytes_le().try_into().unwrap()
}
fn r_le() -> [u8; 32] {
    Fr::MODULUS.to_bytes_le().try_into().unwrap()
}
/// a + b over 256 bits, little-endian; `None` on overflow.
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (carry == 0).then_some(out)
}

/// Property 2. A G1 point has one encoding: whatever decodes encodes back to the same 32 bytes,
/// `x + q` is refused where it fits, bit 255 chooses between P and −P, and nothing decodes to the
/// point at infinity.
#[test]
fn audit_verifier_a_point_has_one_encoding() {
    let mut rng = StdRng::seed_from_u64(2);
    let mut decoded = 0;
    for _ in 0..20_000 {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[31] &= 0xbf >> (rng.next_u32() % 3); // some below q, some with bit 254, some with bit 253 clear
        if let Some(p) = g1_from_bytes(&b) {
            decoded += 1;
            assert!(p.is_on_curve() && !p.infinity);
            assert_eq!(g1_to_bytes(&p).unwrap(), b, "a second encoding of one point");
            // the other value of bit 255 is the opposite point, and no third encoding exists
            let mut other = b;
            other[31] ^= 0x80;
            assert_eq!(g1_from_bytes(&other).unwrap(), (-p.into_group()).into_affine());
            // x + q, where it fits in the 255 bits left to x, is not read as x
            let (flag, mut x) = (b[31] & 0x80, b);
            x[31] &= 0x7f;
            if let Some(mut plus) = add_le(&x, &q_le()).filter(|s| s[31] & 0x80 == 0) {
                plus[31] |= flag;
                assert_eq!(g1_from_bytes(&plus), None, "x + q is accepted");
            }
        }
    }
    assert!(decoded > 5_000, "{decoded} of 20,000 decoded");
    assert_eq!(g1_to_bytes(&G1Affine::identity()), None);
    assert_eq!(g1_from_bytes(&q_le()), None);
    assert_eq!(g1_from_bytes(&[0xff; 32]), None);
    assert_eq!(g1_from_bytes(&[0u8; 31]), None);
    assert_eq!(g1_from_bytes(&[0u8; 33]), None);
    // x = 0 is no point of the curve (3 is not a square of the base field), so 32 zero bytes are no point
    assert_eq!(g1_from_bytes(&[0u8; 32]), None);
    let mut top = [0u8; 32];
    top[31] = 0x80;
    assert_eq!(g1_from_bytes(&top), None);
}

/// Property 3. A scalar is below r: r itself, r + 1 and 2^256 − 1 are refused, r − 1 is read.
#[test]
fn audit_verifier_a_scalar_is_below_r() {
    let r = r_le();
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(fr_from_bytes(&r), None);
    assert_eq!(fr_from_bytes(&add_le(&r, &one).unwrap()), None);
    assert_eq!(fr_from_bytes(&[0xff; 32]), None);
    assert_eq!(fr_from_bytes(&fr_to_bytes(&-Fr::one())), Some(-Fr::one()));
    assert_eq!(fr_from_bytes(&[0u8; 31]), None);

    // in a proof: every evaluation moved up by r is the same value modulo r, and is refused
    let (_, publics, proof) = sample();
    for i in 9..15 {
        let mut p = *proof;
        let slot: [u8; 32] = p[i * 32..(i + 1) * 32].try_into().unwrap();
        if let Some(plus) = add_le(&slot, &r) {
            p[i * 32..(i + 1) * 32].copy_from_slice(&plus);
            assert_eq!(Proof::from_bytes(&p), None, "evaluation {i} + r");
            assert!(!verify(&keys().vk, publics, &p));
        }
    }
}

/// Properties 1 and 5. A proof is 480 bytes, and every bit of them is bound: with any one of its
/// 3,840 bits flipped it does not verify.
#[test]
fn audit_verifier_every_bit_of_a_proof_is_bound() {
    let (_, publics, proof) = sample();
    let vk = &keys().vk;
    for len in [0, 1, 479, 481, 960] {
        let mut p = proof.to_vec();
        p.resize(len, 0);
        assert!(!verify(vk, publics, &p), "{len} bytes");
    }
    let mut reached_the_pairing = 0;
    for bit in 0..PROOF_BYTES * 8 {
        let mut p = *proof;
        p[bit / 8] ^= 1 << (bit % 8);
        if Proof::from_bytes(&p).is_some() {
            reached_the_pairing += 1;
        }
        assert!(!verify(vk, publics, &p), "bit {bit}");
    }
    // the pairing equation, not only the decoding, is what refuses most of them
    assert!(reached_the_pairing > 2_000, "{reached_the_pairing}");
}

/// Properties 4 and 5. The nine public inputs are bound, each one and their order, and their number.
#[test]
fn audit_verifier_every_public_input_is_bound() {
    let (_, publics, proof) = sample();
    let vk = &keys().vk;
    let p = Proof::from_bytes(proof).unwrap();
    for i in 0..9 {
        for delta in [Fr::one(), -Fr::one()] {
            let mut moved = *publics;
            moved[i] += delta;
            assert!(!verify(vk, &moved, proof), "input {i}");
        }
        for j in i + 1..9 {
            let mut swapped = *publics;
            swapped.swap(i, j);
            assert_eq!(verify(vk, &swapped, proof), publics[i] == publics[j], "inputs {i} and {j}");
        }
    }
    assert!(!plonk::verify(vk, &publics[..8], &p));
    assert!(!plonk::verify(vk, &[&publics[..], &[Fr::zero()]].concat(), &p));
    assert!(!plonk::verify(vk, &[], &p));
}

/// Property 5. No part of one proof serves in another: with any of its fifteen parts taken from a
/// second valid proof, neither statement verifies.
#[test]
fn audit_verifier_parts_of_two_proofs_do_not_mix() {
    let (_, publics, proof) = sample();
    let (_, publics2, proof2) = honest(7);
    let vk = &keys().vk;
    for part in 0..15 {
        let mut mixed = *proof;
        mixed[part * 32..(part + 1) * 32].copy_from_slice(&proof2[part * 32..(part + 1) * 32]);
        assert!(Proof::from_bytes(&mixed).is_some());
        assert!(!verify(vk, publics, &mixed), "part {part}");
        assert!(!verify(vk, &publics2, &mixed), "part {part}");
    }
    // nor in another place of the same proof
    for (i, j) in [(0, 1), (1, 2), (0, 3), (4, 5), (5, 6), (7, 8), (9, 10), (12, 13), (11, 14)] {
        let mut moved = *proof;
        let (a, b): ([u8; 32], [u8; 32]) = (proof[i * 32..(i + 1) * 32].try_into().unwrap(), proof[j * 32..(j + 1) * 32].try_into().unwrap());
        moved[i * 32..(i + 1) * 32].copy_from_slice(&b);
        moved[j * 32..(j + 1) * 32].copy_from_slice(&a);
        assert!(!verify(vk, publics, &moved), "parts {i} and {j} exchanged");
    }
}

/// Property 7. Points at infinity and points off the curve, placed in a proof in memory (the wire
/// encoding has neither), are refused before any arithmetic.
#[test]
fn audit_verifier_infinity_and_points_off_the_curve_are_refused() {
    let (_, publics, proof) = sample();
    let vk = &keys().vk;
    let good = Proof::from_bytes(proof).unwrap();
    let off = G1Affine::new_unchecked(Fq::from(1u64), Fq::from(1u64));
    assert!(!off.is_on_curve());
    for bad in [G1Affine::identity(), off] {
        for part in 0..9 {
            let mut p = good.clone();
            *[&mut p.a, &mut p.b, &mut p.c, &mut p.z, &mut p.t1, &mut p.t2, &mut p.t3, &mut p.wxi, &mut p.wxiw][part] = bad;
            assert!(!plonk::verify(vk, publics, &p), "part {part}");
        }
    }
}

/// A random point of the curve.
fn any_point(rng: &mut StdRng) -> [u8; 32] {
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[31] &= 0xbf;
        if g1_from_bytes(&b).is_some() {
            return b;
        }
    }
}

/// Properties 7 and 9. Nothing makes the verifier panic, and nothing but the proof verifies:
/// random bytes, and proofs made of random points of the curve and random scalars, which decode
/// and go through the whole equation.
#[test]
fn audit_verifier_no_proof_makes_it_panic() {
    let (_, publics, proof) = sample();
    let vk = &keys().vk;
    let mut rng = StdRng::seed_from_u64(3);
    for _ in 0..50_000 {
        let mut p = [0u8; PROOF_BYTES];
        rng.fill_bytes(&mut p);
        assert!(!verify(vk, publics, &p));
    }
    for round in 0..1_500 {
        let mut p = *proof;
        for part in 0..15 {
            // from one part replaced to all fifteen
            if rng.next_u32() % 15 <= round % 15 {
                let fresh = if part < 9 { any_point(&mut rng) } else { fr_to_bytes(&Fr::rand(&mut rng)) };
                p[part * 32..(part + 1) * 32].copy_from_slice(&fresh);
            }
        }
        assert!(Proof::from_bytes(&p).is_some());
        assert_eq!(verify(vk, publics, &p), p == *proof);
    }
    // edge scalars in every evaluation at once, and public inputs at the ends of the field
    for value in [Fr::zero(), Fr::one(), -Fr::one()] {
        let mut p = *proof;
        for part in 9..15 {
            p[part * 32..(part + 1) * 32].copy_from_slice(&fr_to_bytes(&value));
        }
        assert!(!verify(vk, publics, &p));
        assert!(!verify(vk, &[value; 9], proof));
        assert!(!verify(vk, &[value; 9], &p));
    }
}

/// Property 8. Every bit of the 712-byte key is pinned: a key with one bit flipped either does
/// not parse or has another digest, and none of those that parse accepts the proof.
#[test]
fn audit_verifier_every_bit_of_the_key_is_pinned() {
    let (_, publics, proof) = sample();
    let key = std::fs::read(repo("artifacts/spend.vk")).unwrap();
    assert_eq!(key.len(), 712);
    assert_eq!(hex::encode(VerifyingKey::from_bytes(&key).unwrap().digest()), VK_DIGEST);
    let mut parsed = 0;
    for bit in 0..key.len() * 8 {
        let mut k = key.clone();
        k[bit / 8] ^= 1 << (bit % 8);
        if let Ok(vk) = VerifyingKey::from_bytes(&k) {
            parsed += 1;
            assert_eq!(vk.to_bytes(), k, "bit {bit}: the key is not read back as written");
            assert_ne!(hex::encode(vk.digest()), VK_DIGEST, "bit {bit}");
            assert!(!verify(&vk, publics, proof), "bit {bit}: another key accepts the proof");
        }
    }
    // the sizes, the two coset shifts: fields that are not points still parse when they change
    assert!(parsed > 100, "{parsed}");
    assert!(VerifyingKey::from_bytes(&key[..711]).is_err());
    assert!(VerifyingKey::from_bytes(&[key.clone(), vec![0]].concat()).is_err());
}

fn publics_le(publics: &[Fr]) -> Vec<u8> {
    publics.iter().flat_map(fr_to_bytes).collect()
}

/// Properties 4 and 9, at the C interface: a key of another length, a public input that is not
/// below r, a proof of another length are refused with the answers the header documents.
#[test]
fn audit_verifier_the_c_interface_refuses_what_it_cannot_read() {
    let (_, publics, proof) = sample();
    let key = keys().vk.to_bytes();
    let inputs = publics_le(publics);
    let call = |key: &[u8], inputs: &[u8], proof: &[u8]| unsafe { ffi::sh20_verify(key.as_ptr(), key.len(), inputs.as_ptr(), proof.as_ptr(), proof.len()) };
    assert_eq!(call(&key, &inputs, proof), 1);
    assert_eq!(call(&key[..711], &inputs, proof), -1);
    assert_eq!(call(&[0u8; 712], &inputs, proof), -1);
    for i in 0..9 {
        // the same value modulo r, written as value + r
        let slot: [u8; 32] = inputs[i * 32..(i + 1) * 32].try_into().unwrap();
        if let Some(plus) = add_le(&slot, &r_le()) {
            let mut moved = inputs.clone();
            moved[i * 32..(i + 1) * 32].copy_from_slice(&plus);
            assert_eq!(call(&key, &moved, proof), -1, "input {i} + r");
        }
    }
    assert_eq!(call(&key, &inputs, &proof[..479]), 0);
    assert_eq!(call(&key, &inputs, &[&proof[..], &[0u8][..]].concat()), 0);
    assert_eq!(call(&key, &inputs, &[0u8; PROOF_BYTES]), 0);
}

/// A circuit with nine public inputs and nothing else, on the first powers of the same SRS: anyone
/// can make its key, and prove any nine values under it.
fn key_of_no_rule(publics: &[Fr; 9]) -> (ProvingKey, Vec<Fr>) {
    let mut cs = Cs::new();
    for x in publics {
        cs.public_input(*x);
    }
    let pinned = keys();
    let count = plonk::keys::rows_for(cs.n_gates()) + plonk::keys::SRS_EXTRA;
    let srs = Srs { g1: pinned.srs_g1[..count].to_vec(), g2_tau: pinned.vk.x2 };
    (plonk::setup(&cs, &srs).unwrap(), cs.values().to_vec())
}

/// Finding verifier-1, the half in Rust. `sh20_verify` verifies under whatever key the host hands
/// it: with the key of a circuit that has no rule, it answers 1 for nine public inputs of a spend
/// that nobody proved. The pinned digest is checked by each host, outside this function.
#[test]
fn audit_verifier_the_c_interface_verifies_under_any_key() {
    // a "spend" that takes 2^64 − 1 units out of the pool, from notes that do not exist
    let publics: [Fr; 9] = std::array::from_fn(|i| if i == 7 { Fr::from(u64::MAX) } else { Fr::from(i as u64 + 1) });
    let (other, values) = key_of_no_rule(&publics);
    let proof = plonk::prove(&other, &values, &mut StdRng::seed_from_u64(5)).unwrap().to_bytes().unwrap();
    let key = other.vk.to_bytes();
    assert_ne!(hex::encode(other.vk.digest()), VK_DIGEST);
    assert!(!verify(&keys().vk, &publics, &proof), "the pinned key refuses it");
    let inputs = publics_le(&publics);
    let answer = unsafe { ffi::sh20_verify(key.as_ptr(), key.len(), inputs.as_ptr(), proof.as_ptr(), proof.len()) };
    assert_eq!(answer, 1, "the interface has no key of its own to hold the proof to");

    // the fixture the JavaScript half reads (indexer/test/audit-verifier.test.js) is such a triple
    let doc = std::fs::read_to_string(repo("tests/fixtures/audit/no-rule.json")).unwrap();
    let field = |name: &str| hex::decode(doc.split_once(&format!("\"{name}\":\"")).unwrap().1.split_once('"').unwrap().0).unwrap();
    let (key, inputs, proof) = (field("vk"), field("publics"), field("proof"));
    assert_eq!((key.len(), inputs.len(), proof.len()), (712, 288, 480));
    assert_ne!(hex::encode(VerifyingKey::from_bytes(&key).unwrap().digest()), VK_DIGEST);
    assert_eq!(unsafe { ffi::sh20_verify(key.as_ptr(), key.len(), inputs.as_ptr(), proof.as_ptr(), proof.len()) }, 1);
    let pinned = keys().vk.to_bytes();
    assert_eq!(unsafe { ffi::sh20_verify(pinned.as_ptr(), pinned.len(), inputs.as_ptr(), proof.as_ptr(), proof.len()) }, 0);
}

/// Writes the fixture of the test above. Run once:
/// `cargo test --release --test audit_verifier -- --ignored audit_verifier_write_the_fixture`.
#[test]
#[ignore]
fn audit_verifier_write_the_fixture() {
    let publics: [Fr; 9] = std::array::from_fn(|i| if i == 7 { Fr::from(u64::MAX) } else { Fr::from(i as u64 + 1) });
    let (other, values) = key_of_no_rule(&publics);
    let proof = plonk::prove(&other, &values, &mut StdRng::seed_from_u64(5)).unwrap().to_bytes().unwrap();
    let doc = format!(
        "{{\"note\":\"A circuit with nine public inputs and no rule, on the first 22 powers of the same SRS: its key, nine public inputs nobody proved a spend for, and a proof under that key. Written by circuit/tests/audit_verifier.rs.\",\"vk\":\"{}\",\"publics\":\"{}\",\"proof\":\"{}\"}}\n",
        hex::encode(other.vk.to_bytes()),
        hex::encode(publics_le(&publics)),
        hex::encode(proof)
    );
    std::fs::create_dir_all(repo("tests/fixtures/audit")).unwrap();
    std::fs::write(repo("tests/fixtures/audit/no-rule.json"), doc).unwrap();
}

/// The wire polynomial of column `j` before blinding, as coefficients.
fn wire_polynomial(pk: &ProvingKey, values: &[Fr], j: usize) -> Vec<Fr> {
    let column: Vec<Fr> = pk.wires[j].iter().map(|&v| values[v as usize]).collect();
    plonk::keys::domain(pk.n).ifft(&column)
}

/// What `sh20_prove` gives for a witness and a seed, as a proof.
fn through_the_c_interface(handle: *const ProvingKey, w: &SpendWitness, seed: [u8; 32]) -> Proof {
    let witness = w.to_bytes();
    let mut out = [0u8; PROOF_BYTES];
    assert_eq!(unsafe { ffi::sh20_prove(handle, witness.as_ptr(), seed.as_ptr(), out.as_mut_ptr()) }, 1);
    assert!(verify(&keys().vk, &w.publics(), &out));
    Proof::from_bytes(&out).unwrap()
}

/// Property 11, and finding verifier-3, fixed. The prover draws its eleven blinding scalars from
/// the generator it is handed and from nothing else: one stream for two witnesses gives the same
/// scalars, and the difference of the two wire commitments is then the commitment of the
/// difference of the unblinded polynomials, with no randomness left in it. That is what
/// `sh20_prove` did with a seed used twice. It now seeds the generator with
/// SHA-256("sh20/v0/blinding" ‖ seed ‖ witness): one seed and two witnesses give unrelated scalars.
#[test]
fn audit_verifier_a_repeated_seed_no_longer_unblinds_the_difference_of_two_proofs() {
    let pk = keys();
    let mut rng = StdRng::seed_from_u64(11);
    let w1 = fixture::spend(&mut rng, fixture::gene(), [600, 400], [700, 250, 50], 0, 0, 2);
    let w2 = fixture::spend(&mut rng, fixture::gene(), [600, 400], [100, 0, 0], 900, fixture::gene(), 2);
    let (v1, v2) = (spend::synthesize(&w1), spend::synthesize(&w2));
    let (v1, v2) = (v1.values(), v2.values());
    let seed = [42u8; 32];
    let unblinded_difference = |j: usize| {
        let (a, b) = (wire_polynomial(pk, v1, j), wire_polynomial(pk, v2, j));
        let diff: Vec<Fr> = a.iter().zip(&b).map(|(x, y)| *x - *y).collect();
        plonk::keys::commit(&pk.srs_g1, &diff)
    };
    let sub = |x: &G1Affine, y: &G1Affine| (x.into_group() - y.into_group()).into_affine();

    // the prover itself, given one stream twice: the blinding cancels. This is why no host and no
    // interface may hand it one.
    let with = |seed: [u8; 32], values: &[Fr]| plonk::prove(pk, values, &mut StdRng::from_seed(seed)).unwrap();
    let (p1, p2) = (with(seed, v1), with(seed, v2));
    for (j, (c1, c2)) in [(&p1.a, &p2.a), (&p1.b, &p2.b), (&p1.c, &p2.c)].into_iter().enumerate() {
        assert_eq!(sub(c1, c2), unblinded_difference(j), "wire {j}");
    }

    // the interface the hosts call, given one seed twice: it does not
    let file = std::fs::read(repo("artifacts/spend.pk")).unwrap();
    let handle = unsafe { ffi::sh20_load_key(file.as_ptr(), file.len()) };
    assert!(!handle.is_null());
    let (q1, q2) = (through_the_c_interface(handle, &w1, seed), through_the_c_interface(handle, &w2, seed));
    for (j, (c1, c2)) in [(&q1.a, &q2.a), (&q1.b, &q2.b), (&q1.c, &q2.c)].into_iter().enumerate() {
        assert_ne!(sub(c1, c2), unblinded_difference(j), "wire {j}: one seed gave two witnesses the same blinding");
    }
    // the generator is seeded with SHA-256("sh20/v0/blinding" ‖ seed ‖ witness), and with nothing else
    for (w, values, q) in [(&w1, v1, &q1), (&w2, v2, &q2)] {
        let hashed: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest([&b"sh20/v0/blinding"[..], &seed, &w.to_bytes()].concat()).into();
        assert_eq!(ffi::blinding_seed(&seed, &w.to_bytes()), hashed);
        assert_eq!(&with(hashed, values), q);
    }
    assert_ne!(ffi::blinding_seed(&seed, &w1.to_bytes()), seed, "the host's seed is not the generator's");
    unsafe { ffi::sh20_key_free(handle) };
}

/// Property 11, through the C interface the hosts call: a proof is a function of the witness and
/// of the host's 32-byte seed. One seed and one witness give one proof; another seed, another
/// proof in every part. So a host still owes each proof a fresh seed.
#[test]
fn audit_verifier_the_c_interface_draws_its_randomness_from_the_seed_and_the_witness() {
    let (w, _, _) = sample();
    let file = std::fs::read(repo("artifacts/spend.pk")).unwrap();
    let handle = unsafe { ffi::sh20_load_key(file.as_ptr(), file.len()) };
    assert!(!handle.is_null());
    let run = |seed: [u8; 32]| through_the_c_interface(handle, w, seed).to_bytes().unwrap();
    let (first, again, other) = (run([9u8; 32]), run([9u8; 32]), run([10u8; 32]));
    assert_eq!(first, again);
    for part in 0..15 {
        // s1 and s2 are evaluations of the key's polynomials at ξ, which moves with the proof
        assert_ne!(first[part * 32..(part + 1) * 32], other[part * 32..(part + 1) * 32], "part {part} does not depend on the seed");
    }
    // a witness that is not one: refused, nothing written
    let mut bad = w.to_bytes();
    bad[31] = 0xff; // the root, not below r
    let mut out = [0u8; PROOF_BYTES];
    assert_eq!(unsafe { ffi::sh20_prove(handle, bad.as_ptr(), [9u8; 32].as_ptr(), out.as_mut_ptr()) }, 0);
    assert_eq!(out, [0u8; PROOF_BYTES]);
    unsafe { ffi::sh20_key_free(handle) };
    // a file that is not the pinned key gives no handle
    let mut other = file.clone();
    other[100] ^= 1;
    assert!(unsafe { ffi::sh20_load_key(other.as_ptr(), other.len()) }.is_null());
}

/// Property 8, behind the digest: the permutation the key commits to is the circuit's copy
/// constraints and nothing else. Read back from the key's own evaluations of σ, it is a bijection
/// of the 3n slots, it never leaves a variable, and the slots of each variable are one cycle: a
/// prover cannot give one variable two values in two gates. (`shipped_key_is_reproducible` ties
/// these evaluations to the commitments S1, S2, S3 of the pinned key.)
#[test]
fn audit_verifier_the_key_ties_every_use_of_a_variable() {
    use ark_ff::Field;
    let pk = keys();
    let n = pk.n;
    let index: std::collections::HashMap<Fr, usize> = plonk::keys::domain(n).elements().enumerate().map(|(i, w)| (w, i)).collect();
    let unshift = [Fr::one(), pk.vk.k1.inverse().unwrap(), pk.vk.k2.inverse().unwrap()];
    let slot_of = |x: Fr| -> usize {
        let hits: Vec<usize> = (0..3).filter_map(|j| index.get(&(x * unshift[j])).map(|i| j * n + i)).collect();
        assert_eq!(hits.len(), 1, "a value of σ that is not one slot");
        hits[0]
    };
    let variable = |slot: usize| pk.wires[slot / n][slot % n];
    let sigma: Vec<usize> = (0..3 * n).map(|s| slot_of(pk.sigma_h[s / n][s % n])).collect();

    let mut uses = vec![0usize; pk.n_vars];
    for s in 0..3 * n {
        uses[variable(s) as usize] += 1;
        assert_eq!(variable(sigma[s]), variable(s), "σ leaves the variable at slot {s}");
    }
    let mut seen = vec![false; 3 * n];
    let mut cycles = 0;
    for start in 0..3 * n {
        if seen[start] {
            continue;
        }
        let (mut s, mut len) = (start, 0);
        while !seen[s] {
            seen[s] = true;
            len += 1;
            s = sigma[s];
        }
        assert_eq!(s, start, "σ is not a bijection");
        assert_eq!(len, uses[variable(start) as usize], "the slots of variable {} are not one cycle", variable(start));
        cycles += 1;
    }
    assert_eq!(cycles, uses.iter().filter(|u| **u > 0).count());
    // every variable of the circuit is on a wire, so each one is in the argument
    assert!(uses.iter().all(|u| *u > 0), "a variable that no gate uses");
}

/// Property 4, in the key: rows 0 to 8 are the public inputs and nothing else (a − x_i = 0 through
/// PI), no later row reads PI, and the nine values the circuit puts there are the nine of
/// SPEC-WIRE §4 in their order.
#[test]
fn audit_verifier_the_first_nine_rows_are_the_public_inputs() {
    let pk = keys();
    let dom = plonk::keys::domain(pk.n);
    let on_rows: Vec<Vec<Fr>> = pk.q.iter().map(|q| dom.fft(q)).collect(); // ql, qr, qo, qm, qc
    for row in 0..9 {
        let q: Vec<Fr> = on_rows.iter().map(|column| column[row]).collect();
        assert_eq!(q, [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()], "row {row}");
    }
    assert_eq!(pk.vk.n_public, 9);
    let (w, publics, _) = sample();
    let cs = spend::synthesize(w);
    assert_eq!(cs.public_values(), publics.to_vec());
    // the wire a of rows 0..9 holds nine different variables, the public ones
    let first: std::collections::BTreeSet<u32> = pk.wires[0][..9].iter().copied().collect();
    assert_eq!(first.len(), 9);
    for (row, x) in publics.iter().enumerate() {
        assert_eq!(cs.values()[pk.wires[0][row] as usize], *x, "row {row}");
    }
    assert_eq!(*publics, [w.root, w.nf[0], w.nf[1], w.out_leaf[0], w.out_leaf[1], w.out_leaf[2], w.body_hash, w.v_pub, w.t_pub]);
}

/// Property 8 again: variable 0, which fills the wire slots a gate does not use and is bound to no
/// value, sits under a zero selector wherever the key has it. Its value changes no gate.
#[test]
fn audit_verifier_variable_zero_is_under_no_selector() {
    let pk = keys();
    let dom = plonk::keys::domain(pk.n);
    let [ql, qr, qo, qm, _qc]: [Vec<Fr>; 5] = std::array::from_fn(|j| dom.fft(&pk.q[j]));
    let mut slots = 0;
    for row in 0..pk.n {
        let [a, b, c] = [pk.wires[0][row], pk.wires[1][row], pk.wires[2][row]];
        if a == 0 {
            assert!(ql[row].is_zero() && qm[row].is_zero(), "row {row}: variable 0 on wire a under a selector");
        }
        if b == 0 {
            assert!(qr[row].is_zero() && qm[row].is_zero(), "row {row}: variable 0 on wire b under a selector");
        }
        if c == 0 {
            assert!(qo[row].is_zero(), "row {row}: variable 0 on wire c under a selector");
        }
        slots += [a, b, c].iter().filter(|v| **v == 0).count();
    }
    assert!(slots > 3 * (pk.n - 86_250), "{slots}");
}

// ── the verifier of the paper, written again by the second reader of this audit ──

mod paper {
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, FftField, Field, One, PrimeField, Zero};
    use sh20_circuit::plonk::{Proof, VerifyingKey};
    use sha3::{Digest, Keccak256};

    fn be<F: PrimeField>(x: &F) -> Vec<u8> {
        x.into_bigint().to_bytes_be()
    }
    fn pt(p: &G1Affine) -> Vec<u8> {
        [be(&p.x), be(&p.y)].concat()
    }
    fn keccak(items: &[Vec<u8>]) -> Fr {
        let mut h = Keccak256::new();
        for i in items {
            h.update(i);
        }
        Fr::from_be_bytes_mod_order(&h.finalize())
    }

    /// ePrint 2019/953 section 8.3, "Verifier algorithm", steps 4 to 12, one group element at a
    /// time, with the challenges of SPEC-WIRE §4 and each Lagrange evaluation taken from its
    /// definition, a product over the whole domain, instead of the closed form. It shares no code
    /// with the crate's verifier or transcript.
    pub fn verify(vk: &VerifyingKey, publics: &[Fr], p: &Proof) -> bool {
        let n = 1u64 << vk.power;
        let omega = Fr::get_root_of_unity(n).unwrap();
        let g = |x: &G1Affine| x.into_group();

        // 4. challenges
        let mut first = vec![pt(&vk.qm), pt(&vk.ql), pt(&vk.qr), pt(&vk.qo), pt(&vk.qc), pt(&vk.s1), pt(&vk.s2), pt(&vk.s3)];
        first.extend(publics.iter().map(be));
        first.extend([pt(&p.a), pt(&p.b), pt(&p.c)]);
        let beta = keccak(&first);
        let gamma = keccak(&[be(&beta)]);
        let alpha = keccak(&[be(&beta), be(&gamma), pt(&p.z)]);
        let xi = keccak(&[be(&alpha), pt(&p.t1), pt(&p.t2), pt(&p.t3)]);
        let v = keccak(&[be(&xi), be(&p.eval_a), be(&p.eval_b), be(&p.eval_c), be(&p.eval_s1), be(&p.eval_s2), be(&p.eval_zw)]);
        let u = keccak(&[pt(&p.wxi), pt(&p.wxiw)]);

        // 5. Z_H(ξ)
        let xin = xi.pow([n]);
        let zh = xin - Fr::one();

        // 6, 7. L_i(ξ) = Π_{j≠i} (ξ − ω^j) / (ω^i − ω^j), for row 0 and the rows of the public inputs
        let lagrange = |i: u64| -> Option<Fr> {
            let wi = omega.pow([i]);
            let (mut num, mut den, mut wj) = (Fr::one(), Fr::one(), Fr::one());
            for j in 0..n {
                if j != i {
                    num *= xi - wj;
                    den *= wi - wj;
                }
                wj *= omega;
            }
            Some(num * den.inverse()?)
        };
        let Some(l1) = lagrange(0) else { return false };
        let mut pi = Fr::zero();
        for (i, x) in publics.iter().enumerate() {
            let Some(l) = lagrange(i as u64) else { return false };
            pi -= *x * l;
        }

        // 8. r0
        let (a, b, c, s1, s2, zw) = (p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw);
        let r0 = pi - l1 * alpha.square() - alpha * (a + beta * s1 + gamma) * (b + beta * s2 + gamma) * (c + gamma) * zw;

        // 9. [D]
        let mut d = g(&vk.qm) * (a * b) + g(&vk.ql) * a + g(&vk.qr) * b + g(&vk.qo) * c + g(&vk.qc);
        d += g(&p.z) * ((a + beta * xi + gamma) * (b + beta * vk.k1 * xi + gamma) * (c + beta * vk.k2 * xi + gamma) * alpha + l1 * alpha.square() + u);
        d -= g(&vk.s3) * ((a + beta * s1 + gamma) * (b + beta * s2 + gamma) * alpha * beta * zw);
        d -= (g(&p.t1) + g(&p.t2) * xin + g(&p.t3) * xin.square()) * zh;

        // 10. [F]   11. [E]
        let f = d + g(&p.a) * v + g(&p.b) * v.pow([2]) + g(&p.c) * v.pow([3]) + g(&vk.s1) * v.pow([4]) + g(&vk.s2) * v.pow([5]);
        let e = G1Projective::generator() * (-r0 + v * a + v.pow([2]) * b + v.pow([3]) * c + v.pow([4]) * s1 + v.pow([5]) * s2 + u * zw);

        // 12. e([Wξ] + u·[Wξω], [x]₂) = e(ξ·[Wξ] + u·ξω·[Wξω] + [F] − [E], [1]₂)
        let lhs = g(&p.wxi) + g(&p.wxiw) * u;
        let rhs = g(&p.wxi) * xi + g(&p.wxiw) * (u * xi * omega) + f - e;
        Bn254::pairing(lhs.into_affine(), vk.x2) == Bn254::pairing(rhs.into_affine(), G2Affine::generator())
    }
}

/// Property 6. The crate's verifier and the paper's written again give one answer: on an honest
/// spend, on each public input moved, on each of the fifteen parts of the proof replaced by other
/// well-formed values, and on snarkjs' own proof and key.
#[test]
fn audit_verifier_the_equation_is_the_papers_written_again() {
    let (_, publics, bytes) = sample();
    let vk = &keys().vk;
    let proof = Proof::from_bytes(bytes).unwrap();
    assert!(paper::verify(vk, publics, &proof), "the paper's verifier refuses an honest spend");
    assert!(plonk::verify(vk, publics, &proof));
    for i in 0..9 {
        let mut moved = *publics;
        moved[i] += Fr::one();
        assert!(!paper::verify(vk, &moved, &proof) && !plonk::verify(vk, &moved, &proof), "public input {i}");
    }
    let parts = |p: &Proof| [p.a, p.b, p.c, p.z, p.t1, p.t2, p.t3, p.wxi, p.wxiw];
    let evals = |p: &Proof| [p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw];
    for i in 0..9 {
        let original = parts(&proof)[i];
        for other in [
            G1Affine::generator(),
            (-original.into_group()).into_affine(),
            (original.into_group() + G1Affine::generator()).into_affine(),
            parts(&proof)[(i + 1) % 9],
        ] {
            let mut bad = proof.clone();
            *[&mut bad.a, &mut bad.b, &mut bad.c, &mut bad.z, &mut bad.t1, &mut bad.t2, &mut bad.t3, &mut bad.wxi, &mut bad.wxiw][i] = other;
            assert_eq!(paper::verify(vk, publics, &bad), plonk::verify(vk, publics, &bad), "point {i}");
            assert!(!plonk::verify(vk, publics, &bad), "point {i}");
        }
    }
    for i in 0..6 {
        let original = evals(&proof)[i];
        for other in [Fr::zero(), Fr::one(), original + Fr::one(), -original, evals(&proof)[(i + 1) % 6]] {
            let mut bad = proof.clone();
            *[&mut bad.eval_a, &mut bad.eval_b, &mut bad.eval_c, &mut bad.eval_s1, &mut bad.eval_s2, &mut bad.eval_zw][i] = other;
            assert_eq!(paper::verify(vk, publics, &bad), plonk::verify(vk, publics, &bad), "evaluation {i}");
            assert!(!plonk::verify(vk, publics, &bad), "evaluation {i}");
        }
    }
    // snarkjs' own proof and key (one public input, a domain of 8 rows)
    let read = |name: &str| std::fs::read_to_string(repo(&format!("tests/fixtures/snarkjs/cubic.{name}.json"))).unwrap();
    let key = plonk::json::vk_from_json(&read("vk")).unwrap();
    let theirs = plonk::json::proof_from_json(&read("proof")).unwrap();
    let inputs = plonk::json::publics_from_json(&read("public")).unwrap();
    assert!(paper::verify(&key, &inputs, &theirs) && plonk::verify(&key, &inputs, &theirs));
    let other = [inputs[0] + Fr::one()];
    assert!(!paper::verify(&key, &other, &theirs) && !plonk::verify(&key, &other, &theirs));
}
