//! The gadgets one at a time, on the values where they could go wrong: points off the curve, the
//! ends of every range, keys of small order, and a decomposition no honest synthesis would write.

mod common;

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use common::Probe;
use num_bigint::BigUint;
use rand_core::OsRng;
use sh20_circuit::cs::{Cs, Var};
use sh20_circuit::model::{self, Pt};
use sh20_circuit::{fixture, gadgets};

fn point(cs: &mut Cs, p: &Pt) -> [Var; 2] {
    [cs.alloc(p[0]), cs.alloc(p[1])]
}

/// A point of the curve outside the prime subgroup: x from y, by the curve equation.
fn curve_point(seed: u64) -> Pt {
    let (a, d) = (Fr::from(model::BJJ_A), Fr::from(model::BJJ_D));
    let mut y = Fr::from(seed);
    loop {
        let y2 = y.square();
        if let Some(x) = ((Fr::one() - y2) * (a - d * y2).inverse().unwrap()).sqrt() {
            let p = [x, y];
            assert!(model::on_curve(&p));
            return p;
        }
        y += Fr::one();
    }
}

/// The points of order 1, 2, 4 and 8: l·P for points P of the whole curve.
fn small_order_points() -> Vec<Pt> {
    let mut found: Vec<Pt> = Vec::new();
    let mut seed = 2u64;
    while found.len() < 8 && seed < 400 {
        let t = model::mul(&curve_point(seed), model::l_big());
        if !found.contains(&t) {
            found.push(t);
        }
        seed += 1;
    }
    found
}

#[test]
fn on_curve_accepts_the_curve_and_nothing_else() {
    let check = |p: &Pt| {
        let mut cs = Cs::new();
        let v = point(&mut cs, p);
        gadgets::assert_on_curve(&mut cs, v);
        assert_eq!(cs.n_gates(), 4);
        cs.is_satisfied()
    };
    let keys = fixture::random_keys(&mut OsRng);
    let neg = |p: &Pt| [-p[0], p[1]];
    for p in [model::base8(), model::identity(), [Fr::zero(), -Fr::one()], keys.ak, neg(&keys.ak), curve_point(7)] {
        assert!(model::on_curve(&p) && check(&p));
    }
    let off = [
        [Fr::zero(), Fr::zero()],
        [Fr::one(), Fr::one()],
        [Fr::zero(), Fr::from(2u64)],
        [keys.ak[0] + Fr::one(), keys.ak[1]],
        [keys.ak[0], keys.ak[1] + Fr::one()],
        [keys.ak[1], keys.ak[0]],
        [keys.ak[0], -keys.ak[1] + Fr::one()],
    ];
    for p in off {
        assert!(!model::on_curve(&p) && !check(&p), "{p:?}");
    }
}

#[test]
fn ranges_end_where_they_say() {
    let two = |n: u64| Fr::from(2u64).pow([n]);
    let range = |x: Fr, n: usize| {
        let mut cs = Cs::new();
        let v = cs.alloc(x);
        gadgets::range(&mut cs, v, n);
        cs.is_satisfied()
    };
    assert!(range(Fr::zero(), 64) && range(two(64) - Fr::one(), 64));
    assert!(!range(two(64), 64) && !range(-Fr::one(), 64) && !range(two(200), 64));
    assert!(range(two(253) - Fr::one(), 253) && !range(two(253), 253));
    assert!(range(Fr::one(), 1) && !range(Fr::from(2u64), 1));

    let scalar = |x: Fr| {
        let mut cs = Cs::new();
        let v = cs.alloc(x);
        gadgets::scalar_bits(&mut cs, v);
        cs.is_satisfied()
    };
    let l = model::fr(model::l_big());
    assert!(scalar(Fr::zero()) && scalar(Fr::one()) && scalar(l - Fr::one()));
    assert!(!scalar(l) && !scalar(l + Fr::one()) && !scalar(two(251) - Fr::one()) && !scalar(two(251)) && !scalar(-Fr::one()));

    // the canonical bits are those of the integer below the modulus, for every field element
    let p = model::p_big();
    let p_hi = &p >> 128usize;
    let edge = |n: BigUint| model::fr(&n);
    for x in [Fr::zero(), Fr::one(), -Fr::one(), two(128) - Fr::one(), two(128), edge(&p_hi << 128usize), edge((&p_hi << 128usize) - 1u8), two(253)] {
        let mut cs = Cs::new();
        let v = cs.alloc(x);
        let bits = gadgets::canonical_bits_254(&mut cs, v);
        assert!(cs.is_satisfied(), "{x:?}");
        let n: BigUint = bits.iter().enumerate().map(|(i, b)| if cs.value(*b).is_one() { BigUint::from(1u8) << i } else { BigUint::from(0u8) }).sum();
        assert_eq!(n, model::to_big(&x));
    }
}

/// x + p has 254 bits too when x is small, and Σ bits·2^i is again x in the field. With that second
/// decomposition of h, a signature would verify for a second scalar. Here a prover writes those bits
/// and adjusts every other choice it has in the gadget to go with them (the bits of the gap to the
/// high half of the modulus, the inverse witness, the bits of the last range check), recomputing what
/// follows. Everything passes except the last gate: the low half is not below the modulus's, and no
/// 128 bits recompose to a negative number.
#[test]
fn the_second_decomposition_of_a_field_element_is_refused() {
    let p = model::p_big();
    let bit = |n: &BigUint, i: usize| if n.bit(i as u64) { Fr::one() } else { Fr::zero() };
    for x in [0u64, 1, 5, 123_456_789, u64::MAX] {
        let mut cs = Cs::new();
        let v = cs.alloc(Fr::from(x));
        let bits = gadgets::canonical_bits_254(&mut cs, v);
        assert!(cs.is_satisfied());
        let mut probe = Probe::new(&cs);

        // the prover's choices, in the order the gadget makes them
        let sources: Vec<u32> = (1..cs.n_vars() as u32).filter(|&i| probe.is_source(i)).collect();
        assert_eq!(sources.len(), 254 + 126 + 1 + 128);
        assert_eq!(sources[..254], bits.iter().map(|b| b.index()).collect::<Vec<_>>()[..]);
        let (gap_bits, inverse, last_bits) = (&sources[254..380], sources[380], &sources[381..]);

        let other = BigUint::from(x) + &p; // the same field element, 254 bits, not below p
        assert!(other.bits() == 254 && (&other >> 128usize) == (&p >> 128usize));
        // the low half minus the modulus's is x, so "p_lo − 1 − lo" is −x − 1: what the last range is asked to hold
        let wanted = &p - BigUint::from(x) - 1u8;
        for attempt in ["its low bits", "zeros", "ones"] {
            let mut changes: Vec<(u32, Fr)> = bits.iter().enumerate().map(|(i, b)| (b.index(), bit(&other, i))).collect();
            changes.extend(gap_bits.iter().map(|&b| (b, Fr::zero()))); // the high halves are equal: the gap is 0
            changes.push((inverse, Fr::zero())); // any value does, for the inverse of 0
            changes.extend(last_bits.iter().enumerate().map(|(i, &b)| {
                (b, match attempt {
                    "its low bits" => bit(&wanted, i),
                    "zeros" => Fr::zero(),
                    _ => Fr::one(),
                })
            }));
            let stop = probe.first_break_of(&changes).expect("the second decomposition went through");
            assert_eq!(stop, cs.n_gates() - 1, "x = {x}, {attempt}: refused at gate {stop}, not by the comparison");
        }
        // and without those adjustments it does not get that far
        let lazy: Vec<(u32, Fr)> = bits.iter().enumerate().map(|(i, b)| (b.index(), bit(&other, i))).collect();
        assert!(probe.first_break_of(&lazy).is_some());
    }
}

/// S·B8 = R8 + h·8·A holds for any S when 8·A is the identity and R8 = S·B8. The circuit refuses
/// such a key: the points of order 1, 2, 4 and 8.
#[test]
fn keys_of_small_order_do_not_sign() {
    let torsion = small_order_points();
    assert_eq!(torsion.len(), 8, "the curve has eight points of order dividing 8");
    let m = Fr::from(99u64);
    let s = BigUint::from(3u8);
    let r8 = model::mul_b8(&s);
    let verify = |a: &Pt, r8: &Pt, s: Fr| {
        let mut cs = Cs::new();
        let (a, r8, s, m) = (point(&mut cs, a), point(&mut cs, r8), cs.alloc(s), cs.alloc(m));
        gadgets::eddsa_verify(&mut cs, a, r8, s, m);
        cs.is_satisfied()
    };
    for t in &torsion {
        assert!(model::on_curve(t));
        assert_eq!(model::mul(t, &BigUint::from(8u8)), model::identity());
        assert!(model::mul(t, &BigUint::from(4u8))[0].is_zero());
        assert!(!verify(t, &r8, model::fr(&s)), "a key of small order signed: {t:?}");
        assert!(!model::verify_sig(t, &m, &model::Sig { r8, s: model::fr(&s) }));
    }

    // an honest key signs, in the circuit as in the model
    let keys = fixture::random_keys(&mut OsRng);
    let sig = model::sign(&keys.sk, &m);
    assert!(verify(&keys.ak, &sig.r8, sig.s) && model::verify_sig(&keys.ak, &m, &sig));
    assert!(!verify(&keys.ak, &sig.r8, sig.s + Fr::one()));
    // off the curve, neither the key nor R8 is accepted
    assert!(!verify(&[keys.ak[0] + Fr::one(), keys.ak[1]], &sig.r8, sig.s));
    assert!(!verify(&keys.ak, &[sig.r8[0], sig.r8[1] + Fr::one()], sig.s));
}

/// What the circuit does not refuse, stated so that nobody assumes otherwise: a key A + T with T of
/// small order is on the curve, outside the prime subgroup, and signs for whoever holds the scalar
/// of A. It is another key (another npk), not a second way to spend a note.
#[test]
fn a_key_outside_the_prime_subgroup_still_signs_for_its_owner() {
    let keys = fixture::random_keys(&mut OsRng);
    let t = small_order_points().into_iter().find(|t| !t[0].is_zero()).expect("a point of order 4 or 8");
    let a = model::add(&keys.ak, &t);
    assert!(model::on_curve(&a) && model::mul(&a, model::l_big()) != model::identity());
    // sign by hand: the challenge hashes A + T, and 8·(A + T) = 8·A
    let m = Fr::from(7u64);
    let k = &keys.sk % model::l_big();
    let r = BigUint::from(123_456_789u64);
    let r8 = model::mul_b8(&r);
    let h = model::to_big(&sh20_circuit::poseidon::hash(&[r8[0], r8[1], a[0], a[1], m]));
    let s = model::fr(&((r + BigUint::from(8u8) * h * k) % model::l_big()));
    let mut cs = Cs::new();
    let (av, rv, sv, mv) = (point(&mut cs, &a), point(&mut cs, &r8), cs.alloc(s), cs.alloc(m));
    gadgets::eddsa_verify(&mut cs, av, rv, sv, mv);
    assert!(cs.is_satisfied());
    assert_ne!(model::npk_of(&a, &keys.nk_pub), keys.npk);
}
