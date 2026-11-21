//! What one proof for several transfers would cost: the measurements behind "Batches and the 150 vB
//! target" in README.md. An experiment. The circuits built here are not the spend circuit of
//! docs/SPEC-WIRE.md, their keys are pinned nowhere and nothing ships them.
//!
//!   cargo run --release --example batch_cost -- <setup> [runs=N] [shape or verify:N ...]
//!
//! <setup> is where the powers of tau come from:
//!   artifacts/spend.pk     the 131,078 powers of the shipped key: enough for a domain of 2^17
//!   <pot18.ptau>           the pinned Hermez file, 524,287 powers: up to a domain of 2^18
//!   --throwaway-srs        powers of a random tau, forgotten at once: for timing only, any domain
//!
//! A shape is `SxI:O`: S spends in one circuit, each with I input notes, O output notes and its own
//! ticker, root and body hash. `1x2:3` is the spend circuit as it is, and the run checks that it
//! emits the same gates as `spend::synthesize`. `3x2:3` is three transfers under one proof, `1x2:11`
//! one transfer that pays ten people and keeps the change. For each shape: the gates, the domain,
//! key generation, the proving time with its phases, and the verification of the proof. The shapes
//! are proved in turn, `runs` times over, and the best pass of each is printed: on a busy machine
//! compare the shapes of one run with each other, not with another day's figures.
//!
//! `verify:N` makes N proofs of `1x2:3` and verifies them one by one, then as one pairing equation.
//!
//! RAYON_NUM_THREADS sets the threads. For the peak memory of one shape, run it alone under
//! `/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux).
//!
//! `synthesize` below restates the relation of `src/spend.rs`, which derives from Tacit's Bitcoin
//! shielded pool spend relation (dapp/circuits/btc-pool/spend.circom and its Halo2 port), MIT
//! License, Copyright (c) 2026 ross.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use rand_core::OsRng;
use sh20_circuit::cs::{Cs, Var};
use sh20_circuit::gadgets::{self, Lane};
use sh20_circuit::model::{self, NoteKeys, Sig, Tree, TREE_DEPTH};
use sh20_circuit::plonk::{self, keys, transcript, Proof, Srs, VerifyingKey};
use sh20_circuit::{fixture, load_key, spend, SpendWitness};
use std::time::Instant;

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

struct Input {
    keys: NoteKeys,
    v: u64,
    rho: Fr,
    index: u64,
    path: [Fr; TREE_DEPTH],
    nf: Fr,
    sig: Sig,
}

struct Output {
    npk: Fr,
    v: u64,
    rho: Fr,
    leaf: Fr,
}

/// One spend of any arity: the relation of `spend::synthesize` with `inputs.len()` input notes and
/// `outputs.len()` output notes instead of two and three.
struct Spend {
    t: Fr,
    root: Fr,
    body: Fr,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

/// An honest transfer with `n_in` notes of 1,000 units in a small tree, paying 7 units to each
/// output but the last, which takes the rest.
fn sample(n_in: usize, n_out: usize) -> Spend {
    let rng = &mut OsRng;
    let t = Fr::from(fixture::gene() as u64);
    let mut body = [0u8; 64];
    rand_core::RngCore::fill_bytes(rng, &mut body);
    let body = model::body_hash(&body);

    let notes: Vec<(NoteKeys, u64, Fr)> = (0..n_in).map(|_| (fixture::random_keys(rng), 1000, Fr::rand(rng))).collect();
    let mut leaves: Vec<Fr> = (0..3).map(|_| Fr::rand(rng)).collect();
    leaves.extend(notes.iter().map(|(keys, v, rho)| model::note_leaf(&t, &Fr::from(*v), &keys.npk, rho)));
    let tree = Tree::new(&leaves);
    let inputs = notes
        .into_iter()
        .enumerate()
        .map(|(i, (keys, v, rho))| {
            let index = 3 + i;
            let nf = model::nullifier(&keys.nk, &leaves[index], index as u64);
            let sig = model::sign(&keys.sk, &body);
            Input { keys, v, rho, index: index as u64, path: tree.path(index), nf, sig }
        })
        .collect();

    let total = 1000 * n_in as u64;
    let outputs = (0..n_out)
        .map(|k| {
            let v = if k + 1 < n_out { 7 } else { total - 7 * (n_out as u64 - 1) };
            let (npk, rho) = (fixture::random_keys(rng).npk, Fr::rand(rng));
            Output { npk, v, rho, leaf: model::note_leaf(&t, &Fr::from(v), &npk, &rho) }
        })
        .collect();
    Spend { t, root: tree.root, body, inputs, outputs }
}

/// leaf = H(H(head, v), H(npk, rho)), as in `spend.rs`.
fn note_leaf(cs: &mut Cs, head: Var, v: Var, npk: Var, rho: Var) -> Var {
    let hv = gadgets::poseidon_vars(cs, &[head, v]);
    let hk = gadgets::poseidon_vars(cs, &[npk, rho]);
    gadgets::poseidon_vars(cs, &[hv, hk])
}

/// The gates of `spend::synthesize`, once for each spend, in one constraint system. Public inputs
/// come first, spend after spend: root, the nullifiers, the output leaves, bodyHash, vPub, tPub.
/// These are transfers: vPub and tPub are 0.
fn synthesize(spends: &[Spend]) -> Cs {
    struct Public {
        root: Var,
        nf: Vec<Var>,
        out_leaf: Vec<Var>,
        body: Var,
        v_pub: Var,
        t_pub: Var,
    }
    let mut system = Cs::new();
    let cs = &mut system;

    cs.at("public");
    let mut publics = Vec::new();
    for s in spends {
        publics.push(Public {
            root: cs.public_input(s.root),
            nf: s.inputs.iter().map(|i| cs.public_input(i.nf)).collect(),
            out_leaf: s.outputs.iter().map(|o| cs.public_input(o.leaf)).collect(),
            body: cs.public_input(s.body),
            v_pub: cs.public_input(Fr::zero()),
            t_pub: cs.public_input(Fr::zero()),
        });
    }

    for (s, p) in spends.iter().zip(&publics) {
        cs.at("ticker");
        let t = cs.alloc(s.t);
        let head = gadgets::poseidon(cs, &[Lane::Const(model::tag_leaf()), Lane::Var(t)]);

        let mut in_v = Vec::new();
        for (i, (note, &nf)) in s.inputs.iter().zip(&p.nf).enumerate() {
            cs.at(format!("in{i} value"));
            let v = cs.alloc(Fr::from(note.v));
            gadgets::range(cs, v, 64);

            cs.at(format!("in{i} nullifier key"));
            let nk = cs.alloc(model::fr(&note.keys.nk));
            let nk_bits = gadgets::scalar_bits(cs, nk);
            let nk_pub = gadgets::fixed_mul(cs, &nk_bits, &model::base8());

            cs.at(format!("in{i} note"));
            let ak = [cs.alloc(note.keys.ak[0]), cs.alloc(note.keys.ak[1])];
            let npk = gadgets::poseidon_vars(cs, &[ak[0], ak[1], nk_pub[0], nk_pub[1]]);
            let rho = cs.alloc(note.rho);
            let leaf = note_leaf(cs, head, v, npk, rho);

            cs.at(format!("in{i} membership"));
            let index = cs.alloc(Fr::from(note.index));
            let index_bits = gadgets::to_bits(cs, index, TREE_DEPTH);
            let path: Vec<Var> = note.path.iter().map(|x| cs.alloc(*x)).collect();
            let reached = gadgets::merkle_root(cs, leaf, &index_bits, &path);
            let dummy = cs.is_zero(v);
            let diff = cs.sub(reached, p.root);
            cs.gate(diff, dummy, Var::from_index(0), [Fr::one(), Fr::zero(), Fr::zero(), -Fr::one(), Fr::zero()]);

            cs.at(format!("in{i} nullifier"));
            let nfh = gadgets::poseidon_vars(cs, &[nk, leaf, index]);
            cs.assert_eq(nfh, nf);

            cs.at(format!("in{i} signature"));
            let r8 = [cs.alloc(note.sig.r8[0]), cs.alloc(note.sig.r8[1])];
            let sig_s = cs.alloc(note.sig.s);
            gadgets::eddsa_verify(cs, ak, r8, sig_s, p.body);

            in_v.push(v);
        }

        let mut out_v = Vec::new();
        for (k, (note, &out_leaf)) in s.outputs.iter().zip(&p.out_leaf).enumerate() {
            cs.at(format!("out{k} value"));
            let v = cs.alloc(Fr::from(note.v));
            gadgets::range(cs, v, 64);
            cs.at(format!("out{k} leaf"));
            let npk = cs.alloc(note.npk);
            let rho = cs.alloc(note.rho);
            let leaf = note_leaf(cs, head, v, npk, rho);
            cs.assert_eq(leaf, out_leaf);
            out_v.push(v);
        }

        cs.at("public value");
        gadgets::range(cs, p.v_pub, 64);
        let dt = cs.sub(t, p.t_pub);
        cs.assert_mul_zero(p.v_pub, dt);

        cs.at("conservation");
        let mut sum_in = in_v[0];
        for &v in &in_v[1..] {
            sum_in = cs.add(sum_in, v);
        }
        let mut terms: Vec<(Fr, Var)> = out_v.iter().map(|&v| (Fr::one(), v)).collect();
        terms.push((Fr::one(), p.v_pub));
        let sum_out = cs.lc(&terms, Fr::zero());
        cs.assert_eq(sum_in, sum_out);
    }
    system
}

/// Powers of a random tau, which is dropped when this returns. For timing only: whoever ran this
/// could have kept tau, and with it forge proofs under these keys.
fn throwaway_srs(count: usize) -> Srs {
    let tau = Fr::rand(&mut OsRng);
    let mut powers = Vec::with_capacity(count);
    let mut x = Fr::one();
    for _ in 0..count {
        powers.push(x);
        x *= tau;
    }
    Srs { g1: G1Projective::generator().batch_mul(&powers), g2_tau: (G2Projective::generator() * tau).into_affine() }
}

/// G1 powers in powersOfTau28_hez_final_18.ptau.
const POT18_POWERS: usize = (1 << 19) - 1;

enum Setup {
    Fixed(Srs, &'static str),
    Throwaway,
}

impl Setup {
    fn open(arg: &str) -> Setup {
        if arg == "--throwaway-srs" {
            return Setup::Throwaway;
        }
        let bytes = std::fs::read(arg).unwrap_or_else(|e| fail(&format!("{arg}: {e}")));
        if bytes.starts_with(b"ptau") {
            if plonk::srs::blake2b_hex(&bytes) != plonk::srs::POT18_BLAKE2B {
                fail("the ptau file is not the pinned Hermez powersOfTau28_hez_final_18.ptau");
            }
            // every power of the file: 2^19 − 1 of them, seven short of what a domain of 2^19 needs
            return Setup::Fixed(Srs::from_ptau(&bytes, POT18_POWERS).unwrap_or_else(|e| fail(&e)), "Hermez pot18");
        }
        Setup::Fixed(load_key(&bytes).unwrap_or_else(|e| fail(&e)).srs(), "Hermez pot18, the powers of the shipped key")
    }

    /// The first `count` powers, and where they come from.
    fn powers(&self, count: usize) -> Result<(Srs, &'static str), String> {
        match self {
            Setup::Throwaway => Ok((throwaway_srs(count), "throwaway powers, timing only")),
            Setup::Fixed(srs, name) if srs.g1.len() >= count => Ok((Srs { g1: srs.g1[..count].to_vec(), g2_tau: srs.g2_tau }, name)),
            Setup::Fixed(srs, _) => Err(format!("needs {count} powers, this setup holds {}", srs.g1.len())),
        }
    }
}

fn threads() -> usize {
    #[cfg(feature = "parallel")]
    return rayon::current_num_threads();
    #[cfg(not(feature = "parallel"))]
    1
}

fn seconds(since: Instant) -> f64 {
    since.elapsed().as_secs_f64()
}

/// Processor time this process has used, all threads together, in seconds.
fn cpu_seconds() -> f64 {
    extern "C" {
        fn clock() -> i64; // POSIX: in millionths of a second
    }
    unsafe { clock() as f64 / 1e6 }
}

/// A shape with its keys, ready to prove.
struct Built {
    name: String,
    cs: Cs,
    pk: plonk::ProvingKey,
    head: String,
    /// (seconds on the clock, processor seconds, phases) of each proof made
    times: Vec<(f64, f64, plonk::Timings)>,
    proof: Option<Proof>,
}

fn build(setup: &Setup, spends: usize, n_in: usize, n_out: usize) -> Option<Built> {
    let name = format!("{spends}x{n_in}:{n_out}");
    let witnesses: Vec<Spend> = (0..spends).map(|_| sample(n_in, n_out)).collect();
    let cs = synthesize(&witnesses);
    if let Some((gate, tag)) = cs.unsatisfied() {
        fail(&format!("{name}: the sample witness breaks gate {gate} ({tag})"));
    }
    if (spends, n_in, n_out) == (1, 2, 3) && !cs.same_gates(&spend::synthesize(&SpendWitness::default())) {
        fail("1x2:3 does not emit the gates of spend::synthesize: this file has drifted from src/spend.rs");
    }
    let rows = keys::rows_for(cs.n_gates());
    let head = format!("{name}: {} gates, {} public inputs, domain 2^{}", cs.n_gates(), cs.n_public(), rows.trailing_zeros());
    let (srs, origin) = match setup.powers(rows + keys::SRS_EXTRA) {
        Ok(x) => x,
        Err(e) => {
            println!("{head}; not proved: {e}");
            return None;
        }
    };
    let t = Instant::now();
    let pk = plonk::setup(&cs, &srs).unwrap_or_else(|e| fail(&e));
    let head = format!("{head} ({origin}); proving key {:.1} MB, key generation {:.1} s", pk.to_bytes().len() as f64 / 1e6, seconds(t));
    Some(Built { name, cs, pk, head, times: Vec::new(), proof: None })
}

impl Built {
    fn prove(&mut self) {
        let (t, cpu) = (Instant::now(), cpu_seconds());
        let (proof, phases) = plonk::prove_timed(&self.pk, self.cs.values(), &mut OsRng).unwrap_or_else(|e| fail(&e));
        self.times.push((seconds(t), cpu_seconds() - cpu, phases));
        self.proof = Some(proof);
    }

    fn report(mut self) {
        let name = &self.name;
        let proof = self.proof.unwrap_or_else(|| fail("runs must be at least 1"));
        let bytes = proof.to_bytes().unwrap_or_else(|| fail("degenerate proof"));
        let publics = self.cs.public_values();
        let reps = 20;
        let t = Instant::now();
        for _ in 0..reps {
            if !plonk::verify(&self.pk.vk, &publics, &proof) {
                fail(&format!("{name}: the proof does not verify"));
            }
        }
        let t_verify = seconds(t) / reps as f64;
        let mut tampered = publics.clone();
        tampered[0] += Fr::one();
        if plonk::verify(&self.pk.vk, &tampered, &proof) {
            fail(&format!("{name}: the proof verifies for another root"));
        }

        self.times.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        let (best, cpu, phases) = &self.times[0];
        println!("{}", self.head);
        println!(
            "  proof {} bytes, verified in {:.2} ms; prove on {} thread(s): best {best:.2} s, median {:.2} s of {} ({cpu:.1} s of processor; commitments {:.2}, transforms {:.2}, quotient {:.2}, rest {:.2})",
            bytes.len(),
            t_verify * 1e3,
            threads(),
            self.times[self.times.len() / 2].0,
            self.times.len(),
            phases.msm,
            phases.fft,
            phases.quotient,
            phases.other
        );
    }
}

/// What `plonk::verify` computes for one proof before its pairing: the equation is
/// e(lhs, [tau]_2) = e(rhs, [1]_2), with lhs = Wxi + u·Wxiw and rhs the sum of `scalars[i]·bases[i]`.
/// The first nine bases are those of the key and the generator, the same for every proof.
/// Follows `plonk/verifier.rs` line by line, without its first step: a verifier that is handed bytes
/// checks the count of public inputs and that each point is on the curve before anything else.
fn pairing_terms(vk: &VerifyingKey, publics: &[Fr], p: &Proof) -> Option<([Fr; 18], [G1Affine; 18], Fr)> {
    let n = 1usize << vk.power;
    let omega = keys::domain(n).group_gen();
    let (k1, k2) = (vk.k1, vk.k2);
    let (beta, gamma) = transcript::beta_gamma(vk, publics, &p.a, &p.b, &p.c);
    let alpha = transcript::alpha(&beta, &gamma, &p.z);
    let xi = transcript::xi(&alpha, &p.t1, &p.t2, &p.t3);
    let v = transcript::v(&xi, [&p.eval_a, &p.eval_b, &p.eval_c, &p.eval_s1, &p.eval_s2, &p.eval_zw]);
    let u = transcript::u(&p.wxi, &p.wxiw);
    let alpha2 = alpha.square();

    let xin = xi.pow([n as u64]);
    let zh = xin - Fr::one();
    let n_inv = Fr::from(n as u64).inverse()?;
    let mut w = Fr::one();
    let mut pi = Fr::zero();
    let mut l1 = Fr::zero();
    for (i, x) in publics.iter().enumerate() {
        let l = w * zh * n_inv * (xi - w).inverse()?;
        if i == 0 {
            l1 = l;
        }
        pi -= *x * l;
        w *= omega;
    }

    let (a, b, c, s1, s2, zw) = (p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw);
    let sa = a + beta * s1 + gamma;
    let sb = b + beta * s2 + gamma;
    let r0 = pi - l1 * alpha2 - alpha * sa * sb * (c + gamma) * zw;
    let (v2, v3, v4, v5) = (v * v, v * v * v, v.square().square(), v.square().square() * v);
    let coef_z = alpha * (a + beta * xi + gamma) * (b + beta * k1 * xi + gamma) * (c + beta * k2 * xi + gamma) + alpha2 * l1 + u;
    let coef_s3 = alpha * sa * sb * beta * zw;
    let e = -r0 + v * a + v2 * b + v3 * c + v4 * s1 + v5 * s2 + u * zw;

    let bases = [vk.qm, vk.ql, vk.qr, vk.qo, vk.qc, vk.s3, vk.s1, vk.s2, G1Affine::generator(), p.z, p.t1, p.t2, p.t3, p.a, p.b, p.c, p.wxi, p.wxiw];
    let scalars = [a * b, a, b, c, Fr::one(), -coef_s3, v4, v5, -e, coef_z, -zh, -zh * xin, -zh * xin * xin, v, v2, v3, xi, u * xi * omega];
    Some((scalars, bases, u))
}

/// N proofs in one pairing equation: each proof's equation is multiplied by a random r_i and the
/// N equations are added. If one of them does not hold, the sum holds with probability 1/|Fr|.
/// The r_i must be unknown to whoever made the proofs: here they are the verifier's own randomness.
fn verify_together(vk: &VerifyingKey, batch: &[(Vec<Fr>, Proof)]) -> bool {
    let mut shared = [Fr::zero(); 9];
    let (mut bases, mut scalars) = (Vec::new(), Vec::new());
    let (mut lhs_bases, mut lhs_scalars) = (Vec::new(), Vec::new());
    for (publics, p) in batch {
        let Some((s, b, u)) = pairing_terms(vk, publics, p) else { return false };
        let r = Fr::rand(&mut OsRng);
        for (acc, x) in shared.iter_mut().zip(&s[..9]) {
            *acc += r * x;
        }
        bases.extend_from_slice(&b[9..]);
        scalars.extend(s[9..].iter().map(|x| r * x));
        lhs_bases.extend([p.wxi, p.wxiw]);
        lhs_scalars.extend([r, r * u]);
    }
    bases.extend([vk.qm, vk.ql, vk.qr, vk.qo, vk.qc, vk.s3, vk.s1, vk.s2, G1Affine::generator()]);
    scalars.extend(shared);
    let rhs = G1Projective::msm_unchecked(&bases, &scalars);
    let lhs = G1Projective::msm_unchecked(&lhs_bases, &lhs_scalars);
    Bn254::multi_pairing([(-lhs).into_affine(), rhs.into_affine()], [vk.x2, G2Affine::generator()]).is_zero()
}

fn verify_many(setup: &Setup, n: usize) {
    let cs = spend::synthesize(&SpendWitness::default());
    let (srs, _) = setup.powers(keys::rows_for(cs.n_gates()) + keys::SRS_EXTRA).unwrap_or_else(|e| fail(&e));
    let pk = plonk::setup(&cs, &srs).unwrap_or_else(|e| fail(&e));
    let batch: Vec<(Vec<Fr>, Proof)> = (0..n)
        .map(|_| {
            let w = fixture::transfer(&mut OsRng);
            let proof = plonk::prove(&pk, spend::synthesize(&w).values(), &mut OsRng).unwrap_or_else(|e| fail(&e));
            (w.publics().to_vec(), proof)
        })
        .collect();

    // one process, one after the other, as an indexer does it: the best of several passes
    let best = |f: &dyn Fn() -> bool| {
        (0..20)
            .map(|_| {
                let t = Instant::now();
                assert!(f());
                seconds(t)
            })
            .fold(f64::MAX, f64::min)
    };
    let one_by_one = best(&|| batch.iter().all(|(publics, proof)| plonk::verify(&pk.vk, publics, proof)));
    let together = best(&|| verify_together(&pk.vk, &batch));

    // one bad proof among them: the sum fails, and the indexer still has to find which one
    let mut bad = batch.clone();
    bad[n / 2].0[1] += Fr::one();
    assert!(!verify_together(&pk.vk, &bad), "a batch with a wrong nullifier verifies");

    println!("verify:{n}: {n} proofs of 1x2:3, {} thread(s)", threads());
    println!(
        "  one by one {:.2} ms ({:.2} ms each); as one equation {:.2} ms ({:.2} ms each)",
        one_by_one * 1e3,
        one_by_one * 1e3 / n as f64,
        together * 1e3,
        together * 1e3 / n as f64
    );
    println!("  a batch with one wrong public input is refused as a whole; the bytes on the wire are the same");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(first) = args.first() else { fail("usage: batch_cost <artifacts/spend.pk | pot18.ptau | --throwaway-srs> [runs=N] [SxI:O | verify:N ...]") };
    let setup = Setup::open(first);
    let mut runs = 3;
    let mut jobs: Vec<&str> = Vec::new();
    for a in &args[1..] {
        match a.strip_prefix("runs=") {
            Some(n) => runs = n.parse().unwrap_or_else(|_| fail("runs=N")),
            None => jobs.push(a),
        }
    }
    if jobs.is_empty() {
        jobs = vec!["1x2:3", "1x2:11", "1x2:25", "2x2:3", "3x2:3", "verify:10"];
    }
    let mut built = Vec::new();
    let mut verifications = Vec::new();
    for job in jobs {
        if let Some(n) = job.strip_prefix("verify:") {
            verifications.push(n.parse().unwrap_or_else(|_| fail("verify:N")));
            continue;
        }
        let parsed = job.split_once('x').and_then(|(s, rest)| {
            let (i, o) = rest.split_once(':')?;
            Some((s.parse().ok()?, i.parse().ok()?, o.parse().ok()?))
        });
        match parsed {
            Some((s, i, o)) if s >= 1 && i >= 1 && o >= 1 => built.extend(build(&setup, s, i, o)),
            _ => fail(&format!("{job}: a shape is SxI:O, as in 3x2:3")),
        }
    }
    // One proof of each shape in turn, `runs` times over: whatever else the machine is doing falls on
    // every shape alike, and the best pass of each is kept.
    for _ in 0..runs {
        for b in built.iter_mut() {
            b.prove();
        }
    }
    for b in built {
        b.report();
    }
    for n in verifications {
        verify_many(&setup, n);
    }
}
