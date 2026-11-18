//! How small can a Halo2-KZG proof (PSE halo2_proofs v0.3.0, SHPLONK, BLAKE2b transcript: Tacit's
//! stack) get for the SH-20 spend relation, and what does it cost to prove?
//!
//! A Halo2 proof carries one commitment per advice column and one evaluation per (column, rotation)
//! queried, fixed columns included: unlike PLONK's linearisation, selectors are opened. So the size
//! is set by the layout, not by the statement. This program measures two layouts that bracket what a
//! "tighter Halo2 circuit" can be; rows are filled with satisfied gates on random-looking data, so
//! the proving time is that of a full circuit of this shape. It does not implement the relation.
//!
//!   vanilla   3 advice columns, the 5 PLONK selectors, no rotation: the narrowest layout, which
//!             needs as many rows as PLONK does (k = 17)
//!   narrow    4 advice columns with a degree-5 round gate (x^5 S-box, next-row rotation) and an
//!             arithmetic gate: about 16,000 rows for the relation (k = 14)
//!
//!   cargo run --release -- <vanilla|narrow> <k> [runs]        (RAYON_NUM_THREADS=1 for one thread)

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand_core::OsRng;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Vanilla,
    Narrow,
}

#[derive(Clone)]
struct Config {
    shape: Shape,
    s: [Column<Advice>; 3],
    aux: Option<Column<Advice>>,
    f: [Column<Fixed>; 5],
    q_round: Option<Selector>,
}

/// `NARROW` picks the layout at compile time (the circuit's columns are fixed by its type).
#[derive(Clone)]
struct Bench<const NARROW: bool> {
    k: u32,
}

/// A fixed invertible 3×3 matrix standing in for the MDS matrix.
fn mix(i: usize, j: usize) -> Fr {
    Fr::from(((i + 1) * (j + 2) + (i == j) as usize * 7) as u64)
}

impl<const NARROW: bool> Circuit<Fr> for Bench<NARROW> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        let shape = if NARROW { Shape::Narrow } else { Shape::Vanilla };
        let s = [(); 3].map(|_| meta.advice_column());
        for c in &s {
            meta.enable_equality(*c);
        }
        let f = [(); 5].map(|_| meta.fixed_column());
        // one permutation product for the three columns needs degree 5 (chunks of degree − 2)
        meta.set_minimum_degree(5);
        // ql·a + qr·b + qo·c + qm·a·b + qc = 0; all-zero selectors switch a row off
        meta.create_gate("arith", |m| {
            let [a, b, c] = s.map(|col| m.query_advice(col, Rotation::cur()));
            let [ql, qr, qo, qm, qc] = f.map(|col| m.query_fixed(col, Rotation::cur()));
            vec![ql * a.clone() + qr * b.clone() + qo * c + qm * a * b + qc]
        });
        let (aux, q_round) = match shape {
            Shape::Vanilla => (None, None),
            Shape::Narrow => {
                let aux = meta.advice_column();
                let q = meta.selector();
                // one hash round per row: next = M·(cur + rc)^5, with aux = (s0 + rc0)^2 to keep degree 5
                meta.create_gate("round", |m| {
                    let q = m.query_selector(q);
                    let x: Vec<Expression<Fr>> = (0..3).map(|j| m.query_advice(s[j], Rotation::cur()) + m.query_fixed(f[j], Rotation::cur())).collect();
                    let sq = m.query_advice(aux, Rotation::cur());
                    let sb: Vec<Expression<Fr>> = vec![sq.clone() * sq.clone() * x[0].clone(), x[1].clone(), x[2].clone()];
                    let mut cs = vec![q.clone() * (sq - x[0].clone() * x[0].clone())];
                    for i in 0..3 {
                        let acc = (0..3).fold(Expression::Constant(Fr::ZERO), |acc, j| acc + Expression::Constant(mix(i, j)) * sb[j].clone());
                        cs.push(q.clone() * (m.query_advice(s[i], Rotation::next()) - acc));
                    }
                    cs
                });
                (Some(aux), Some(q))
            }
        };
        Config { shape, s, aux, f, q_round }
    }

    fn synthesize(&self, cfg: Config, mut ly: impl Layouter<Fr>) -> Result<(), Error> {
        let rows = (1usize << self.k) - 16;
        ly.assign_region(
            || "fill",
            |mut r| {
                match cfg.shape {
                    Shape::Vanilla => {
                        // a chain of multiplications: c_i = a_i·b_i, a_{i+1} copied from c_i
                        let mut prev = None;
                        let mut a = Fr::from(3u64);
                        for i in 0..rows {
                            let b = Fr::from(i as u64 * 0x9e37_79b9 + 5).square();
                            let c = a * b;
                            let ac = r.assign_advice(|| "a", cfg.s[0], i, || Value::known(a))?;
                            r.assign_advice(|| "b", cfg.s[1], i, || Value::known(b))?;
                            let cc = r.assign_advice(|| "c", cfg.s[2], i, || Value::known(c))?;
                            r.assign_fixed(|| "qo", cfg.f[2], i, || Value::known(-Fr::ONE))?;
                            r.assign_fixed(|| "qm", cfg.f[3], i, || Value::known(Fr::ONE))?;
                            if let Some(p) = prev {
                                r.constrain_equal(p, ac.cell())?;
                            }
                            prev = Some(cc.cell());
                            a = c;
                        }
                    }
                    Shape::Narrow => {
                        let mut st = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
                        for i in 0..rows {
                            let rc: [Fr; 3] = std::array::from_fn(|j| Fr::from((i * 3 + j) as u64 + 11).square());
                            for j in 0..3 {
                                r.assign_advice(|| "s", cfg.s[j], i, || Value::known(st[j]))?;
                                r.assign_fixed(|| "rc", cfg.f[j], i, || Value::known(rc[j]))?;
                            }
                            // with round constants in f0..f2, the arithmetic gate needs ql·a + qr·b + qo·c = 0
                            // off: this layout would keep separate rows for arithmetic; here the gate is
                            // satisfied by cancelling it through qc
                            let x: [Fr; 3] = std::array::from_fn(|j| st[j] + rc[j]);
                            let lin = rc[0] * st[0] + rc[1] * st[1] + rc[2] * st[2];
                            r.assign_fixed(|| "qc", cfg.f[4], i, || Value::known(-lin))?;
                            let sq = x[0].square();
                            r.assign_advice(|| "aux", cfg.aux.unwrap(), i, || Value::known(sq))?;
                            if i + 1 < rows {
                                cfg.q_round.unwrap().enable(&mut r, i)?;
                            }
                            let sb = [sq.square() * x[0], x[1], x[2]];
                            st = std::array::from_fn(|a| (0..3).fold(Fr::ZERO, |acc, j| acc + mix(a, j) * sb[j]));
                        }
                    }
                }
                Ok(())
            },
        )
    }
}

fn run<const NARROW: bool>(name: &str, k: u32, runs: usize) {
    let circuit = Bench::<NARROW> { k };

    // any SRS gives the same size and time; the standard would use the Hermez one
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let t = Instant::now();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let t_keygen = t.elapsed().as_secs_f64();

    let mut times = Vec::new();
    let mut proof = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        let mut tr = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(&params, &pk, &[circuit.clone()], &[&[]], OsRng, &mut tr).unwrap();
        proof = tr.finalize();
        times.push(t.elapsed().as_secs_f64());
    }
    let mut tr = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(&params, pk.get_vk(), SingleStrategy::new(&params), &[&[]], &mut tr).expect("proof verifies");

    let cs = pk.get_vk().cs();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "{name} k={k}: proof {} bytes; advice {} (queries {}), fixed {} (queries {}), degree {}; threads {}: prove min {:.2} s, median {:.2} s ({}); keygen {:.2} s",
        proof.len(),
        cs.num_advice_columns(),
        cs.advice_queries().len(),
        cs.num_fixed_columns(),
        cs.fixed_queries().len(),
        cs.degree(),
        rayon::current_num_threads(),
        sorted[0],
        sorted[sorted.len() / 2],
        times.iter().map(|x| format!("{x:.2}")).collect::<Vec<_>>().join(" / "),
        t_keygen
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let k: u32 = args.get(1).and_then(|s| s.parse().ok()).expect("usage: halo2-shape <vanilla|narrow> <k> [runs]");
    let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    match args[0].as_str() {
        "vanilla" => run::<false>("vanilla", k, runs),
        "narrow" => run::<true>("narrow", k, runs),
        _ => panic!("usage: halo2-shape <vanilla|narrow> <k> [runs]"),
    }
}
