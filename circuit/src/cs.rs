//! Constraint system: PLONK gates over three wires,
//!
//!   ql·a + qr·b + qo·c + qm·a·b + qc = 0,
//!
//! with copy constraints given by variables shared between wire slots. The first `n_public` gates
//! bind the public inputs (a = public input i, ql = 1, and the prover's PI polynomial supplies
//! −public_i).
//!
//! The same synthesis code runs for key generation and for proving: the gates it emits never depend
//! on the values, only the assignment does.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use std::collections::HashMap;

/// A variable of the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Var(pub(crate) u32);

impl Var {
    pub fn from_index(i: u32) -> Var {
        Var(i)
    }
    pub fn index(self) -> u32 {
        self.0
    }
}

/// Selector indices in `Gate::q`.
pub const QL: usize = 0;
pub const QR: usize = 1;
pub const QO: usize = 2;
pub const QM: usize = 3;
pub const QC: usize = 4;

#[derive(Clone, Debug)]
pub struct Gate {
    /// Variables on wires a, b, c.
    pub w: [u32; 3],
    /// ql, qr, qo, qm, qc.
    pub q: [Fr; 5],
}

pub struct Cs {
    pub(crate) values: Vec<Fr>,
    pub(crate) gates: Vec<Gate>,
    pub(crate) n_public: usize,
    constants: HashMap<[u8; 32], Var>,
    tags: Vec<String>,
    gate_tag: Vec<u32>,
}

fn key(x: &Fr) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().expect("32 bytes")
}

impl Default for Cs {
    fn default() -> Self {
        Self::new()
    }
}

impl Cs {
    pub fn new() -> Self {
        // variable 0 fills unused wire slots; it is never constrained
        Cs { values: vec![Fr::zero()], gates: Vec::new(), n_public: 0, constants: HashMap::new(), tags: vec![String::new()], gate_tag: Vec::new() }
    }

    /// Names the gates that follow (reported by `unsatisfied`).
    pub fn at(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    pub fn n_gates(&self) -> usize {
        self.gates.len()
    }
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }
    pub fn n_vars(&self) -> usize {
        self.values.len()
    }
    pub fn n_public(&self) -> usize {
        self.n_public
    }
    pub fn public_values(&self) -> Vec<Fr> {
        self.gates[..self.n_public].iter().map(|g| self.values[g.w[0] as usize]).collect()
    }

    pub fn value(&self, x: Var) -> Fr {
        self.values[x.0 as usize]
    }

    /// The assignment: one value per variable.
    pub fn values(&self) -> &[Fr] {
        &self.values
    }

    pub fn alloc(&mut self, v: Fr) -> Var {
        self.values.push(v);
        Var((self.values.len() - 1) as u32)
    }

    /// The next public input. Every public input is declared before any other gate.
    pub fn public_input(&mut self, v: Fr) -> Var {
        assert_eq!(self.gates.len(), self.n_public, "public inputs come first");
        let x = self.alloc(v);
        self.gate(x, Var(0), Var(0), [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()]);
        self.n_public += 1;
        x
    }

    /// One gate: q[QL]·a + q[QR]·b + q[QO]·c + q[QM]·a·b + q[QC] = 0.
    pub fn gate(&mut self, a: Var, b: Var, c: Var, q: [Fr; 5]) {
        self.gates.push(Gate { w: [a.0, b.0, c.0], q });
        self.gate_tag.push((self.tags.len() - 1) as u32);
    }

    /// out = qm·x·y + ql·x + qr·y + qc
    pub fn quad(&mut self, x: Var, y: Var, qm: Fr, ql: Fr, qr: Fr, qc: Fr) -> Var {
        let (vx, vy) = (self.value(x), self.value(y));
        let out = self.alloc(qm * vx * vy + ql * vx + qr * vy + qc);
        self.gate(x, y, out, [ql, qr, -Fr::one(), qm, qc]);
        out
    }

    pub fn mul(&mut self, x: Var, y: Var) -> Var {
        self.quad(x, y, Fr::one(), Fr::zero(), Fr::zero(), Fr::zero())
    }
    pub fn add(&mut self, x: Var, y: Var) -> Var {
        self.quad(x, y, Fr::zero(), Fr::one(), Fr::one(), Fr::zero())
    }
    pub fn sub(&mut self, x: Var, y: Var) -> Var {
        self.quad(x, y, Fr::zero(), Fr::one(), -Fr::one(), Fr::zero())
    }
    /// out = cx·x + k
    pub fn lin1(&mut self, cx: Fr, x: Var, k: Fr) -> Var {
        self.quad(x, Var(0), Fr::zero(), cx, Fr::zero(), k)
    }
    /// out = cx·x + cy·y + k
    pub fn lin2(&mut self, cx: Fr, x: Var, cy: Fr, y: Var, k: Fr) -> Var {
        self.quad(x, y, Fr::zero(), cx, cy, k)
    }

    /// out = Σ coef·var + k, in max(1, terms − 1) gates.
    pub fn lc(&mut self, terms: &[(Fr, Var)], k: Fr) -> Var {
        match terms {
            [] => self.constant(k),
            [(c, x)] => self.lin1(*c, *x, k),
            [(c0, x0), (c1, x1), rest @ ..] => {
                let mut acc = self.lin2(*c0, *x0, *c1, *x1, k);
                for (c, x) in rest {
                    acc = self.lin2(Fr::one(), acc, *c, *x, Fr::zero());
                }
                acc
            }
        }
    }

    /// A variable fixed to the constant k (one gate per distinct constant).
    pub fn constant(&mut self, k: Fr) -> Var {
        if let Some(v) = self.constants.get(&key(&k)) {
            return *v;
        }
        let x = self.alloc(k);
        self.gate(x, Var(0), Var(0), [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), -k]);
        self.constants.insert(key(&k), x);
        x
    }

    pub fn assert_eq(&mut self, x: Var, y: Var) {
        self.gate(x, y, Var(0), [Fr::one(), -Fr::one(), Fr::zero(), Fr::zero(), Fr::zero()]);
    }
    /// x = k
    pub fn assert_const(&mut self, x: Var, k: Fr) {
        self.gate(x, Var(0), Var(0), [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), -k]);
    }
    /// x·(x − 1) = 0
    pub fn assert_bool(&mut self, x: Var) {
        self.gate(x, x, Var(0), [-Fr::one(), Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()]);
    }
    /// x·y = 0
    pub fn assert_mul_zero(&mut self, x: Var, y: Var) {
        self.gate(x, y, Var(0), [Fr::zero(), Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()]);
    }
    /// x ≠ 0, by exhibiting its inverse.
    pub fn assert_nonzero(&mut self, x: Var) {
        let inv = self.alloc(self.value(x).inverse().unwrap_or(Fr::zero()));
        self.gate(x, inv, Var(0), [Fr::zero(), Fr::zero(), Fr::zero(), Fr::one(), -Fr::one()]);
    }
    /// out = 1 if x = 0, else 0   (out = 1 − x·inv, x·out = 0).
    pub fn is_zero(&mut self, x: Var) -> Var {
        let inv = self.alloc(self.value(x).inverse().unwrap_or(Fr::zero()));
        let out = self.quad(x, inv, -Fr::one(), Fr::zero(), Fr::zero(), Fr::one());
        self.assert_mul_zero(x, out);
        out
    }

    /// The first gate the assignment does not satisfy, with the tag it was emitted under.
    pub fn unsatisfied(&self) -> Option<(usize, String)> {
        for (i, g) in self.gates.iter().enumerate() {
            let [a, b, c] = g.w.map(|w| self.values[w as usize]);
            let mut v = g.q[QL] * a + g.q[QR] * b + g.q[QO] * c + g.q[QM] * a * b + g.q[QC];
            if i < self.n_public {
                v -= a;
            }
            if !v.is_zero() {
                return Some((i, self.tags[self.gate_tag[i] as usize].clone()));
            }
        }
        None
    }

    pub fn is_satisfied(&self) -> bool {
        self.unsatisfied().is_none()
    }

    /// The number of gates emitted under each tag, in the order the tags were set: where the size of
    /// the circuit is.
    pub fn gate_counts(&self) -> Vec<(String, usize)> {
        let mut counts = vec![0usize; self.tags.len()];
        for t in &self.gate_tag {
            counts[*t as usize] += 1;
        }
        self.tags.iter().cloned().zip(counts).filter(|(_, n)| *n > 0).collect()
    }

    /// The tag gate `i` was emitted under.
    pub fn tag_of(&self, i: usize) -> &str {
        &self.tags[self.gate_tag[i] as usize]
    }

    /// Same gates on the same wires (the assignment may differ).
    pub fn same_gates(&self, other: &Cs) -> bool {
        self.n_public == other.n_public && self.gates.len() == other.gates.len() && self.gates.iter().zip(&other.gates).all(|(a, b)| a.w == b.w && a.q == b.q)
    }
}
