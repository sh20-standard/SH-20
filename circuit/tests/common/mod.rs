//! A malicious prover's view of an assignment: change one variable and see what the gates say.
//!
//! Two questions, for a variable `v` of a satisfied circuit and a new value for it:
//!
//!   * `breaks_alone`: with every other variable left as it is, is some gate now unsatisfied?
//!   * `first_break`: after recomputing every variable that a later gate defines, as an honest
//!     synthesis would, is some gate still unsatisfied?
//!
//! The second is the stronger one. A variable that only feeds computations passes the first test
//! trivially (the gate computing from it no longer matches its old output); it passes the second
//! only if the change reaches a gate that checks something.
//!
//! "A gate defines a variable" when that gate is the first one the variable appears in, on wire c
//! with a non-zero qO and nowhere else in the gate: `Cs::quad` and everything built on it. The other
//! variables are the prover's free choices (the witness, bits, inverses, quotients of divisions) and
//! are called sources here.

#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use sh20_circuit::cs::{Cs, Gate, QC, QL, QM, QO, QR};

pub struct Probe<'a> {
    pub cs: &'a Cs,
    gates: &'a [Gate],
    /// The value each public-input row compares with: the statement does not move.
    publics: Vec<Fr>,
    /// Gates each variable appears in, in order.
    uses: Vec<Vec<u32>>,
    /// The variable gate i defines, if any, with −1/qO of that gate.
    defines: Vec<Option<(u32, Fr)>>,
    /// Whether some gate defines the variable.
    derived: Vec<bool>,
    work: Vec<Fr>,
}

impl<'a> Probe<'a> {
    pub fn new(cs: &'a Cs) -> Probe<'a> {
        assert!(cs.is_satisfied(), "the probe starts from a satisfied circuit");
        let gates = cs.gates();
        let n_vars = cs.n_vars();
        let mut uses: Vec<Vec<u32>> = vec![Vec::new(); n_vars];
        let mut defines = vec![None; gates.len()];
        let mut derived = vec![false; n_vars];
        for (i, g) in gates.iter().enumerate() {
            let [a, b, c] = g.w;
            if i >= cs.n_public() && c != 0 && uses[c as usize].is_empty() && c != a && c != b && !g.q[QO].is_zero() {
                defines[i] = Some((c, -g.q[QO].inverse().expect("qO")));
                derived[c as usize] = true;
            }
            for w in g.w {
                if uses[w as usize].last() != Some(&(i as u32)) {
                    uses[w as usize].push(i as u32);
                }
            }
        }
        Probe { cs, gates, publics: cs.public_values(), uses, defines, derived, work: cs.values().to_vec() }
    }

    pub fn value(&self, v: u32) -> Fr {
        self.cs.values()[v as usize]
    }
    /// A variable the prover chooses: not variable 0, and not defined by a gate.
    pub fn is_source(&self, v: u32) -> bool {
        v != 0 && !self.derived[v as usize]
    }
    /// The first gate the variable appears in.
    pub fn first_use(&self, v: u32) -> usize {
        self.uses[v as usize][0] as usize
    }
    pub fn uses(&self, v: u32) -> &[u32] {
        &self.uses[v as usize]
    }

    fn residue(&self, i: usize, at: impl Fn(u32) -> Fr) -> Fr {
        let g = &self.gates[i];
        let [a, b, c] = g.w.map(at);
        let mut e = g.q[QL] * a + g.q[QR] * b + g.q[QO] * c + g.q[QM] * a * b + g.q[QC];
        if i < self.publics.len() {
            e -= self.publics[i];
        }
        e
    }

    /// Does setting `v` to `to`, and nothing else, leave a gate unsatisfied?
    pub fn breaks_alone(&self, v: u32, to: Fr) -> bool {
        let at = |w: u32| if w == v { to } else { self.cs.values()[w as usize] };
        self.uses[v as usize].iter().any(|&i| !self.residue(i as usize, at).is_zero())
    }

    /// Sets `v` to `to`, recomputes every variable a later gate defines, and returns the first gate
    /// left unsatisfied. `None`: the change went through, the variable is free (for this value).
    pub fn first_break(&mut self, v: u32, to: Fr) -> Option<usize> {
        self.first_break_of(&[(v, to)])
    }

    /// The same for several variables changed together (a hand-made assignment).
    pub fn first_break_of(&mut self, changes: &[(u32, Fr)]) -> Option<usize> {
        let mut undo: Vec<(u32, Fr)> = Vec::new();
        let mut start = usize::MAX;
        for &(v, to) in changes {
            undo.push((v, self.work[v as usize]));
            self.work[v as usize] = to;
            start = start.min(self.first_use(v));
        }
        let pinned = |x: u32| changes.iter().any(|(v, _)| *v == x);
        let mut broken = None;
        for i in start..self.gates.len() {
            if let Some((c, scale)) = self.defines[i] {
                if !pinned(c) {
                    let g = &self.gates[i];
                    let [a, b] = [self.work[g.w[0] as usize], self.work[g.w[1] as usize]];
                    let value = (g.q[QL] * a + g.q[QR] * b + g.q[QM] * a * b + g.q[QC]) * scale;
                    if value != self.work[c as usize] {
                        undo.push((c, self.work[c as usize]));
                        self.work[c as usize] = value;
                    }
                    continue;
                }
            }
            let work = &self.work;
            if !self.residue(i, |w| work[w as usize]).is_zero() {
                broken = Some(i);
                break;
            }
        }
        for (x, old) in undo.into_iter().rev() {
            self.work[x as usize] = old;
        }
        broken
    }
}

/// The values a variable is moved to: one more, one less, 0, 1, and an unrelated one. For a bit this
/// includes its flip; for a coordinate it includes values on and off the curve.
pub fn mutations(x: Fr) -> Vec<Fr> {
    let mut out = Vec::new();
    for y in [x + Fr::one(), x - Fr::one(), Fr::zero(), Fr::one(), x * Fr::from(7u64) + Fr::from(3u64)] {
        if y != x && !out.contains(&y) {
            out.push(y);
        }
    }
    out
}
