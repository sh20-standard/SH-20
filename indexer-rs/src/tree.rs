//! The shared append-only note tree (SPEC-WIRE §2): depth 32, nodes `H(left, right)`,
//! empty leaf `0`, `Z[0] = 0`, `Z[i+1] = H(Z[i], Z[i])`.

use crate::field::h2;
use ark_bn254::Fr;
use ark_ff::Zero;

pub const DEPTH: usize = 32;
pub const CAPACITY: u64 = 1 << DEPTH;

/// What a block needs to put the tree back as it was: appends only touch the frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeSnapshot {
    size: u64,
    frontier: [Fr; DEPTH],
}

#[derive(Clone, Debug)]
pub struct Tree {
    /// `zeros[i]` = root of an empty subtree of height `i` (`zeros[32]` = the empty root).
    zeros: [Fr; DEPTH + 1],
    /// `frontier[i]` = the last completed left sibling at level `i`.
    frontier: [Fr; DEPTH],
    size: u64,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    pub fn new() -> Self {
        let mut zeros = [Fr::zero(); DEPTH + 1];
        for i in 0..DEPTH {
            zeros[i + 1] = h2(&zeros[i], &zeros[i]);
        }
        Tree { zeros, frontier: [Fr::zero(); DEPTH], size: 0 }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Leaves that can still be appended.
    pub fn room(&self) -> u64 {
        CAPACITY - self.size
    }

    pub fn empty_root(&self) -> Fr {
        self.zeros[DEPTH]
    }

    /// Appends a leaf and returns its position. The caller checks `room()` first.
    pub fn append(&mut self, leaf: Fr) -> u32 {
        assert!(self.size < CAPACITY, "note tree is full");
        let pos = self.size;
        let mut idx = pos;
        let mut cur = leaf;
        for level in 0..DEPTH {
            if idx & 1 == 0 {
                self.frontier[level] = cur;
                break;
            }
            cur = h2(&self.frontier[level], &cur);
            idx >>= 1;
        }
        self.size += 1;
        pos as u32
    }

    pub fn root(&self) -> Fr {
        let mut cur = self.zeros[0];
        let mut idx = self.size;
        for level in 0..DEPTH {
            cur = if idx & 1 == 1 { h2(&self.frontier[level], &cur) } else { h2(&cur, &self.zeros[level]) };
            idx >>= 1;
        }
        cur
    }

    pub fn snapshot(&self) -> TreeSnapshot {
        TreeSnapshot { size: self.size, frontier: self.frontier }
    }

    pub fn restore(&mut self, s: &TreeSnapshot) {
        self.size = s.size;
        self.frontier = s.frontier;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frontier root against a root computed the slow way over a small padded tree.
    #[test]
    fn frontier_matches_naive() {
        let mut t = Tree::new();
        let mut leaves: Vec<Fr> = Vec::new();
        for n in 0..37u64 {
            // naive: fold 64 leaves (depth 6), then lift with empty siblings
            let mut layer: Vec<Fr> = (0..64).map(|i| leaves.get(i).copied().unwrap_or(Fr::zero())).collect();
            while layer.len() > 1 {
                layer = layer.chunks(2).map(|p| h2(&p[0], &p[1])).collect();
            }
            let mut root = layer[0];
            for level in 6..DEPTH {
                root = h2(&root, &t.zeros[level]);
            }
            assert_eq!(t.root(), root, "size {n}");
            let leaf = Fr::from(1000 + n);
            assert_eq!(t.append(leaf) as u64, n);
            leaves.push(leaf);
        }
    }

    #[test]
    fn snapshot_restores() {
        let mut t = Tree::new();
        for n in 0..5u64 {
            t.append(Fr::from(n + 1));
        }
        let snap = t.snapshot();
        let root = t.root();
        for n in 0..9u64 {
            t.append(Fr::from(n + 77));
        }
        assert_ne!(t.root(), root);
        t.restore(&snap);
        assert_eq!(t.root(), root);
        assert_eq!(t.size(), 5);
    }
}
