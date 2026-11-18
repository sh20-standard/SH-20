// Append-only Merkle tree of note leaves, shared by every ticker.
// Depth 32, Poseidon nodes, empty leaf = 0. Snapshots make reorg rollback cheap.

import { poseidon2 } from './poseidon.js';
import { TREE_DEPTH } from './constants.js';

export class NoteTree {
  constructor(depth = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = [0n];
    for (let i = 0; i < depth; i++) this.zeros.push(poseidon2(this.zeros[i], this.zeros[i]));
    this.filled = this.zeros.slice(0, depth);
    this.leaves = [];
    this.root = this.zeros[depth];
  }

  get size() {
    return this.leaves.length;
  }

  get capacity() {
    return 2 ** this.depth;
  }

  /** Appends a leaf and returns its position. */
  append(leaf) {
    if (this.leaves.length >= this.capacity) throw new Error('tree full');
    let index = this.leaves.length;
    let cur = leaf;
    for (let i = 0; i < this.depth; i++) {
      if (index % 2 === 0) {
        this.filled[i] = cur;
        cur = poseidon2(cur, this.zeros[i]);
      } else {
        cur = poseidon2(this.filled[i], cur);
      }
      index = Math.floor(index / 2);
    }
    this.root = cur;
    this.leaves.push(leaf);
    return this.leaves.length - 1;
  }

  snapshot() {
    return { filled: this.filled.slice(), root: this.root, size: this.leaves.length };
  }

  restore(s) {
    this.filled = s.filled.slice();
    this.root = s.root;
    this.leaves.length = s.size;
  }

  /** Sibling path for a leaf at the current root (for wallets). O(size). */
  path(position) {
    if (position < 0 || position >= this.leaves.length) throw new Error('no such leaf');
    let level = this.leaves.slice();
    let idx = position;
    const siblings = [];
    for (let i = 0; i < this.depth; i++) {
      const sib = idx ^ 1;
      siblings.push(sib < level.length ? level[sib] : this.zeros[i]);
      const next = [];
      for (let k = 0; k < level.length; k += 2) {
        next.push(poseidon2(level[k], k + 1 < level.length ? level[k + 1] : this.zeros[i]));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }
    return siblings;
  }
}

/** Recomputes a root from a leaf and its path (what the circuit proves). */
export function rootFromPath(leaf, position, siblings) {
  let cur = leaf;
  let idx = position;
  for (const sib of siblings) {
    cur = idx % 2 === 0 ? poseidon2(cur, sib) : poseidon2(sib, cur);
    idx = Math.floor(idx / 2);
  }
  return cur;
}
