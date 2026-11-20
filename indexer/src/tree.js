// Append-only Merkle tree of note leaves, shared by every ticker.
// Depth 32, Poseidon nodes, empty leaf = 0.
//
// The tree keeps every complete subtree's root: levels[i][k] is the root of the k-th full subtree of height i
// (levels[0] are the leaves). An append hashes only the subtrees it completes, one hash on average instead of 32;
// the root and the nodes over the rightmost, unfinished subtree are computed when asked for, once per size. A path
// is then 32 lookups, and a rollback (reorg) is a truncation of each level.

import { poseidon2 } from './poseidon.js';
import { TREE_DEPTH } from './constants.js';

export class NoteTree {
  constructor(depth = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = [0n];
    for (let i = 0; i < depth; i++) this.zeros.push(poseidon2(this.zeros[i], this.zeros[i]));
    this.levels = Array.from({ length: depth + 1 }, () => []);
    this.partial = new Map(); // nodes over the unfinished subtree, for the current size: "level:index" -> node
  }

  get leaves() {
    return this.levels[0];
  }

  get size() {
    return this.levels[0].length;
  }

  get capacity() {
    return 2 ** this.depth;
  }

  get root() {
    return this.node(this.depth, 0);
  }

  /** Appends a leaf and returns its position. */
  append(leaf) {
    if (this.size >= this.capacity) throw new Error('tree full');
    const pos = this.size;
    this.levels[0].push(leaf);
    let cur = leaf;
    for (let i = 0, k = pos; k % 2 === 1; i++, k = (k - 1) / 2) {
      cur = poseidon2(this.levels[i][k - 1], cur); // this leaf completes the subtree k−1, k: its parent is final
      this.levels[i + 1].push(cur);
    }
    this.partial.clear();
    return pos;
  }

  /** The node at `level` (0 = leaves) and `index`: a complete subtree's root, a node over unfinished leaves, or a zero. */
  node(level, index) {
    const lv = this.levels[level];
    if (index < lv.length) return lv[index];
    if (level === 0 || index * 2 ** level >= this.size) return this.zeros[level];
    const key = `${level}:${index}`;
    let n = this.partial.get(key);
    if (n === undefined) {
      n = poseidon2(this.node(level - 1, 2 * index), this.node(level - 1, 2 * index + 1));
      this.partial.set(key, n);
    }
    return n;
  }

  /** A snapshot is the size: everything above it can be cut off. */
  snapshot() {
    return { size: this.size };
  }

  restore({ size }) {
    for (let i = 0; i <= this.depth; i++) this.levels[i].length = Math.floor(size / 2 ** i);
    this.partial.clear();
  }

  /** Sibling path of a leaf at the current root (for wallets): one node per level. */
  path(position) {
    if (position < 0 || position >= this.size) throw new Error('no such leaf');
    const siblings = [];
    for (let i = 0, idx = position; i < this.depth; i++, idx = Math.floor(idx / 2)) siblings.push(this.node(i, siblingIndex(idx)));
    return siblings;
  }
}

/** Index of a node's sibling. Plain arithmetic: JavaScript's `^` works on 32-bit signed
 *  integers and gives a wrong answer from position 2^31 on, while the tree holds 2^32 leaves. */
export const siblingIndex = (i) => (i % 2 === 0 ? i + 1 : i - 1);

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
