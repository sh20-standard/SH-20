// The shared note tree, rebuilt on the device from every leaf of /notes.
// Same tree as indexer/src/tree.js (depth 32, nodes H(left, right) with
// circomlib Poseidon(2), empty subtree of height i = Z[i]); the tests check
// roots and paths against it. This version keeps every level, so appending k
// leaves costs about 2k + 32 hashes and a Merkle path costs none.

import { poseidon2, TREE_DEPTH } from './sh20.js';

const ZEROS = [0n];
for (let i = 0; i < TREE_DEPTH; i++) ZEROS.push(poseidon2(ZEROS[i], ZEROS[i]));

export class LocalTree {
  constructor() {
    this.levels = Array.from({ length: TREE_DEPTH + 1 }, () => []); // levels[0] = leaves
  }

  get size() {
    return this.levels[0].length;
  }

  get root() {
    return this.size ? this.levels[TREE_DEPTH][0] : ZEROS[TREE_DEPTH];
  }

  /** Recomputes every node that depends on leaves from position `start` on. */
  #rebuildFrom(start) {
    for (let l = 1; l <= TREE_DEPTH; l++) {
      const below = this.levels[l - 1];
      const here = this.levels[l];
      here.length = Math.ceil(below.length / 2);
      // division, not start >> l: shift counts are taken mod 32 (l reaches 32) and work on int32
      for (let j = Math.floor(start / 2 ** l); j < here.length; j++) {
        here[j] = poseidon2(below[2 * j], 2 * j + 1 < below.length ? below[2 * j + 1] : ZEROS[l - 1]);
      }
    }
  }

  append(leaves) {
    const start = this.size;
    if (start + leaves.length > 2 ** TREE_DEPTH) throw new Error('tree full');
    for (const x of leaves) this.levels[0].push(x);
    this.#rebuildFrom(start);
  }

  /** Keeps the first `n` leaves (reorg rollback). */
  truncate(n) {
    if (n >= this.size) return;
    this.levels[0].length = n;
    this.#rebuildFrom(n);
  }

  leaf(pos) {
    return this.levels[0][pos];
  }

  /** Siblings from the leaf up, as indexer/src/tree.js `path` returns them. */
  path(pos) {
    if (!(pos >= 0 && pos < this.size)) throw new Error('no such leaf');
    const siblings = [];
    for (let i = 0; i < TREE_DEPTH; i++) {
      const q = Math.floor(pos / 2 ** i); // no bit operators: they work on int32, positions reach 2^32 - 1
      const sib = q % 2 === 0 ? q + 1 : q - 1;
      siblings.push(sib < this.levels[i].length ? this.levels[i][sib] : ZEROS[i]);
    }
    return siblings;
  }
}

export { ZEROS };
