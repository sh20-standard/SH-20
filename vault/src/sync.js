// Private sync: the vault downloads public data in bulk and works out on the
// device what is its own. It reads /status, every leaf of /notes and every
// spent nullifier of /nullifiers; it never asks /path/:pos or /nullifier/:hex,
// which would tell the indexer which notes are the user's (docs/API.md).
//
// The tree is rebuilt locally with the indexer's own NoteTree (indexer/src/tree.js: an append hashes only
// the subtrees it completes, a path is 32 lookups, a reorg a truncation) and must hash to the indexer's
// root at the same height; Merkle paths for spends come from that local tree.
// Leaves and nullifiers are cached; each sync re-reads only the last few blocks
// (REORG_MARGIN) plus new ones. A deeper reorg shows up as a root mismatch and
// triggers one full re-download. Leaves the vault has not scanned yet (a sync while it was locked,
// or a scan that failed: docs/AUDIT.md §8.6) are read again until it says so (`scanned`).

import { NoteTree, rootFromPath } from './sh20.js';
import { frHex } from './fr.js';

export const REORG_MARGIN = 6; // blocks re-read on every sync
const FORMAT = 1;

const toBytes = (xs) => {
  const out = new Uint8Array(xs.length * 32);
  xs.forEach((x, i) => {
    const h = frHex(x);
    for (let k = 0; k < 32; k++) out[32 * i + k] = parseInt(h.slice(2 * k, 2 * k + 2), 16);
  });
  return out;
};
const fromBytes = (b) => {
  const out = [];
  for (let i = 0; i < b.length; i += 32) {
    let h = '';
    for (let k = 0; k < 32; k++) h += b[i + k].toString(16).padStart(2, '0');
    out.push(BigInt('0x' + h));
  }
  return out;
};

export class Sync {
  constructor(cache, key) {
    this.cache = cache;
    this.key = `sync:${key}`;
    this.reset();
  }

  reset() {
    this.tree = new NoteTree();
    this.leafHeights = []; // block of each leaf, to roll back the last blocks
    this.height = null; // indexer height of the last successful sync
    this.nullifiers = new Map(); // hex -> block height
    this.nullifiersKnown = false; // false until /nullifiers has answered once
    this.unscanned = null; // position of the first leaf the vault has not scanned, null when none
  }

  async load() {
    const c = await this.cache.get(this.key);
    if (!c || c.v !== FORMAT) return false;
    for (const leaf of fromBytes(c.leaves)) this.tree.append(leaf);
    if (frHex(this.tree.root) !== c.root) {
      this.reset(); // corrupted cache: start again
      return false;
    }
    this.leafHeights = Array.from(c.leafHeights);
    this.height = c.height;
    this.nullifiers = new Map(c.nullifiers);
    this.nullifiersKnown = c.nullifiersKnown;
    this.unscanned = Number.isInteger(c.unscanned) ? c.unscanned : null;
    return true;
  }

  async save() {
    await this.cache.set(this.key, {
      v: FORMAT,
      height: this.height,
      root: frHex(this.tree.root),
      leaves: toBytes(this.tree.leaves),
      leafHeights: Uint32Array.from(this.leafHeights),
      nullifiers: [...this.nullifiers],
      nullifiersKnown: this.nullifiersKnown,
      unscanned: this.unscanned,
    });
  }

  /**
   * Brings the local tree and nullifier set to the indexer's current height.
   * Returns the notes read in this sync (for matching the vault's own notes),
   * the height and whether the spent-nullifier list is available.
   */
  async sync(api, { full = false } = {}) {
    if (full) this.reset();
    const status = await api.status();
    const H = status.height;
    if (!Number.isInteger(H)) throw new Error('the indexer reports no height');
    if (this.height !== null && H < this.height - REORG_MARGIN) this.reset(); // indexer far behind us: start again

    // leaves: drop the last REORG_MARGIN blocks, read from there on, keep blocks ≤ H
    const keepBelow = this.height === null ? 0 : this.height - REORG_MARGIN + 1;
    let keep = this.leafHeights.findIndex((h) => h >= keepBelow);
    if (keep < 0) keep = this.leafHeights.length;
    if (this.unscanned !== null) keep = Math.min(keep, this.unscanned); // read again what the vault has not scanned
    if (keep < this.tree.size) this.tree.restore({ size: keep }); // drop the leaves of the re-read blocks
    this.leafHeights.length = keep;
    const notes = (await api.notes(keep)).filter((n) => n.height !== null && n.height <= H);
    const leaves = [];
    for (const n of notes) {
      if (n.pos !== keep + leaves.length || n.leaf === null) throw new Error(`the indexer's note list has a gap or no leaf at ${keep + leaves.length}`);
      leaves.push(n.leaf);
      this.leafHeights.push(n.height);
    }
    for (const leaf of leaves) this.tree.append(leaf);

    const want = String(status.root).toLowerCase();
    if (frHex(this.tree.root) !== want || (Number.isInteger(status.leaves) && status.leaves !== this.tree.size)) {
      if (keep > 0) return this.sync(api, { full: true }); // a reorg deeper than the margin, or a stale cache
      throw new Error(`the indexer's leaves do not hash to its own root at block ${H}: it is inconsistent or lying`);
    }

    // nullifiers: same window
    const nfFrom = this.height === null || !this.nullifiersKnown ? 0 : Math.max(0, this.height - REORG_MARGIN + 1);
    const list = await api.nullifiers(nfFrom);
    if (list === null) {
      this.nullifiersKnown = false; // indexer without /nullifiers: spent status unknown, never asked per note
    } else {
      for (const [nf, h] of this.nullifiers) if (h >= nfFrom) this.nullifiers.delete(nf);
      for (const { nullifier, height } of list) if (height <= H) this.nullifiers.set(nullifier, height);
      this.nullifiersKnown = true;
    }

    this.height = H;
    this.unscanned = keep < this.tree.size ? keep : null; // the notes returned stay unscanned until the vault says so
    await this.save();
    return { height: H, digest: status.digest ?? null, notes, leaves: this.tree.size, nullifiersKnown: this.nullifiersKnown };
  }

  /** The vault has scanned every note the last sync returned: the next one reads only the last blocks. */
  async scanned() {
    this.unscanned = null;
    await this.save();
  }

  /** Merkle witness of the leaf at `pos` from the local tree, checked against the local root. */
  witness(pos, leaf) {
    if (this.tree.leaves[pos] !== leaf) throw new Error(`leaf ${pos} is not the expected note`);
    const siblings = this.tree.path(pos);
    const root = this.tree.root;
    if (rootFromPath(leaf, pos, siblings) !== root) throw new Error('local Merkle path does not reach the root');
    return { pos, leaf, siblings, root, anchorHeight: this.height };
  }

  /**
   * The root of the tree at the end of block `height` (a spend's anchor), from the local leaves;
   * undefined past the synced height.
   */
  rootAt(height) {
    if (this.height === null || height > this.height) return undefined;
    let k = this.leafHeights.findIndex((h) => h > height);
    if (k < 0) k = this.leafHeights.length;
    const t = new NoteTree();
    for (const leaf of this.tree.leaves.slice(0, k)) t.append(leaf);
    return t.root;
  }

  /** Block height at which `nf` (hex) was spent, null if not seen, undefined if unknown. */
  spentAt(nf) {
    if (!this.nullifiersKnown) return undefined;
    return this.nullifiers.get(nf) ?? null;
  }
}
