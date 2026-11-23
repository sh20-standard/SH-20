// Finding the vault's notes among the notes a sync read, on the device (docs/SPEC-NOTES.md §4, §5).

import { frHex } from './fr.js';
import { PUBLIC_RHO, noteLeaf, tickerT } from './sh20.js';
import { LOCK_GAP } from './keys.js';
import { toHex } from './bytes.js';

/**
 * Public notes by npk (leaf recomputed with rho = 0), sealed outputs by opening them with the
 * viewing key (leaf checked by circuit/js). Notes are told apart by position, never by leaf.
 *
 * A note whose scan throws does not stop the others (docs/AUDIT.md §8.6): the rest are scanned, and
 * `failed` lists each one that threw, by position, with its error. The caller keeps the sync's
 * leaves from the first of them unscanned (`Sync.scanned(failed[0].pos)`), so the next sync reads
 * them again. Returns { found, failed }.
 */
export async function matchNotes(v, pub, { onProgress } = {}) {
  let found = 0;
  const failed = new Map(); // pos → the first error of that note
  const attempt = async (n, f) => {
    try {
      return await f();
    } catch (e) {
      if (!failed.has(n.pos)) failed.set(n.pos, e);
      return false;
    }
  };
  for (const n of pub) {
    if (n.kind !== 'OUT' || !n.pkEph || !n.ct || n.leaf === null || n.pos === null) continue;
    if (await attempt(n, () => v.receive(n))) found++;
  }
  // public notes: repeat while a match moves the window of keys to look for (a restore)
  for (let before = -1; before !== v.state.next;) {
    before = v.state.next;
    const keys = await v.npkWindow({ onProgress });
    for (const n of pub) {
      if (n.kind === 'OUT' || n.npk === null || n.ticker === null || n.v === null || n.pos === null) continue;
      if (await attempt(n, () => matchPublic(v, n, keys))) found++;
    }
  }
  return { found, failed: [...failed].sort(([a], [b]) => a - b).map(([pos, error]) => ({ pos, error })) };
}

/** Public-note key `index` is used, whatever the rest of what names it says: the counter moves past it (docs/AUDIT.md §8.9). */
function keyUsed(v, index) {
  if (v.state.next <= index) v.state.next = index + 1;
  if ((v.state.seenNext ?? 0) <= index) v.state.seenNext = index + 1;
}

async function matchPublic(v, n, keys) {
  const index = keys.get(frHex(n.npk));
  if (index === undefined) return false;
  keyUsed(v, index);
  // never trust the API's (ticker, v) alone: they must give back the leaf it put in the tree
  const leaf = frHex(noteLeaf(tickerT(n.ticker), n.v, n.npk, PUBLIC_RHO));
  if (n.leaf !== null && frHex(n.leaf) !== leaf) return false;
  const txid = n.txid ? { txid: n.txid } : {};
  const here = v.state.notes.find((x) => x.pos === n.pos);
  if (here) {
    if (here.leaf === leaf && here.status !== 'in tree' && here.status !== 'spending') {
      await v.updateNote(here.id, { status: 'in tree', ...txid });
      return true;
    }
    return false;
  }
  // our own mint confirmed; its amount is the indexer's when a late batch got fewer than k mints
  const pending = v.state.notes.find((x) => x.kind === 'public' && x.index === index && x.pos === null);
  if (pending) await v.updateNote(pending.id, { status: 'in tree', pos: n.pos, ticker: n.ticker, v: n.v.toString(), leaf, ...txid });
  else await v.addNote({ index, ticker: n.ticker, v: n.v, txid: n.txid, status: 'in tree', pos: n.pos });
  return true;
}

/**
 * The vault's public-note keys that `all` (another indexer's /notes, read whole) names, whatever its
 * kind, ticker or amount say: each one moves the counter (docs/AUDIT.md §8.9). Only the primary's notes
 * are matched and recorded, against the tree rebuilt here; which leaf is which key is metadata the
 * vault cannot check for a sealed output, so a primary that labels one of the vault's MINTs as sealed,
 * or leaves its npk out, could keep the counter back. A restored vault therefore counts the keys every
 * other indexer reports too, before its counters are checked. Repeats while the window moves.
 */
export async function noteKeysSeen(v, all, { onProgress } = {}) {
  for (let before = -1; before !== v.state.next;) {
    before = v.state.next;
    const keys = await v.npkWindow({ onProgress });
    for (const n of all) {
      if (n.npk === null || n.npk === undefined) continue;
      const index = keys.get(frHex(n.npk));
      if (index !== undefined) keyUsed(v, index);
    }
  }
}

/**
 * The vault's listings among `all` (an indexer's /listings), found by their lock keys: the vault's
 * next LOCK_GAP keys past the last one used, again while a match moves that window (a restore, from
 * an old backup or the words). A key found moves the counter on even when its LIST cannot be read
 * (docs/AUDIT.md §8.9: a lock key is never used twice); `fromChain(l)` reads the listing's terms from
 * its transaction, never from the indexer's word (§8.2). Returns how many were added.
 */
export async function matchListings(v, all, fromChain) {
  const known = new Set((v.state.listings ?? []).map((r) => r.listTxid));
  let found = 0;
  for (let before = -1; before !== (v.state.nextLock ?? 0);) {
    before = v.state.nextLock ?? 0;
    const keys = new Map();
    for (let i = 0; i < before + LOCK_GAP; i++) keys.set(toHex((await v.lockOutput(i)).key), i);
    for (const l of all) {
      const i = keys.get(l.lockKey);
      if (i === undefined || known.has(l.listTxid)) continue;
      if ((v.state.nextLock ?? 0) <= i) v.state.nextLock = i + 1; // before addListing saves
      let chain;
      try {
        chain = await fromChain(l);
      } catch {
        continue;
      }
      known.add(l.listTxid);
      await v.addListing({ lockIndex: i, ticker: chain.ticker, amount: String(chain.amount), price: String(chain.price), payScript: toHex(chain.payScript), listTxid: l.listTxid, state: l.state, source: 'chain' });
      found++;
    }
  }
  return found;
}
