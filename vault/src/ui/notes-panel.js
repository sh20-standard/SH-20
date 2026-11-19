// The vault's notes and the private sync: every leaf and nullifier downloaded, the vault's notes found
// on the device, their Merkle paths and spends checked locally.

import { defaultCache } from '../cache.js';
import { frHex } from '../fr.js';
import { PUBLIC_RHO, noteLeaf, tickerT } from '../sh20.js';
import { Sync } from '../sync.js';
import { $, explorerTx, fill, h, indexer, report, short, st, staticWarnings, units } from './context.js';
import { processDeploys } from './deploy-panel.js';
import { syncListings } from './market-panel.js';
import { renderAll } from './render.js';

// ---- notes -----------------------------------------------------------------------

function spentText(n) {
  if (n.spent === undefined || n.spent === 'unknown') return n.pos === null ? '—' : 'unknown';
  return n.spent === 'no' ? 'no' : `yes, ${n.spent}`;
}

export function renderNotes() {
  const ss = st.sync;
  fill('sync-status', ss
    ? [`Synced to block ${ss.height}: ${ss.leaves} leaves, rebuilt here; the root matches the indexer. `,
      ss.nullifiersKnown ? 'Spends from the full nullifier list.' : h('span', { class: 'err' }, 'This indexer has no /nullifiers yet: spends unknown.')]
    : 'Not synced yet.');
  if (!st.vault) {
    fill('notes-body', h('p', { class: 'muted' }, 'Unlock the vault to see your notes.'));
    return;
  }
  const notes = st.vault.state.notes;
  if (!notes.length) {
    fill('notes-body', h('p', { class: 'muted' }, 'No note yet.'));
    return;
  }
  fill('notes-body', h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Ticker', 'Amount', 'Status', 'Position', 'Merkle path', 'Spent', 'Transaction', 'Key'].map((x) => h('th', {}, x)))),
    h('tbody', {}, notes.map((n) => h('tr', {},
      h('td', {}, n.ticker),
      h('td', { class: 'num' }, units(n.v)),
      h('td', { class: n.status === 'in tree' ? 'ok' : '' }, n.status),
      h('td', { class: 'num' }, n.pos ?? '—'),
      h('td', {}, n.pathAt ? `checked at block ${n.pathAt}` : '—'),
      h('td', {}, spentText(n)),
      h('td', {}, n.txid ? h('a', { href: explorerTx(n.txid), target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, short(n.txid)) : '—'),
      h('td', { class: 'muted' }, n.kind === 'sealed' ? 'received, sealed' : `public #${n.index}`)))))));
}

let syncer = null;

export async function getSyncer() {
  if (!syncer || syncer.base !== indexer.base) {
    syncer = new Sync(await defaultCache(), indexer.base);
    syncer.base = indexer.base;
    await syncer.load();
  }
  return syncer;
}

/**
 * Finds the vault's notes among the notes read by a sync, on the device (docs/SPEC-NOTES.md §4, §5):
 * public notes by npk (leaf recomputed with rho = 0), sealed outputs by opening them with the
 * viewing key (leaf checked by circuit/js). Notes are told apart by position, never by leaf.
 */
async function matchNotes(pub) {
  const v = st.vault;
  let found = 0;
  for (const n of pub) if (n.kind === 'OUT' && n.pkEph && n.ct && n.leaf !== null && n.pos !== null && (await v.receive(n))) found++;
  // public notes: repeat while a match moves the window of keys to look for (a restore)
  for (let before = -1; before !== v.state.next;) {
    before = v.state.next;
    const keys = await v.npkWindow({ onProgress: (d, n) => fill('sync-status', `Deriving note keys on this device: ${d} / ${n} (once per key)…`) });
    for (const n of pub) {
      if (n.kind === 'OUT' || n.npk === null || n.ticker === null || n.v === null || n.pos === null) continue;
      const index = keys.get(frHex(n.npk));
      if (index === undefined) continue;
      // never trust the API's (ticker, v) alone: they must give back the leaf it put in the tree
      const leaf = frHex(noteLeaf(tickerT(n.ticker), n.v, n.npk, PUBLIC_RHO));
      if (n.leaf !== null && frHex(n.leaf) !== leaf) continue;
      const txid = n.txid ? { txid: n.txid } : {};
      const here = v.state.notes.find((x) => x.pos === n.pos);
      if (here) {
        if (here.leaf === leaf && here.status !== 'in tree' && here.status !== 'spending') {
          await v.updateNote(here.id, { status: 'in tree', ...txid });
          found++;
        }
        continue;
      }
      // our own mint confirmed; its amount is the indexer's when a late batch got fewer than k mints
      const pending = v.state.notes.find((x) => x.kind === 'public' && x.index === index && x.pos === null);
      if (pending) await v.updateNote(pending.id, { status: 'in tree', pos: n.pos, ticker: n.ticker, v: n.v.toString(), leaf, ...txid });
      else await v.addNote({ index, ticker: n.ticker, v: n.v, txid: n.txid, status: 'in tree', pos: n.pos });
      found++;
    }
  }
  return found;
}

/** Merkle path and spent status of every owned note, from the local tree and nullifier set only. */
async function checkOwned(s) {
  const v = st.vault;
  for (const n of [...v.state.notes]) {
    if (n.pos === null || n.pos === undefined) continue;
    const leaf = BigInt('0x' + n.leaf);
    if (n.pos >= s.tree.size || s.tree.leaves[n.pos] !== leaf) {
      if (n.kind === 'sealed') await v.dropNote(n.id); // scanning finds it again wherever it now is
      else await v.updateNote(n.id, { status: 'not in tree (reorg?)', pos: null, pathAt: null, spent: undefined });
      continue;
    }
    s.witness(n.pos, leaf); // throws if the local path does not reach the local root
    const at = s.spentAt(frHex(await v.nullifier(n)));
    await v.updateNote(n.id, { pathAt: s.height, spent: at === undefined ? 'unknown' : at === null ? 'no' : `block ${at}` });
  }
}

/**
 * Private sync: downloads every leaf and every spent nullifier (only what is
 * new since the cached block), rebuilds the tree here, then finds the vault's
 * notes, their Merkle paths and their spends on the device.
 */
export async function syncNotes({ full = false } = {}) {
  const s = await getSyncer();
  const r = await s.sync(indexer, { full });
  st.sync = { height: r.height, leaves: r.leaves, nullifiersKnown: r.nullifiersKnown };
  let found = 0;
  if (st.vault) {
    // a scan that throws leaves the sync's notes unscanned: the next sync reads them again (AUDIT §8.6)
    found = await matchNotes(r.notes);
    await s.scanned();
    await checkOwned(s);
    await syncListings();
  }
  renderAll();
  staticWarnings();
  processDeploys().catch(report);
  if (found) $('warnings').append(h('div', { class: 'warn' }, `${found} note(s) found in the tree.`));
}
