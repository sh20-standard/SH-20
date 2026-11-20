// The vault's notes and the private sync: every leaf and nullifier downloaded, the vault's notes found
// on the device, their Merkle paths and spends checked locally.

import { defaultCache } from '../cache.js';
import { frHex } from '../fr.js';
import { Sync } from '../sync.js';
import { matchNotes } from '../match.js';
import { REFUSAL_DEPTH, refusedSpend } from '../send.js';
import { $, esplora, explorerTx, fill, h, indexer, indexers, report, short, st, staticWarnings, units } from './context.js';
import { agreementText, digestAgreement, refusalAgreed } from '../consensus.js';
import { balances } from './send-panel.js';
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
  const a = ss?.agreement;
  const agreement = a ? h('span', { id: 'agreement', class: a.disagree.length ? 'err' : a.agreed > 1 ? 'ok' : 'muted' }, agreementText(a)) : null;
  const bal = [...balances()].map(([t, v]) => `${units(v)} ${t}`).join(' · ');
  if (!st.vault) {
    fill('notes-body', h('p', { class: 'muted' }, 'Unlock the vault to see your notes.'));
    return;
  }
  const notes = st.vault.state.notes;
  if (!notes.length) {
    fill('notes-body', h('p', { class: 'muted' }, 'No note yet.'));
    return;
  }
  fill('notes-body', h('p', { id: 'balance' }, h('strong', {}, 'Balance: '), bal || 'nothing spendable yet', agreement ? ' — ' : null, agreement),
    h('div', { class: 'table-wrap' }, h('table', {},
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
 * Spends sent from this vault that the indexers refused (send.js refusedSpend): no nullifier was
 * recorded, so the notes they had reserved are given back. Only spends whose notes are all unspent
 * in the synced tree are looked up on Esplora. Returns the spends given back.
 */
async function settleRefused(s) {
  const v = st.vault;
  const back = [];
  for (const p of (v.state.pending ?? []).filter((x) => x.status === 'broadcast' && x.inputs?.length && x.revealTxid)) {
    if (!p.inputs.every((id) => v.state.notes.find((n) => n.id === id)?.spent === 'no')) continue;
    const rs = await esplora.txStatus(p.revealTxid).catch(() => null);
    const revealHeight = rs?.confirmed ? rs.block_height : null;
    if (!refusedSpend(p, v.state.notes, { revealHeight, syncHeight: s.height, nullifiersKnown: s.nullifiersKnown })) continue;
    // every indexer must agree, not only the primary this sync read: else the notes stay reserved, and the next sync asks again
    const nfs = await Promise.all(v.state.notes.filter((n) => p.inputs.includes(n.id)).map(async (n) => frHex(await v.nullifier(n))));
    const agreed = await refusalAgreed(indexers, nfs, { revealHeight, atLeast: revealHeight + REFUSAL_DEPTH - 1 });
    if (!agreed.ok) {
      await v.updatePending(p.id, { refusal: `looks refused, but ${agreed.why}: its notes stay reserved` });
      continue;
    }
    await v.releaseInputs(p.inputs);
    await v.updatePending(p.id, { status: 'refused by the indexers' });
    back.push(p);
  }
  return back;
}

/**
 * Private sync: downloads every leaf and every spent nullifier (only what is
 * new since the cached block), rebuilds the tree here, then finds the vault's
 * notes, their Merkle paths and their spends on the device.
 */
export async function syncNotes({ full = false } = {}) {
  const s = await getSyncer();
  const r = await s.sync(indexer, { full });
  // the other indexers' root and digest after the same block (AUDIT §8.5): shown next to the balance
  st.sync = { height: r.height, leaves: r.leaves, nullifiersKnown: r.nullifiersKnown, agreement: await digestAgreement(indexers, r.height, r.digest, r.root) };
  let found = 0;
  let failed = [];
  let refused = [];
  if (st.vault) {
    // a note whose scan throws does not stop the others; the sync's leaves from the first of them stay
    // unscanned, and the next sync reads them again (AUDIT §8.6)
    const m = await matchNotes(st.vault, r.notes, { onProgress: (d, n) => fill('sync-status', `Deriving note keys on this device: ${d} / ${n} (once per key)…`) });
    found = m.found;
    failed = m.failed;
    await s.scanned(failed[0]?.pos ?? null);
    await checkOwned(s);
    refused = await settleRefused(s);
    await syncListings();
  }
  renderAll();
  staticWarnings();
  processDeploys().catch(report);
  if (found) $('warnings').append(h('div', { class: 'warn' }, `${found} note(s) found in the tree.`));
  if (failed.length) {
    $('warnings').append(h('div', { class: 'warn err' }, `${failed.length} note(s) could not be scanned, from leaf ${failed[0].pos} (${failed[0].error.message}). The others were; the next sync reads these again.`));
  }
  for (const p of refused) {
    $('warnings').append(h('div', { class: 'warn' }, `The ${p.kind} of ${short(p.revealTxid)} was refused by the indexers: it spent none of your notes, and they are back in your balance (its network fees are lost).`));
  }
}
