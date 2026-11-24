// The vault's notes and the private sync: every leaf and nullifier downloaded, the vault's notes found
// on the device, their Merkle paths and spends checked locally.

import { defaultCache } from '../cache.js';
import { frHex } from '../fr.js';
import { Sync } from '../sync.js';
import { matchNotes, noteKeysSeen } from '../match.js';
import { refusalAt, refusedSpend } from '../send.js';
import { $, NO_INDEXER, during, esplora, explorerTx, fill, h, indexer, indexers, report, short, st, staticWarnings, units } from './context.js';
import { agreementText, digestAgreement, refusalAgreed } from '../consensus.js';
import { balances } from './send-panel.js';
import { processDeploys } from './deploy-panel.js';
import { syncListings } from './market-panel.js';
import { renderAll } from './render.js';
import { PROFILE } from '../profile.js';

// ---- notes -----------------------------------------------------------------------

function spentText(n) {
  if (n.spent === undefined || n.spent === 'unknown') return n.pos === null ? '—' : 'unknown';
  return n.spent === 'no' ? 'no' : `yes, ${n.spent}`;
}

export function renderNotes() {
  const ss = st.sync;
  fill('sync-status', ss?.height === null
    ? ss.problem
      ? h('span', { class: 'err', id: 'before-a-problem' }, `The primary indexer says SH-20 has not started, which cannot be right: ${ss.problem}. Nothing is shown from it; check the indexers in Settings.`)
      : `SH-20 starts at block ${PROFILE.activationHeight.toLocaleString('en-US')}: the indexers have counted no block yet, so there is nothing to sync.`
    : ss
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
  // an indexer whose verifier is not the pinned PLONK one verifies no spend (consensus.js unverifiedSpends)
  const unverified = st.profile?.unverified?.length
    ? h('p', { class: 'err', id: 'balance-unverified' }, `Spends not verified: ${st.profile.unverified.map(({ base, why }) => `${base}: ${why}`).join('. ')}.`)
    : null;
  const notes = st.vault.state.notes;
  if (!notes.length) {
    fill('notes-body', h('p', { class: 'muted' }, 'No note yet.'), unverified);
    return;
  }
  fill('notes-body', h('p', { id: 'balance' }, h('strong', {}, 'Balance: '), bal || 'nothing spendable yet', agreement ? ' — ' : null, agreement),
    unverified,
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
  if (!indexer) throw new Error(NO_INDEXER);
  if (!syncer || syncer.base !== indexer.base) {
    syncer = new Sync(await defaultCache(), indexer.base);
    syncer.base = indexer.base;
    await syncer.load();
  }
  return syncer;
}

/**
 * Merkle path and spent status of every owned note, from the local tree and nullifier set only: no
 * request. With `rest`, only the notes not yet checked at this height: those the scan found or placed.
 * Nothing is written here: a path and a spent status are not stored, and what is (a note dropped, or
 * out of the tree) goes with the sync's one save (vault-3).
 */
async function checkOwned(s, { rest = false } = {}) {
  const v = st.vault;
  for (const n of [...v.state.notes]) {
    if (rest && n.pathAt === s.height) continue;
    if (n.pos === null || n.pos === undefined) continue;
    const leaf = BigInt('0x' + n.leaf);
    if (n.pos >= s.tree.size || s.tree.leaves[n.pos] !== leaf) {
      if (n.kind === 'sealed') await v.dropNote(n.id, { save: false }); // scanning finds it again wherever it now is
      else await v.updateNote(n.id, { status: 'not in tree (reorg?)', pos: null, pathAt: null, spent: undefined }, { save: false });
      continue;
    }
    s.witness(n.pos, leaf); // throws if the local path does not reach the local root
    const at = s.spentAt(frHex(await v.nullifier(n)));
    await v.updateNote(n.id, { pathAt: s.height, spent: at === undefined ? 'unknown' : at === null ? 'no' : `block ${at}` }, { save: false });
  }
}

/**
 * Spends sent from this vault that can no longer take the notes they reserved (send.js refusedSpend): refused by
 * the indexers, or never mined while their anchor left the window (vault-2). No nullifier was recorded, so the
 * notes are given back. Only spends whose notes are all unspent in the synced tree are looked up on Esplora.
 * Returns the spends given back, each with `expired` when it was never mined.
 */
async function settleRefused(s) {
  const v = st.vault;
  const back = [];
  for (const p of (v.state.pending ?? []).filter((x) => ['signed', 'commit broadcast', 'broadcast'].includes(x.status) && x.inputs?.length)) {
    if (!p.inputs.every((id) => v.state.notes.find((n) => n.id === id)?.spent === 'no')) continue;
    const rs = p.revealTxid ? await esplora.txStatus(p.revealTxid).catch(() => null) : null;
    const revealHeight = rs?.confirmed ? rs.block_height : null;
    if (!refusedSpend(p, v.state.notes, { revealHeight, syncHeight: s.height, nullifiersKnown: s.nullifiersKnown })) continue;
    // every indexer must agree, not only the primary this sync read: else the notes stay reserved, and the next sync asks again
    const inputs = v.state.notes.filter((n) => p.inputs.includes(n.id));
    const nfs = await Promise.all(inputs.map(async (n) => frHex(await v.nullifier(n))));
    const agreed = await refusalAgreed(indexers, nfs, { atLeast: refusalAt(p, revealHeight) }); // their full lists, from block 0
    const expired = revealHeight === null;
    if (!agreed.ok) {
      await v.updatePending(p.id, { refusal: `looks ${expired ? 'expired' : 'refused'}, but ${agreed.why}: its notes stay reserved` });
      continue;
    }
    await v.releaseInputs(p.inputs);
    await v.updatePending(p.id, { status: expired ? 'expired: never mined, its anchor left the window' : 'refused by the indexers' });
    back.push({ ...p, expired });
  }
  return back;
}

/**
 * Why the primary's "no block yet" (/status height null) cannot be right, or null: the chain's tip is at
 * or past A (Esplora), or another indexer has counted blocks, or reports another digest before A.
 */
export async function beforeAProblem() {
  const A = PROFILE.activationHeight;
  const tip = await esplora.tipHeight().catch(() => null);
  if (Number.isInteger(tip) && tip >= A) return `the chain is at block ${tip.toLocaleString('en-US')}, past block ${A.toLocaleString('en-US')} where SH-20 starts, but ${indexer.base} says it has counted no block`;
  const [mine, ...others] = await Promise.allSettled(indexers.map((i) => i.status()));
  for (const [k, o] of others.entries()) {
    if (o.status !== 'fulfilled') continue;
    const base = indexers[k + 1].base;
    if (o.value.height !== null) return `${base} has counted blocks up to ${o.value.height}, but ${indexer.base} says it has none`;
    if (mine.status === 'fulfilled' && o.value.digest !== mine.value.digest) return `${base} and ${indexer.base} disagree on the state before block ${A.toLocaleString('en-US')}`;
  }
  return null;
}

/**
 * Private sync: downloads every leaf and every spent nullifier (only what is
 * new since the cached block), rebuilds the tree here, then finds the vault's
 * notes, their Merkle paths and their spends on the device.
 */
export async function syncNotes(opts) {
  return during(() => syncOnce(opts)); // the vault does not lock itself in the middle of a sync
}

async function syncOnce({ full = false } = {}) {
  const s = await getSyncer();
  // a restored vault reads every leaf until it has checked its public-note keys (AUDIT §8.9)
  const r = await s.sync(indexer, { full: full || !!st.vault?.state.unchecked?.notes });
  if (r.height === null) {
    // before block A: no note, no spend and no listing exists yet (a restored vault's counters stay unchecked).
    // The primary's word is checked against the chain's tip and the other indexers: one that says "no block"
    // while the chain or another indexer is past A would hide the vault's notes behind "not started yet"
    st.sync = { height: null, problem: await beforeAProblem() };
    renderAll();
    staticWarnings();
    return;
  }
  // the other indexers' root and digest after the same block (AUDIT §8.5): shown next to the balance
  st.sync = { height: r.height, leaves: r.leaves, nullifiersKnown: r.nullifiersKnown, agreement: await digestAgreement(indexers, r.height, r.digest, r.root) };
  let found = 0;
  let failed = [];
  let refused = [];
  if (st.vault) {
    // Every request of this sync goes out before the scan, and none after it (docs/audit/2026-11-24-sealing.md,
    // sealing-1). An output that opens costs its owner about 0.2 s and one that does not a fraction of a
    // millisecond, and the pkEph and ct of a leaf are the indexer's word: a request that waited on the scan
    // would tell the indexer, by its clock, whether this vault holds an address and how many outputs are its
    // own. None of what follows needs the scan: the notes held already (their paths, their spends, the spends
    // refused), the listings, the DEPLOY reveals, and the other indexers' /notes a restored vault counts.
    await checkOwned(s); // and a sealed note whose leaf moved is dropped before the scan, which finds it again (sealing-8)
    refused = await settleRefused(s);
    await syncListings();
    await processDeploys().catch(report);
    const counting = r.from === 0 && !st.sync.agreement.disagree.length && st.vault.state.unchecked?.notes;
    const others = counting ? await Promise.allSettled(indexers.slice(1).map((i) => i.notes(0))) : null;
    // the scan, on this device, with no request until the next sync. A note whose scan throws does not stop the
    // others; the sync's leaves from the first of them stay unscanned, and the next sync reads them again (AUDIT §8.6)
    const m = await matchNotes(st.vault, r.notes, { defer: true, onProgress: (d, n) => fill('sync-status', `Deriving note keys on this device: ${d} / ${n} (once per key)…`) });
    found = m.found;
    failed = m.failed;
    // every leaf read and matched: a restored vault knows the public-note keys it used (AUDIT §8.9),
    // once no other indexer disagrees with the state those leaves come from, and the keys every other
    // indexer names in its own /notes are counted too (one whose labels hide a key cannot keep it back)
    if (others && !failed.length) {
      for (const o of others) if (o.status === 'fulfilled') await noteKeysSeen(st.vault, o.value);
      if (others.every((o) => o.status === 'fulfilled')) await st.vault.chainChecked('notes');
    }
    await checkOwned(s, { rest: true }); // the notes the scan found, or gave a position
    // one write for the sync (vault-3): the notes found or changed, then the vault's record; and only then are the
    // leaves marked scanned, so that a note found is never lost to a page closed in between
    await st.vault.save();
    await s.scanned(failed[0]?.pos ?? null);
  }
  renderAll();
  staticWarnings();
  if (found) $('warnings').append(h('div', { class: 'warn' }, `${found} note(s) found in the tree.`));
  if (failed.length) {
    $('warnings').append(h('div', { class: 'warn err' }, `${failed.length} note(s) could not be scanned, from leaf ${failed[0].pos} (${failed[0].error.message}). The others were; the next sync reads these again.`));
  }
  for (const p of refused) {
    $('warnings').append(h('div', { class: 'warn' }, p.expired
      ? `The ${p.kind} of ${short(p.revealTxid ?? p.commitTxid ?? '')} was never mined, and its anchor is now out of the window: no block can take it any more. It spent none of your notes, and they are back in your balance.`
      : `The ${p.kind} of ${short(p.revealTxid)} was refused by the indexers: it spent none of your notes, and they are back in your balance (its network fees are lost).`));
  }
}
