// The market panel: the vault's listings (offers, cancel, claim) and buying from an offer.

import { toHex } from '../bytes.js';
import { scriptToAddress } from '../btc.js';
import { frHex } from '../fr.js';
import { loadProver } from '../prover.js';
import { LOCK_GAP } from '../keys.js';
import { buildCancel, buildClaim, buildTake, claimProblem, decodeOffer, encodeOffer, listingFromChain, offerTerms, offerValid, signOffer } from '../market.js';
import { busy, esplora, fill, h, indexer, indexers, requireProfile, result, resultBox, sats, short, st, units } from './context.js';
import { renderAll } from './render.js';
import { sendForm } from './send-panel.js';
import { signFunded, txLink, walletUtxos } from './spends.js';
import { listingCheck, TAKE_QUORUM } from '../consensus.js';
import { getSyncer } from './notes-panel.js';

// ---- market: the vault's listings, and buying from an offer --------------------------------------

/**
 * Brings the vault's listings up to date from the indexer's full list (never asking about one
 * listing of its own), and finds them again after a restore by their lock keys.
 */
export async function syncListings() {
  const v = st.vault;
  if (!v) return;
  let all;
  try {
    all = await indexer.listings();
  } catch {
    return; // an indexer without /listings: states stay as they were
  }
  const byTxid = new Map(all.filter((l) => l.listTxid).map((l) => [l.listTxid, l]));
  for (const rec of v.state.listings ?? []) {
    const l = byTxid.get(rec.listTxid);
    if (l && l.state !== rec.state) await v.updateListing(rec.id, { state: l.state });
  }
  const known = new Set((v.state.listings ?? []).map((r) => r.listTxid));
  const keys = new Map();
  for (let i = 0; i < (v.state.nextLock ?? 0) + LOCK_GAP; i++) keys.set(toHex((await v.lockOutput(i)).key), i);
  for (const l of all) {
    const i = keys.get(l.lockKey);
    if (i === undefined || known.has(l.listTxid)) continue;
    // found again by its lock key: its terms come from the LIST on chain, not from the indexer's word
    let chain;
    try {
      chain = listingFromChain(l.listTxid, await esplora.txHex(l.listTxid), { ...l, amount: String(l.amount), price: String(l.price) });
    } catch {
      continue;
    }
    if ((v.state.nextLock ?? 0) <= i) v.state.nextLock = i + 1; // before addListing saves: a lock key is never used twice
    await v.addListing({ lockIndex: i, ticker: chain.ticker, amount: String(chain.amount), price: String(chain.price), payScript: toHex(chain.payScript), listTxid: l.listTxid, state: l.state, source: 'chain' });
  }
}

/**
 * A listing read from the chain and reported the same way by every indexer that answers; one that
 * answers "unknown" refuses it (consensus.js listingCheck, docs/AUDIT.md §8.3). `enough` says
 * whether TAKE_QUORUM of them agree, which a TAKE needs.
 */
async function checkedListing(listTxid) {
  const { listing: indexed, agreed, down, enough } = await listingCheck(indexers, listTxid);
  const l = listingFromChain(listTxid, await esplora.txHex(listTxid), { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
  return { l, state: indexed.state, agreed, down, enough };
}

/**
 * One of the vault's own listings, from the indexer's full list (asking /listing/:txid would tell
 * the indexer it is ours) and the LIST transaction this vault sent (else fetched from Esplora).
 */
async function ownListing(rec) {
  const indexed = (await indexer.listings()).find((l) => l.listTxid === rec.listTxid);
  if (!indexed) throw new Error('the indexer does not list it (yet): sync after the next block');
  const sent = (st.vault.state.pending ?? []).find((p) => p.revealTxid === rec.listTxid)?.revealHex;
  const l = listingFromChain(rec.listTxid, sent ?? (await esplora.txHex(rec.listTxid)), { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
  return { l, state: indexed.state };
}

const marketForm = { offer: '', checked: null };

export function renderMarket() {
  if (!st.vault) return fill('market-body', h('p', { class: 'muted' }, 'Unlock the vault to trade.'));
  const mine = st.vault.state.listings ?? [];
  const rows = mine.map((rec) => {
    const act = [];
    if (rec.state === 'ACTIVE') {
      const offer = h('button', { type: 'button', class: 'small', name: 'offer' }, 'Copy offer');
      offer.addEventListener('click', busy(offer, () => copyOffer(rec)));
      const cancel = h('button', { type: 'button', class: 'small secondary', disabled: !st.wallet, name: 'cancel' }, 'Cancel');
      cancel.addEventListener('click', busy(cancel, () => sendCancel(rec)));
      act.push(offer, ' ', cancel);
    } else if (rec.state === 'CLOSED') {
      const claim = h('button', { type: 'button', class: 'small', disabled: !st.wallet, name: 'claim' }, 'Claim back');
      claim.addEventListener('click', busy(claim, () => sendClaim(rec)));
      act.push(claim);
    }
    return h('tr', {},
      h('td', {}, rec.ticker), h('td', { class: 'num' }, units(rec.amount)), h('td', { class: 'num' }, sats(rec.price)),
      h('td', {}, rec.state), h('td', { class: 'mono' }, short(rec.listTxid)), h('td', {}, act));
  });
  const offer = h('textarea', { rows: '2', name: 'offer', spellcheck: 'false', placeholder: 'sh20offer1:…' }, marketForm.offer);
  offer.addEventListener('input', () => { marketForm.offer = offer.value; marketForm.checked = null; });
  const check = h('button', { type: 'button', class: 'secondary', name: 'check' }, 'Check the offer');
  check.addEventListener('click', busy(check, checkOffer));
  const c = marketForm.checked;
  let buy = null;
  if (c) {
    buy = h('button', { type: 'button', disabled: !st.wallet || c.state !== 'ACTIVE' || !c.enough, name: 'buy', title: c.enough ? null : `a TAKE needs ${TAKE_QUORUM} indexers that report this listing` }, `Buy ${units(c.l.amount)} ${c.l.ticker} for ${sats(c.l.price)}`);
    buy.addEventListener('click', busy(buy, () => sendTake(c)));
  }
  fill('market-body',
    h('h3', {}, 'Your listings'),
    rows.length
      ? h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Ticker', 'Amount', 'Price', 'State', 'Listing', ''].map((x) => h('th', {}, x)))), h('tbody', {}, rows)))
      : h('p', { class: 'muted' }, 'None. List tokens from the panel above (Sell for BTC).'),
    resultBox('listing-out'),
    h('h3', {}, 'Buy from an offer'),
    h('label', {}, 'Offer (a line the seller shared)', offer),
    h('div', { class: 'row' }, check),
    c ? h('dl', {},
      h('dt', {}, 'Tokens'), h('dd', {}, `${units(c.l.amount)} ${c.l.ticker}, as a public note of this vault`),
      h('dt', {}, 'Price'), h('dd', {}, `${sats(c.l.price)} to ${payee(c.l.payScript)}`),
      h('dt', {}, 'State'), h('dd', {}, c.state),
      h('dt', {}, 'Checked'), h('dd', {}, `the LIST on chain, the seller's signature for this price and payee, ${c.agreed} indexer${c.agreed > 1 ? 's' : ''} ${c.agreed > 1 ? 'agree' : 'knows it'}${c.down.length ? ` (${c.down.length} unreachable, not counted)` : ''}`)) : null,
    c && !c.enough ? h('p', { class: 'warn err' }, `Not enough to buy: ${c.agreed} indexer${c.agreed > 1 ? 's' : ''} ${c.agreed > 1 ? 'report' : 'reports'} this listing, and a TAKE needs ${TAKE_QUORUM} that agree. The chain alone cannot show whether the indexers accepted the LIST; one indexer could report a listing the others rejected, and the price would be paid for nothing. Add an independent indexer in Settings.`) : null,
    buy,
    resultBox('buy-out'));
}

const payee = (script) => scriptToAddress(script) ?? `script ${toHex(script)}`;

/**
 * Signs an offer for one of the vault's listings, for terms it can vouch for (market.js offerTerms,
 * docs/AUDIT.md §8.2): its own record, or the LIST's proof over notes of this vault; failing both,
 * only once the user has read the price and payee and said yes.
 */
async function copyOffer(rec) {
  const v = st.vault;
  const { l } = await ownListing(rec);
  const lock = await v.lockOutput(rec.lockIndex);
  const ownNullifiers = new Set();
  for (const n of v.state.notes) if (n.pos !== null && n.pos !== undefined) ownNullifiers.add(frHex(await v.nullifier(n)));
  const s = await getSyncer();
  const t = await offerTerms({
    rec, l, lockKey: lock.key, ownNullifiers, rootAt: (a) => s.rootAt(a),
    verify: async (publics, proof) => (await loadProver({ onStatus: (x) => result('listing-out', h('p', { class: 'muted' }, `Checking the LIST's proof: ${x}`)) })).verify(publics, proof),
  });
  const terms = `${units(l.amount)} ${l.ticker} for ${sats(l.price)}, paid to ${payee(l.payScript)}`;
  if (t.vouched === 'ask' && !confirm(`This vault cannot vouch for the terms of this listing: ${t.why}.\n\nSign an offer that sells\n\n${terms}?\n\nWhoever holds the offer can take the tokens by paying that price to that address. Sign only if this is the listing you made.`)) {
    result('listing-out', h('p', { class: 'muted' }, 'No offer signed.'));
    return;
  }
  const offer = encodeOffer(rec.listTxid, signOffer(lock.secret, l));
  await navigator.clipboard?.writeText(offer).catch(() => {});
  const by = { record: 'the listing this vault sent', proof: 'the LIST\'s proof, which spends notes of this vault', ask: 'your confirmation only' }[t.vouched];
  result('listing-out',
    h('p', {}, h('strong', {}, 'Offer signed for: '), terms, '.'),
    h('p', { class: 'muted' }, `Terms vouched for by ${by}. Anyone who completes the offer pays that price to that address and gets the tokens. Share it anywhere.`),
    h('p', { class: 'mono', id: 'offer-text' }, offer));
}

async function checkOffer() {
  const { listTxid, sig } = decodeOffer(marketForm.offer);
  const c = await checkedListing(listTxid);
  if (!offerValid(c.l, sig)) throw new Error('the offer is not signed by the listing\'s lock key for this price and payee');
  marketForm.checked = { ...c, sig };
  renderMarket();
}

/** Signs a transaction with a pre-signed or vault-signed lock input, broadcasts it, records the public note. */
async function sendFunded(m, outId, label, note) {
  await requireProfile(); // a TAKE, a cancel, a CLAIM: only with indexers on the vault's profile
  const done = await signFunded(m);
  const id = await esplora.broadcast(done.hex);
  if (note) await st.vault.addNote({ ...note, txid: id, status: 'broadcast' });
  renderAll();
  result(outId, h('p', { class: 'ok' }, `${label}: broadcast (${done.vsize} vB).`), txLink(id), h('p', { class: 'muted' }, 'Sync after the next block to see the note.'));
}

async function sendTake(c) {
  const fresh = await checkedListing(c.l.listTxid); // still ACTIVE, same terms, now
  if (fresh.state !== 'ACTIVE') throw new Error(`the listing is ${fresh.state} now`);
  if (!fresh.enough) throw new Error(`not bought: ${fresh.agreed} indexer${fresh.agreed > 1 ? 's' : ''} ${fresh.agreed > 1 ? 'report' : 'reports'} this listing, and a TAKE needs ${TAKE_QUORUM} that agree (add one in Settings)`);
  const tip = await esplora.tipHeight();
  const o = await st.vault.reserveNote(); // the tokens come as this public note
  const m = buildTake({ l: fresh.l, sig: c.sig, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: tip });
  if (!confirm(`Pay ${sats(fresh.l.price)} plus ${sats(m.fee)} of fees for ${units(fresh.l.amount)} ${fresh.l.ticker}?`)) return;
  await sendFunded(m, 'buy-out', `TAKE of ${units(fresh.l.amount)} ${fresh.l.ticker}`, { index: o.index, ticker: fresh.l.ticker, v: fresh.l.amount });
  marketForm.checked = null;
}

async function sendCancel(rec) {
  const { l, state } = await ownListing(rec);
  if (state !== 'ACTIVE') throw new Error(`the listing is ${state}`);
  if (!confirm(`Take ${units(l.amount)} ${l.ticker} back? The listing ends.`)) return;
  const o = await st.vault.reserveNote();
  const m = buildCancel({ l, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: await esplora.tipHeight() });
  await sendFunded(m, 'listing-out', `Cancel of ${units(l.amount)} ${l.ticker}`, { index: o.index, ticker: l.ticker, v: l.amount });
}

async function sendClaim(rec) {
  // CLOSED by every configured indexer (their full lists, never a question about this listing), and on
  // chain: the lock spent by a transaction with no TAKE. Else the CLAIM would be rejected and its fees lost.
  const lists = await Promise.allSettled(indexers.map((a) => a.listings()));
  const states = lists.filter((r) => r.status === 'fulfilled').map((r) => r.value.find((x) => x.listTxid === rec.listTxid)?.state ?? 'unknown');
  if (!states.length || states.some((s) => s !== 'CLOSED')) throw new Error(`not claimed: the indexers say ${[...new Set(states)].join(', ') || 'nothing'}, not CLOSED everywhere`);
  const { l } = await ownListing(rec);
  const out = await esplora.outspend(l.listTxid, l.lockVout);
  const problem = claimProblem(l, out.spent && out.txid ? await esplora.txHex(out.txid) : null);
  if (problem) throw new Error(`not claimed: ${problem}`);
  const o = await st.vault.reserveNote();
  const m = buildClaim({ listTxid: rec.listTxid, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: Number(sendForm.fee) || 2, tipHeight: await esplora.tipHeight() });
  await sendFunded(m, 'listing-out', `CLAIM of ${units(rec.amount)} ${rec.ticker}`, { index: o.index, ticker: rec.ticker, v: BigInt(rec.amount) });
}
