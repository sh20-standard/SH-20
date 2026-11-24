// The market panel: the vault's listings (offers, cancel, claim) and buying from an offer.

import { toHex } from '../bytes.js';
import { scriptToAddress } from '../btc.js';
import { frHex } from '../fr.js';
import { loadProver } from '../prover.js';
import { matchListings } from '../match.js';
import { buildCancel, buildClaim, buildTake, claimProblem, decodeOffer, encodeOffer, listingFromChain, offerTerms, offerValid, payeeProblem, signOffer } from '../market.js';
import { busy, esplora, feeRateOf, fill, h, indexer, indexers, requireProfile, result, resultBox, sats, short, st, units } from './context.js';
import { renderAll } from './render.js';
import { sendForm } from './send-panel.js';
import { signFunded, txLink, walletUtxos } from './spends.js';
import { PAY_DEPTH, listingCheck, payDepthProblem, TAKE_QUORUM } from '../consensus.js';
import { committedHex } from '../witness.js';
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
  // the lock keys are looked for in the lists of every indexer (AUDIT §8.9): one that leaves a listing
  // out cannot hide that its key is used, as long as another reports it
  const others = await Promise.allSettled(indexers.slice(1).map((i) => i.listings()));
  const union = new Map(all.filter((l) => l.listTxid).map((l) => [l.listTxid, l]));
  for (const r of others) if (r.status === 'fulfilled' && Array.isArray(r.value)) for (const l of r.value) if (l?.listTxid && !union.has(l.listTxid)) union.set(l.listTxid, l);
  // found again by its lock key: its terms come from the LIST on chain, not from the indexer's word
  await matchListings(v, [...union.values()], async (l) => listingFromChain(l.listTxid, await committedHex(esplora, l.listTxid), { ...l, amount: String(l.amount), price: String(l.price) }));
  // every list read: a restored vault may reserve lock keys again
  if (others.every((r) => r.status === 'fulfilled')) await v.chainChecked('locks');
}

/**
 * A listing read from the chain and reported the same way by every indexer that answers; one that
 * answers "unknown" refuses it (consensus.js listingCheck, docs/AUDIT.md §8.3). `enough` says
 * whether TAKE_QUORUM of them that verify spends agree (vault-16), which a TAKE needs; `deep` whether every one of them, and
 * Esplora, holds the LIST PAY_DEPTH blocks deep, which a TAKE needs too (vault-1), with `shallow`
 * saying why not.
 */
async function checkedListing(listTxid) {
  const { listing: indexed, agreed, verifying, down, enough, depth, depthProblem } = await listingCheck(indexers, listTxid);
  // the LIST's envelope as the chain committed to it (vault-6): the output it spends binds its witness
  const [hex, tx, tip] = await Promise.all([committedHex(esplora, listTxid), esplora.txStatus(listTxid), esplora.tipHeight()]);
  const l = listingFromChain(listTxid, hex, { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
  const shallow = depthProblem ?? payDepthProblem('the LIST transaction, at Esplora,', tx?.confirmed ? tx.block_height : null, tip);
  return { l, state: indexed.state, agreed, verifying, down, enough, depth, deep: !shallow, shallow };
}

/**
 * One of the vault's own listings, from the indexer's full list (asking /listing/:txid would tell
 * the indexer it is ours) and the LIST transaction this vault sent (else fetched from Esplora).
 */
async function ownListing(rec) {
  const indexed = (await indexer.listings()).find((l) => l.listTxid === rec.listTxid);
  if (!indexed) throw new Error('the indexer does not list it (yet): sync after the next block');
  const sent = (st.vault.state.pending ?? []).find((p) => p.revealTxid === rec.listTxid)?.revealHex;
  const l = listingFromChain(rec.listTxid, sent ?? (await committedHex(esplora, rec.listTxid)), { ...indexed, amount: String(indexed.amount), price: String(indexed.price) });
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
  const badPayee = c ? payeeProblem(c.l.payScript) : null; // a TAKE to it would not be relayed
  if (c) {
    buy = h('button', { type: 'button', disabled: !st.wallet || c.state !== 'ACTIVE' || !c.enough || !c.deep || !!badPayee, name: 'buy', title: badPayee ?? (!c.enough ? `a TAKE needs ${TAKE_QUORUM} indexers that verify spends and report this listing` : c.shallow) }, `Buy ${units(c.l.amount)} ${c.l.ticker} for ${sats(c.l.price)}`);
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
      h('dt', {}, 'Depth'), h('dd', { id: 'listing-depth' }, c.deep ? `the LIST is ${PAY_DEPTH} blocks deep or more everywhere` : `${c.depth > 0 ? `${c.depth} of ${PAY_DEPTH} blocks` : 'not confirmed'}: check the offer again after ${PAY_DEPTH - Math.max(c.depth, 0)} more block${PAY_DEPTH - Math.max(c.depth, 0) > 1 ? 's' : ''}`),
      h('dt', {}, 'Checked'), h('dd', {}, `the LIST on chain, the seller's signature for this price and payee, ${c.agreed} indexer${c.agreed > 1 ? 's' : ''} ${c.agreed > 1 ? 'agree' : 'knows it'}${c.down.length ? ` (${c.down.length} unreachable, not counted)` : ''}`)) : null,
    badPayee ? h('p', { class: 'warn err', id: 'payee-problem' }, `Cannot buy: ${badPayee}.`) : null,
    c && !c.enough ? h('p', { class: 'warn err' }, `Not enough to buy: ${c.agreed} indexer${c.agreed > 1 ? 's' : ''} ${c.agreed > 1 ? 'report' : 'reports'} this listing, ${c.verifying} of them verifying spends, and a TAKE needs ${TAKE_QUORUM} that verify spends and agree. An indexer that verifies no spend would vouch for a LIST whose proof is anything. The chain alone cannot show whether the indexers accepted the LIST; one indexer could report a listing the others rejected, and the price would be paid for nothing. Add an independent indexer in Settings.`) : null,
    c && c.enough && !c.deep ? h('p', { class: 'warn', id: 'listing-shallow' }, `Not yet: ${c.shallow}.`) : null,
    buy,
    resultBox('buy-out'));
}

// an address only for a whole standard template (btc.js scriptType); anything else as its raw hex, flagged
const payee = (script) => scriptToAddress(script) ?? `script ${toHex(script)} (not a standard address)`;

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
  const bad = payeeProblem(fresh.l.payScript);
  if (bad) throw new Error(`not bought: ${bad}`);
  if (!fresh.enough) throw new Error(`not bought: ${fresh.agreed} indexer${fresh.agreed > 1 ? 's' : ''} ${fresh.agreed > 1 ? 'report' : 'reports'} this listing, ${fresh.verifying} of them verifying spends, and a TAKE needs ${TAKE_QUORUM} that verify spends and agree (add one in Settings)`);
  if (!fresh.deep) throw new Error(`not bought yet: ${fresh.shallow}`);
  const tip = await esplora.tipHeight();
  const o = await st.vault.reserveNote(); // the tokens come as this public note
  const m = buildTake({ l: fresh.l, sig: c.sig, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: feeRateOf(sendForm.fee), tipHeight: tip });
  if (!confirm(`Pay ${sats(fresh.l.price)} plus ${sats(m.fee)} of fees for ${units(fresh.l.amount)} ${fresh.l.ticker}?`)) return;
  await sendFunded(m, 'buy-out', `TAKE of ${units(fresh.l.amount)} ${fresh.l.ticker}`, { index: o.index, ticker: fresh.l.ticker, v: fresh.l.amount });
  marketForm.checked = null;
}

async function sendCancel(rec) {
  const { l, state } = await ownListing(rec);
  if (state !== 'ACTIVE') throw new Error(`the listing is ${state}`);
  if (!confirm(`Take ${units(l.amount)} ${l.ticker} back? The listing ends.`)) return;
  const o = await st.vault.reserveNote();
  const m = buildCancel({ l, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: feeRateOf(sendForm.fee), tipHeight: await esplora.tipHeight() });
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
  const m = buildClaim({ listTxid: rec.listTxid, lockSecret: (await st.vault.lockOutput(rec.lockIndex)).secret, npk: o.npk, payer: st.wallet, utxos: await walletUtxos(), feeRate: feeRateOf(sendForm.fee), tipHeight: await esplora.tipHeight() });
  await sendFunded(m, 'listing-out', `CLAIM of ${units(rec.amount)} ${rec.ticker}`, { index: o.index, ticker: rec.ticker, v: BigInt(rec.amount) });
}
