// Proof-carrying spends from the page: plan, prove (WebAssembly), the wallet signs the commit, the
// vault the reveal; the helpers that fund and sign a transaction with the wallet.

import { finalizePsbt, sameUnsignedTx } from '../btc.js';
import { loadProver, unloadProver } from '../prover.js';
import { pendingRecord, planCarrier, proveSpend, revealFor } from '../send.js';
import { IS_MAINNET, PROFILE } from '../profile.js';
import { spendableCoins, unverifiedCoins } from '../coins.js';
import { MAX_FEE_SATS, esplora, explorerTx, h, noCoins, requireProfile, result, sats, short, st } from './context.js';
import { processDeploys } from './deploy-panel.js';
import { renderAll } from './render.js';

// ---- spends: proved here; the wallet signs the commit, the vault the reveal --------------------

export const txLink = (id) => h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, id));

/**
 * The wallet's coins that pay a transaction of the vault (coins.js spendableCoins): confirmed ones only, by
 * Esplora's word (vault-2), and on mainnet plain ones only (vault-15): the wallet's own list of the coins that carry
 * nothing, or, for a wallet that keeps its collectibles at another address, the coins above SMALL_COIN at the one
 * it pays from. A wallet that does neither is refused on mainnet.
 */
export async function walletUtxos() {
  const w = st.wallet;
  const chain = await esplora.utxos(w.address);
  const listed = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  const apart = !!w.otherAddress && w.otherAddress !== w.address;
  const utxos = spendableCoins({ chain, listed, apart, mainnet: IS_MAINNET, wallet: w.adapter.name, address: w.address });
  if (!utxos.length) throw new Error(noCoins(w.address));
  // on mainnet, coins no list vouches for are spent only on the user's word, each time, naming them (unverifiedCoins)
  const ask = unverifiedCoins({ listed, mainnet: IS_MAINNET, wallet: w.adapter.name, coins: utxos });
  if (ask && !confirm(ask)) throw new Error('not spent: the coins were not confirmed as plain');
  return utxos;
}

/** The wallet's coins a transaction spends, as `txid:vout (value)`: named before the wallet is asked (vault-15). */
export function coinsText(tx, utxos) {
  return tx.vin
    .map((i) => [i, utxos.find((u) => u.txid === i.txid && u.vout === i.vout)])
    .filter(([, u]) => u)
    .map(([i, u]) => `${short(i.txid)}:${i.vout} (${sats(u.value)})`)
    .join(', ');
}

/** Has the wallet sign a PSBT the vault built, and checks it signed exactly that transaction. */
export async function signFunded(m) {
  const w = st.wallet;
  if (m.fee > MAX_FEE_SATS && !confirm(`The network fee is ${sats(m.fee)}, which is unusually high. Sign anyway?`)) throw new Error('not signed');
  const signed = await w.adapter.signPsbt(m.psbt, m.inputIndexes, w.address);
  const done = finalizePsbt(signed);
  if (!sameUnsignedTx(done.tx, m.tx)) throw new Error('the wallet changed the transaction; nothing was sent');
  return done;
}

/**
 * A proof-carrying spend: plan (witness), prove, commit (wallet), reveal (vault), broadcast both.
 * The one-time key is saved before the wallet signs, so the reveal can always be sent again.
 */
export async function carry(args) {
  try {
    await carryOnce(args);
  } catch (e) {
    result(args.out, h('p', { class: 'err' }, e.message || String(e)));
    throw e;
  }
}

async function carryOnce({ kind, out, feeRate, tip, plan, label, outputs, onRevealed, deploy, sweep }) {
  const status = (t) => result(out, h('p', { class: 'muted' }, t));
  await requireProfile(); // a DEPLOY, a burn, a LIST, a transfer: only with indexers on the vault's profile
  status('Building the envelope: note keys, sealed outputs, signatures…');
  await new Promise((r) => setTimeout(r, 30));
  const built = await plan();
  let envelope = built.envelope; // a DEPLOY with no burn carries no spend, hence no proof
  let proveS = null;
  if (!envelope) {
    const prover = await loadProver({ onStatus: status });
    status(`Proving on ${prover.threads} thread${prover.threads > 1 ? 's' : ''}… keep this tab open.`);
    const t0 = performance.now();
    try {
      envelope = await proveSpend(prover, built);
    } finally {
      // the witness holds the nullifier keys and note tweaks of this spend (AUDIT §8.8): zeroed here,
      // and the prover's memory, which keeps a copy until the next proof, goes with its workers
      built.witness.fill(0);
      unloadProver();
    }
    proveS = ((performance.now() - t0) / 1000).toFixed(1);
  }
  const coins = await walletUtxos();
  const cp = planCarrier({ envelope, payer: st.wallet, utxos: coins, feeRate, tipHeight: tip, outputs, sweep });
  const draft = revealFor(cp, '00'.repeat(32));
  const wait = deploy ? ` The reveal goes out once the commit is ${PROFILE.deployMaturity} blocks deep (SPEC-WIRE §5): keep the vault open, or come back.` : '';
  if (!confirm(`${label}${proveS ? `: proved in ${proveS} s` : ''}. Commit ≈ ${cp.commit.vsizeEstimate} vB, reveal ${draft.vsize} vB, network fees ≈ ${sats(cp.commit.fee + draft.fee)}.${wait} The commit spends ${coinsText(cp.commit.tx, coins)}. Sign it with ${st.wallet.adapter.name}?`)) {
    status('Not sent.');
    return;
  }
  const pid = await st.vault.addPending({ ...pendingRecord(kind, cp, envelope, built.inputs), ...(deploy ? { deploy, anchorHeight: built.anchorHeight ?? null } : {}) });
  let done;
  try {
    done = await signFunded(cp.commit);
  } catch (e) {
    // not signed: the envelope went nowhere (the vault signs the reveal only after the commit), so its notes come back now (vault-2)
    await st.vault.givePendingUp(pid, 'not signed');
    renderAll();
    throw e;
  }
  // given up meanwhile from the list of spends: the notes are back, and nothing goes out
  if (st.vault.state.pending.find((x) => x.id === pid)?.status !== 'prepared') throw new Error('given up while the wallet was signing: nothing was sent');
  const reveal = revealFor(cp, done.txid);
  await st.vault.updatePending(pid, { commitTxid: done.txid, commitHex: done.hex, revealHex: reveal.hex, revealTxid: reveal.txid, status: 'signed' });
  await onRevealed?.(reveal);
  await esplora.broadcast(done.hex);
  await st.vault.updatePending(pid, { status: deploy ? 'waiting maturity' : 'commit broadcast' });
  if (deploy) {
    // the signed reveal stays in the encrypted state until the commit is N blocks deep (processDeploys)
    renderAll();
    result(out,
      h('p', { class: 'ok' }, `${label}: the commit is broadcast. The reveal waits until it is ${PROFILE.deployMaturity} blocks deep, against ticker sniping; the notes it burns stay reserved meanwhile.`),
      h('p', { class: 'muted' }, 'Commit:'), txLink(done.txid),
      h('p', { class: 'muted', id: 'deploy-countdown' }, 'Spends sent from this vault (below) shows the countdown.'));
    await processDeploys();
    return;
  }
  await esplora.broadcast(reveal.hex);
  await st.vault.updatePending(pid, { status: 'broadcast' });
  renderAll();
  result(out,
    h('p', { class: 'ok' }, `${label}: broadcast. ${proveS ? `Proved in ${proveS} s; ` : ''}${envelope.length}-byte envelope; reveal ${reveal.vsize} vB.`),
    h('p', { class: 'muted' }, 'Commit, then reveal:'), txLink(done.txid), txLink(reveal.txid),
    h('p', { class: 'muted' }, 'Sync after the next block: the notes spent show their block, and the change shows as a received note.'));
}
