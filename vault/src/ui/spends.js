// Proof-carrying spends from the page: plan, prove (WebAssembly), the wallet signs the commit, the
// vault the reveal; the helpers that fund and sign a transaction with the wallet.

import { finalizePsbt, sameUnsignedTx } from '../btc.js';
import { loadProver } from '../prover.js';
import { pendingRecord, planCarrier, proveSpend, revealFor } from '../send.js';
import { MAX_FEE_SATS, esplora, explorerTx, h, result, sats, st } from './context.js';
import { processDeploys } from './deploy-panel.js';
import { renderAll } from './render.js';

// ---- spends: proved here; the wallet signs the commit, the vault the reveal --------------------

export const txLink = (id) => h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, id));

export async function walletUtxos() {
  const w = st.wallet;
  let utxos = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  if (!utxos) utxos = await esplora.utxos(w.address);
  if (!utxos.length) throw new Error(`no UTXO at ${w.address}; get signet coins from a faucet first`);
  return utxos;
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
  status('Building the envelope: note keys, sealed outputs, signatures…');
  await new Promise((r) => setTimeout(r, 30));
  const built = await plan();
  let envelope = built.envelope; // a DEPLOY with no burn carries no spend, hence no proof
  let proveS = null;
  if (!envelope) {
    const prover = await loadProver({ onStatus: status });
    status(`Proving on ${prover.threads} thread${prover.threads > 1 ? 's' : ''}… keep this tab open.`);
    const t0 = performance.now();
    envelope = await proveSpend(prover, built);
    proveS = ((performance.now() - t0) / 1000).toFixed(1);
  }
  const cp = planCarrier({ envelope, payer: st.wallet, utxos: await walletUtxos(), feeRate, tipHeight: tip, outputs, sweep });
  const draft = revealFor(cp, '00'.repeat(32));
  const wait = deploy ? ` The reveal goes out once the commit is ${deploy.N} blocks deep (SPEC-WIRE §5): keep the vault open, or come back.` : '';
  if (!confirm(`${label}${proveS ? `: proved in ${proveS} s` : ''}. Commit ≈ ${cp.commit.vsizeEstimate} vB, reveal ${draft.vsize} vB, network fees ≈ ${sats(cp.commit.fee + draft.fee)}.${wait} Sign the commit with ${st.wallet.adapter.name}?`)) {
    status('Not sent.');
    return;
  }
  const pid = await st.vault.addPending({ ...pendingRecord(kind, cp, envelope, built.inputs), ...(deploy ? { deploy, anchorHeight: built.anchorHeight ?? null } : {}) });
  const done = await signFunded(cp.commit);
  const reveal = revealFor(cp, done.txid);
  await st.vault.updatePending(pid, { commitTxid: done.txid, commitHex: done.hex, revealHex: reveal.hex, revealTxid: reveal.txid, status: 'signed' });
  await onRevealed?.(reveal);
  await esplora.broadcast(done.hex);
  await st.vault.updatePending(pid, { status: deploy ? 'waiting maturity' : 'commit broadcast' });
  if (deploy) {
    // the signed reveal stays in the encrypted state until the commit is N blocks deep (processDeploys)
    renderAll();
    result(out,
      h('p', { class: 'ok' }, `${label}: the commit is broadcast. The reveal waits until it is ${deploy.N} blocks deep, against ticker sniping; the notes it burns stay reserved meanwhile.`),
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
