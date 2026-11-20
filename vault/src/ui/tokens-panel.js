// The tickers table and the mint panel: the indexer's tokens, the cross-check, and a MINT built,
// signed by the wallet and broadcast.

import { finalizePsbt, sameUnsignedTx, scriptType } from '../btc.js';
import { toHex } from '../bytes.js';
import { TERMS, crossCheck, profileCheck } from '../consensus.js';
import { verifyMintTerms } from '../deploy.js';
import { buildMint, mintProblems, mintsLeft } from '../mint.js';
import { MINT_BATCH_MAX, PAY_MODE } from '../sh20.js';
import { $, MAX_FEE_SATS, busy, esplora, explorerTx, fill, h, indexer, indexers, report, sats, short, st, units } from './context.js';
import { processDeploys, renderDeploy } from './deploy-panel.js';
import { renderNotes } from './notes-panel.js';
import { renderAll } from './render.js';

// ---- tokens ----------------------------------------------------------------------

const payText = (t) => (t.payMode === PAY_MODE.NONE ? 'free' : `${sats(t.price)} ${t.payMode === PAY_MODE.BURN ? 'burned' : 'to deployer'}`);

export async function refresh() {
  try {
    const [status, tokens] = await Promise.all([indexer.status(), indexer.tokens()]);
    st.status = status;
    st.tokens = tokens;
    const wrongNet = status.network && status.network !== 'signet';
    fill('indexer-status',
      wrongNet ? h('span', { class: 'err' }, `Indexer follows ${status.network}, not signet. `) : null,
      `Indexer at block ${status.height ?? '?'}`,
      status.digest ? ` · digest ${short(String(status.digest))}` : '',
      status.verifier === 'reject-all' ? ' · spends not verified yet' : '',
      ` · ${indexers.length} indexer${indexers.length > 1 ? 's' : ''} configured`);
    if (wrongNet) st.tokens = [];
  } catch (e) {
    st.tokens = [];
    fill('indexer-status', h('span', { class: 'err' }, `Indexer unreachable (${indexer.base}): ${e.message}`));
  }
  // every indexer against the vault's own profile (profile.js): one that differs is named, and nothing is done
  st.profile = await profileCheck(indexers);
  if (st.profile.problems.length) $('indexer-status')?.append(h('span', { class: 'err', id: 'profile-problems' }, ` · This vault acts on nothing: ${st.profile.problems.join('. ')}.`));
  try {
    st.tip = await esplora.tipHeight();
  } catch {
    st.tip = null;
  }
  renderTokens();
  renderDeploy();
  processDeploys().catch(report);
}

export function chainHeight() {
  return st.tip ?? st.status?.height ?? null;
}

export function renderTokens() {
  if (!st.tokens.length) {
    fill('tokens-body', h('p', { class: 'muted' }, 'No ticker to show.'));
    return;
  }
  const H = chainHeight();
  const rows = st.tokens.map((t) => {
    const problems = H === null ? ['chain height unknown'] : mintProblems(t, H + 1);
    const b = h('button', { type: 'button', class: 'small', disabled: problems.length > 0, title: problems.join('; ') }, 'Mint');
    b.addEventListener('click', () => openMint(t.ticker));
    return h('tr', {},
      h('td', {}, h('strong', {}, t.ticker), t.genesis ? h('span', { class: 'muted' }, ' genesis') : null),
      h('td', { class: 'num' }, units(t.lim)),
      h('td', { class: 'num' }, `${units(t.mints)} / ${units((t.max - t.pre) / t.lim)}`),
      h('td', {}, payText(t)),
      h('td', {}, `${t.start}${t.end ? `–${t.end}` : '→'}`),
      h('td', { class: 'num' }, t.pre > 0n ? `${units(t.pre)} @ ${t.unlock}` : '0'),
      h('td', {}, problems.length ? h('span', { class: 'muted' }, problems[0]) : b));
  });
  fill('tokens-body', h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Ticker', 'Per mint', 'Mints', 'Price', 'Window', 'Team', ''].map((x) => h('th', {}, x)))),
    h('tbody', {}, rows))),
  h('p', { class: 'muted' }, `Chain tip ${H ?? '?'}; a mint sent now confirms at ${H === null ? '?' : H + 1} or later.`));
}

// ---- mint ------------------------------------------------------------------------

async function openMint(ticker) {
  $('mint').hidden = false;
  fill('mint-ticker', ticker);
  fill('mint-body', h('p', { class: 'muted' }, 'Loading…'));
  $('mint').scrollIntoView({ behavior: 'smooth' });
  try {
    const check = await crossCheck(indexers, ticker);
    renderMint(check, await esplora.feeRate());
  } catch (e) {
    fill('mint-body', h('p', { class: 'err' }, e.message));
  }
}

function checkNotes(check) {
  return [
    ...check.problems.map((p) => h('div', { class: 'warn err' }, `Mint refused: ${p}`)),
    ...check.warnings.map((w) => h('div', { class: 'warn' }, w)),
  ];
}

function renderMint(check, defaultFee) {
  const token = check.token;
  const need = check.problems.length ? ['resolve the indexer disagreement'] : [];
  if (!st.vault) need.push('unlock the vault');
  if (!st.wallet) need.push('connect a wallet');
  const fee = h('input', { type: 'number', min: '0.1', step: '0.1', value: String(defaultFee), class: 'narrow' });
  // batch mint (wire v0.3): k mints in one envelope, one note of k × lim for k × price, never more than what is left
  const most = Math.min(MINT_BATCH_MAX, Number(mintsLeft(token)));
  const count = h('input', { type: 'number', min: '1', max: String(Math.max(1, most)), step: '1', value: '1', class: 'narrow', name: 'k' });
  const receive = h('dd');
  const showCount = () => {
    const k = BigInt(Math.max(1, Math.min(most, Number(count.value) | 0)));
    receive.textContent = `${units(token.lim * k)} ${token.ticker} (one public note${k > 1n ? `, ${k} mints` : ''}) for ${token.payMode === PAY_MODE.NONE ? 'network fees only' : sats(token.price * k)}`;
  };
  count.addEventListener('input', showCount);
  showCount();
  const prep = h('button', { type: 'button', disabled: need.length > 0 }, 'Prepare transaction');
  const out = h('div');
  prep.addEventListener('click', busy(prep, () => prepareMint(token, Number(fee.value), Number(count.value), out)));
  fill('mint-body',
    h('dl', {},
      h('dt', {}, 'You receive'), receive,
      h('dt', {}, 'Price per mint'), h('dd', {}, payText(token)),
      h('dt', {}, 'Mints left'), h('dd', {}, units(mintsLeft(token))),
      h('dt', {}, 'Window'), h('dd', {}, `block ${token.start} to ${token.end || 'no end'}`)),
    checkNotes(check),
    h('div', { class: 'row' }, h('label', {}, `Mints (1 to ${Math.max(1, most)}) `, count), h('label', {}, 'Fee rate (sat/vB) ', fee), prep),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(' and ')}.`) : null,
    out);
}

async function prepareMint(shown, feeRate, k, out) {
  // ask every indexer again: the terms signed must be the ones shown, agreed on, and on chain
  const check = await crossCheck(indexers, shown.ticker);
  if (check.problems.length) throw new Error(`mint refused: ${check.problems.join('; ')}`);
  const token = check.token;
  if (TERMS.some((k) => String(token[k]) !== String(shown[k]))) throw new Error('the token terms changed since they were shown; open the mint again');
  // the mint terms come from the chain (the DEPLOY) or the profile (SH20), not from the indexer alone
  const source = await verifyMintTerms(esplora, token);
  const tip = await esplora.tipHeight();
  const w = st.wallet;
  let utxos = w.adapter.utxos ? await w.adapter.utxos(w.address) : null;
  if (!utxos) utxos = await esplora.utxos(w.address);
  if (!utxos.length) throw new Error(`no UTXO at ${w.address}; get signet coins from a faucet first`);
  const opening = await st.vault.opening(st.vault.state.next); // reserved only when signed
  const m = buildMint({ token, opening, payer: w, utxos, feeRate, tipHeight: tip, k });

  const sign = h('button', { type: 'button' }, `Sign with ${w.adapter.name} and broadcast`);
  sign.addEventListener('click', busy(sign, () => signAndSend(token, m, opening, out)));
  out.replaceChildren(
    h('dl', {},
      h('dt', {}, 'Inputs'), h('dd', {}, `${m.tx.vin.length} from ${short(w.address)}`),
      h('dt', {}, 'Outputs'), h('dd', {}, m.tx.vout.map((o, i) => `#${i} ${scriptType(o.script)} ${sats(o.value)}`).join(' · ')),
      h('dt', {}, 'Size'), h('dd', {}, `≈ ${m.vsizeEstimate} vB (a plain P2TR payment is ≈ 154 vB)`),
      h('dt', {}, 'Network fee'), h('dd', {}, sats(m.fee)),
      h('dt', {}, 'You receive'), h('dd', {}, `${units(m.v)} ${token.ticker}${m.k > 1 ? ` (${m.k} mints in one note)` : ''}`),
      h('dt', {}, 'Mint price'), h('dd', {}, token.payMode === PAY_MODE.NONE ? 'free' : m.k > 1 ? `${sats(m.price)} (${m.k} × ${sats(token.price)})` : sats(m.price)),
      h('dt', {}, 'Total'), h('dd', {}, h('strong', {}, sats(m.fee + m.price))),
      h('dt', {}, 'Terms'), h('dd', {}, source === 'genesis'
        ? `genesis token: price, payment, window and supply checked against the profile constants in this vault (start = activation block ${check.profile.activationHeight})`
        : 'price, payment, window and supply checked against the DEPLOY transaction on chain'),
      check.agreed > 1 ? [h('dt', {}, 'Indexers'), h('dd', {}, `${check.agreed} agree on these terms`)] : null,
      h('dt', {}, 'Envelope'), h('dd', {}, h('code', {}, toHex(m.envelope)))),
    checkNotes(check),
    h('p', { class: 'muted' }, m.k > 1
      ? 'A mint rejected by the indexers is not refunded. If other mints in the same block leave fewer than k, the indexers give you what is left and keep the whole payment.'
      : 'A mint rejected by the indexers (for example sold out by a mint in the same block) is not refunded.'),
    sign);
}

async function signAndSend(token, m, opening, out) {
  const w = st.wallet;
  if (m.fee > MAX_FEE_SATS && !confirm(`The network fee is ${sats(m.fee)}, which is unusually high. Sign anyway?`)) return;
  const signed = await w.adapter.signPsbt(m.psbt, m.inputIndexes, w.address);
  const done = finalizePsbt(signed);
  if (!sameUnsignedTx(done.tx, m.tx)) throw new Error('the wallet changed the transaction; nothing was sent');
  const reserved = await st.vault.reserveNote();
  if (reserved.index !== opening.index) throw new Error('note index moved; prepare the transaction again');
  const note = await st.vault.addNote({ index: reserved.index, ticker: token.ticker, v: m.v, txid: done.txid, status: 'signed' });
  let id;
  try {
    id = await esplora.broadcast(done.hex);
  } catch (e) {
    await st.vault.updateNote(note.id, { status: 'broadcast failed' });
    renderNotes();
    throw e;
  }
  await st.vault.updateNote(note.id, { status: 'broadcast', txid: id });
  out.replaceChildren(
    h('p', { class: 'ok' }, `Broadcast: ${done.vsize} vB, fee ${sats(m.fee)}.`),
    h('p', {}, h('a', { href: explorerTx(id), target: '_blank', rel: 'noopener noreferrer' }, id)));
  renderAll();
}
