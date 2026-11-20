// The send panel (TRANSFER, BURN, LIST) and the list of spends sent from this vault.

import { addressToScript } from '../btc.js';
import { toHex } from '../bytes.js';
import { listOutputs, planBurn, planList, poolProblem } from '../market.js';
import { planFromPending, planTransfer, revealFor } from '../send.js';
import { busy, esplora, fill, h, indexers, isolation, resultBox, sats, short, st, units } from './context.js';
import { broadcastDeployReveal, processDeploys, reproveDeploy } from './deploy-panel.js';
import { renderMarket } from './market-panel.js';
import { getSyncer } from './notes-panel.js';
import { carry } from './spends.js';
import { agreementText } from '../consensus.js';

// ---- send ------------------------------------------------------------------------

export const sendForm = { action: 'transfer', ticker: '', amount: '', to: '', fee: '2', price: '', payTo: '' };

export function balances() {
  const out = new Map();
  for (const n of st.vault?.state.notes ?? []) {
    if (n.status !== 'in tree' || n.spent !== 'no' || BigInt(n.v) === 0n) continue;
    out.set(n.ticker, (out.get(n.ticker) ?? 0n) + BigInt(n.v));
  }
  return out;
}

function proverModeText() {
  if (isolation === 'headers') return `Prover: thread pool (this page is cross-origin isolated${navigator.serviceWorker?.controller ? ' by its service worker' : ''}).`;
  return `Prover: one thread, about half a minute a proof (${{
    'not-a-subdomain-gateway': 'the page is not isolated; on an IPFS subdomain gateway it isolates itself',
    unavailable: 'no service worker here',
    refused: 'the browser refused cross-origin isolation',
  }[isolation] ?? 'not isolated'}).`;
}

export function renderSend() {
  if (!st.vault) {
    fill('send-body', h('p', { class: 'muted' }, 'Unlock the vault to send.'));
    fill('pending-body');
    return;
  }
  const bal = balances();
  const f = sendForm;
  if (!bal.has(f.ticker)) f.ticker = [...bal.keys()][0] ?? '';
  const ticker = h('select', { name: 'ticker' }, [...bal].map(([t, v]) => h('option', { value: t, selected: t === f.ticker }, `${t} (${units(v)})`)));
  ticker.addEventListener('change', () => { f.ticker = ticker.value; });
  const input = (key, attrs) => {
    const el = h('input', { value: f[key], spellcheck: 'false', autocomplete: 'off', ...attrs });
    el.addEventListener('input', () => { f[key] = el.value; });
    return el;
  };
  const out = resultBox('send-out');
  const need = [];
  if (!bal.size) need.push('hold a note that is in the tree and known unspent (sync)');
  if (!st.wallet) need.push('connect a wallet (it pays the network fees)');
  if (!f.payTo && st.wallet) f.payTo = st.wallet.address;
  const action = h('select', { name: 'action' }, [['transfer', 'Send privately (TRANSFER)'], ['burn', 'Burn (BURN)'], ['list', 'Sell for BTC (LIST)']].map(([v, t]) => h('option', { value: v, selected: f.action === v }, t)));
  action.addEventListener('change', () => { f.action = action.value; renderSend(); });
  const label = { transfer: 'Prove and send', burn: 'Prove and burn', list: 'Prove and list' }[f.action];
  const b = h('button', { type: 'button', disabled: need.length > 0, name: 'send' }, label);
  b.addEventListener('click', busy(b, () => ({ transfer: sendTransfer, burn: sendBurn, list: sendList })[f.action]('send-out')));
  fill('send-body',
    st.sync?.agreement?.disagree.length ? h('p', { class: 'warn err' }, agreementText(st.sync.agreement), ' A spend built on that state would be rejected after paying its fee.') : null,
    h('p', { class: 'muted' }, {
      transfer: 'A private TRANSFER, proved on this device: the amount, the ticker, the sender and the recipient stay hidden. Your Bitcoin wallet pays the network fees.',
      burn: 'A BURN takes tokens out of the supply for good, in public: the amount and the ticker are shown, not which notes paid it.',
      list: 'A LIST moves the amount into a public escrow with a lock output only this vault can spend; you then share a signed offer, and whoever completes it pays the price to your address and gets the tokens.',
    }[f.action]),
    h('p', { class: 'muted', id: 'prover-mode' }, proverModeText()),
    h('div', { class: 'grid' },
      h('label', {}, 'Action ', action),
      h('label', {}, 'Ticker ', ticker),
      h('label', {}, 'Amount ', input('amount', { inputmode: 'numeric', name: 'amount' })),
      f.action === 'list' ? h('label', {}, 'Price (sats) ', input('price', { inputmode: 'numeric', name: 'price' })) : null,
      h('label', {}, 'Fee rate (sat/vB) ', input('fee', { type: 'number', min: '0.1', step: '0.1', name: 'fee' }))),
    f.action === 'transfer' ? h('label', {}, 'To (an sh20 address, tsh20…) ', input('to', { name: 'to', class: 'wide' })) : null,
    f.action === 'list' ? h('label', {}, 'Paid to (a signet address) ', input('payTo', { name: 'payTo', class: 'wide' })) : null,
    h('div', { class: 'row' }, b),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(' and ')}.`) : null,
    out);
  renderPending();
  renderMarket();
}

const amountOf = (x) => {
  if (!/^[0-9]{1,20}$/.test(x.trim())) throw new Error('amounts and prices are whole numbers');
  return BigInt(x.trim());
};

/**
 * Before proving a spend that takes `amount` of `ticker` out of the pool: every configured indexer's
 * /token/:ticker must have room for it (the turnstile), else the spend would be rejected and its fees lost.
 */
export async function checkPool(ticker, amount, what) {
  const answers = await Promise.allSettled(indexers.map((a) => a.token(ticker)));
  const tokens = answers.filter((a) => a.status === 'fulfilled').map((a) => a.value);
  const problem = poolProblem(tokens, ticker, amount, what);
  if (problem) throw new Error(`Not sent: ${problem}.`);
}

async function sendBurn(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  await checkPool(f.ticker, amount, 'BURN');
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  if (!confirm(`Burn ${units(amount)} ${f.ticker}? They leave the supply for good.`)) return;
  await carry({
    kind: 'BURN', out, feeRate: Number(f.fee), tip,
    plan: () => planBurn({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount }),
    label: `BURN of ${units(amount)} ${f.ticker}`,
  });
}

async function sendList(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  const price = amountOf(f.price);
  const payScript = addressToScript(f.payTo.trim());
  await checkPool(f.ticker, amount, 'LIST');
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  const lockIndex = await st.vault.reserveLock();
  const lock = await st.vault.lockOutput(lockIndex);
  await carry({
    kind: 'LIST', out, feeRate: Number(f.fee), tip,
    plan: () => planList({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount, price, payScript, lockKey: lock.key }),
    outputs: listOutputs(lock.script),
    label: `LIST of ${units(amount)} ${f.ticker} for ${sats(price)}`,
    onRevealed: (reveal) => st.vault.addListing({ lockIndex, ticker: f.ticker, amount: amount.toString(), price: price.toString(), payScript: toHex(payScript), listTxid: reveal.txid, state: 'broadcast', source: 'sent' }),
  });
}

async function sendTransfer(out) {
  const f = sendForm;
  const amount = amountOf(f.amount);
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  await carry({
    kind: 'TRANSFER', out, feeRate: Number(f.fee), tip,
    plan: () => planTransfer({ vault: st.vault, sync: s, tip, ticker: f.ticker, amount, to: f.to }),
    label: `TRANSFER of ${units(amount)} ${f.ticker}`,
  });
}

/** Spends whose reveal may still need sending: their one-time key is in the vault. */
export function renderPending() {
  const open = (st.vault?.state.pending ?? []).filter((p) => p.status !== 'prepared' && p.status !== 'replaced');
  if (!open.length) return fill('pending-body');
  fill('pending-body', h('h3', {}, 'Spends sent from this vault'), h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['What', 'Status', 'Commit', 'Reveal', ''].map((x) => h('th', {}, x)))),
    h('tbody', {}, open.map((p) => {
      if (p.status === 'anchor expired') {
        const re = h('button', { type: 'button', class: 'small', name: 'reprove' }, 'Prove again');
        re.addEventListener('click', busy(re, () => reproveDeploy(p)));
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, 'the proof\'s anchor left the window W: prove again'), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, '—'), h('td', {}, re));
      }
      if (p.kind === 'DEPLOY' && p.status === 'signed') {
        // signed but the commit may never have gone out: send the commit only, then the countdown
        const commit = h('button', { type: 'button', class: 'small secondary' }, 'Broadcast the commit');
        commit.addEventListener('click', busy(commit, async () => {
          try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
          await st.vault.updatePending(p.id, { status: 'waiting maturity' });
          await processDeploys();
        }));
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, 'signed; the commit may not be out yet'), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, 'kept, signed'), h('td', {}, commit));
      }
      if (p.kind === 'DEPLOY' && p.status !== 'broadcast' && p.status !== 'waiting maturity') {
        // ticker taken, replaced: nothing to broadcast
        return h('tr', {}, h('td', {}, p.kind), h('td', {}, p.status), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, '—'), h('td', {}));
      }
      if (p.status === 'waiting maturity') {
        const left = p.schedule === 'unconfirmed' || p.revealIn === undefined ? 'the commit is not confirmed yet'
          : /no indexer answered/.test(p.schedule ?? '') ? 'due, but no indexer answered: the reveal waits for one to say the ticker is free'
          : /^due, but/.test(p.schedule ?? '') ? p.schedule
          : `reveal in ${p.revealIn} block${p.revealIn === 1 ? '' : 's'}`;
        const commitAgain = h('button', { type: 'button', class: 'small secondary' }, 'Broadcast the commit again');
        commitAgain.addEventListener('click', busy(commitAgain, async () => {
          try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
        }));
        return h('tr', {}, h('td', {}, p.kind), h('td', { class: 'countdown' }, `${p.deploy.ticker}: ${left}`), h('td', { class: 'mono' }, short(p.commitTxid ?? '')), h('td', {}, 'kept, signed'), h('td', {}, commitAgain));
      }
      const again = h('button', { type: 'button', class: 'small secondary', disabled: !p.commitHex }, 'Broadcast again');
      again.addEventListener('click', busy(again, async () => {
        // the same signed transactions; a reveal is signed again only if it was never made
        const reveal = p.revealHex ? { hex: p.revealHex, txid: p.revealTxid } : revealFor(planFromPending(p), p.commitTxid);
        try { await esplora.broadcast(p.commitHex); } catch (e) { if (!/already|known|exists|conflict/i.test(e.message)) throw e; }
        if (p.kind === 'DEPLOY') await broadcastDeployReveal({ ...p, revealHex: reveal.hex }); // only once mature
        else await esplora.broadcast(reveal.hex);
        await st.vault.updatePending(p.id, { status: 'broadcast', revealHex: reveal.hex, revealTxid: reveal.txid });
        renderPending();
      }));
      return h('tr', {},
        h('td', {}, p.kind), h('td', {}, p.status),
        h('td', { class: 'mono' }, p.commitTxid ? short(p.commitTxid) : '—'),
        h('td', { class: 'mono' }, p.revealTxid ? short(p.revealTxid) : '—'),
        h('td', {}, again));
    })))));
}
