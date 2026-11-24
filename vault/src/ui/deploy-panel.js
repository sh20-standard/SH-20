// The deploy screen, and the DEPLOYs waiting for their commit to mature (SPEC-WIRE §5): the countdown,
// the reveal once the commit is N blocks deep, and proving again when the anchor would expire.

import { addressToScript } from '../btc.js';
import { fromHex, toHex } from '../bytes.js';
import { planDeploy } from '../deploy-plan.js';
import { frFromHex, frHex } from '../fr.js';
import { deploySchedule, planDeployBurn, planPlainDeploy, tickerState } from '../send.js';
import { PROFILE } from '../profile.js';
import { actProblems, profileCheck } from '../consensus.js';
import { NET, busy, esplora, fill, h, indexer, indexers, report, requireProfile, result, resultBox, st, units } from './context.js';
import { getSyncer, syncNotes } from './notes-panel.js';
import { checkPool, renderPending } from './send-panel.js';
import { carry, txLink } from './spends.js';
import { chainHeight, refresh } from './tokens-panel.js';

// ---- deploy ----------------------------------------------------------------------

const deployForm = { ticker: '', max: '21000000', lim: '1000', pre: '0', start: '', end: '0', unlock: '', payMode: '0', price: '0', payTo: '' };

const bigField = (x) => (/^[0-9]{1,20}$/.test(x.trim()) ? BigInt(x.trim()) : null);
const heightField = (x) => (/^[0-9]{1,10}$/.test(x.trim()) ? Number(x.trim()) : null);

/** D, from the vault's own profile (profile.js); null, with the reason, while an indexer follows another one. */
function deployBurn() {
  const pr = st.profile;
  if (!pr.answered) return { D: null, why: 'no indexer answered' };
  const act = actProblems(pr, indexer?.base); // another profile, or a primary that verifies no spend (vault-16)
  if (act.length) return { D: null, why: act.join('. ') };
  return { D: PROFILE.deployBurn, agreed: pr.answered };
}

/** The DEPLOY terms the form holds now, as deploy-plan.js reads them. */
function currentTerms() {
  const f = deployForm;
  let payScript = new Uint8Array(0);
  let payProblem = null;
  if (f.payMode === '2' && f.payTo.trim()) {
    try {
      payScript = addressToScript(f.payTo.trim());
    } catch {
      payProblem = `the payment address is not a ${NET} address`;
    }
  }
  const d = {
    ticker: f.ticker.trim().toUpperCase(), max: bigField(f.max), lim: bigField(f.lim), pre: bigField(f.pre),
    start: heightField(f.start), end: heightField(f.end), unlock: heightField(f.unlock),
    payMode: Number(f.payMode), price: f.payMode === '0' ? 0n : bigField(f.price), payScript,
  };
  return { d, payProblem };
}

export function renderDeploy() {
  const H = chainHeight();
  const f = deployForm;
  if (!f.start && H !== null) f.start = String(H + 12);
  if (!f.unlock && f.start) f.unlock = f.start;
  const { d, payProblem } = currentTerms();
  const { D, why, agreed } = deployBurn();
  const plan = planDeploy(d, {
    nextHeight: H === null ? null : H + 1,
    taken: st.tokens.map((t) => t.ticker),
    deployBurn: D,
    notes: st.vault ? st.vault.state.notes : [],
  });
  if (payProblem) plan.problems.push(payProblem);

  const field = (key, label, attrs = {}) => {
    const el = h('input', { value: f[key], spellcheck: 'false', autocomplete: 'off', ...attrs });
    el.addEventListener('change', () => { f[key] = el.value; renderDeploy(); });
    return h('label', {}, label, ' ', el);
  };
  const mode = h('select', {}, [['0', 'free'], ['1', 'burned (OP_RETURN)'], ['2', 'paid to an address']].map(([v, t]) => h('option', { value: v, selected: f.payMode === v }, t)));
  mode.addEventListener('change', () => { f.payMode = mode.value; renderDeploy(); });

  let burnRow;
  let yours = null;
  if (D === null) burnRow = h('span', { class: 'err' }, `${why}: nothing can be deployed`);
  else if (D === 0n) burnRow = 'none: this profile has D = 0, so a DEPLOY carries no proof';
  else {
    burnRow = [h('strong', {}, `${units(D)} SH20`), ` burned with a proof: a spend of your SH20 notes (vPub = ${units(D)}, tPub = SH20), the change comes back to you as a shielded note`,
      agreed > 1 ? ` · ${agreed} indexers agree on D` : ' · one indexer agrees on D'];
    const inp = plan.inputs;
    yours = !st.vault ? 'unlock the vault to see your SH20'
      : !st.sync?.nullifiersKnown ? 'sync your notes first: spends of your SH20 notes are not known yet'
      : inp.pick ? `${units(inp.total)} SH20 in ${inp.count} note(s); ${inp.pick.length === 1 ? 'one note' : 'two notes'} would pay the burn`
      : h('span', { class: 'err' }, `${units(inp.total)} SH20 in ${inp.count} note(s): not enough, a spend takes at most two notes (mint SH20 first)`);
  }

  fill('deploy-body',
    h('p', { class: 'muted' }, 'Pick a free 4-character ticker and its terms. The first valid DEPLOY of a ticker wins; the terms are public and final.'),
    h('div', { class: 'grid' },
      field('ticker', 'Ticker', { maxlength: '4', class: 'narrow', placeholder: 'ABCD' }),
      field('max', 'Max supply', { inputmode: 'numeric' }),
      field('lim', 'Per mint', { inputmode: 'numeric' }),
      field('pre', 'Team allocation', { inputmode: 'numeric' }),
      field('unlock', 'Team unlock block', { inputmode: 'numeric' }),
      field('start', 'Mint start block', { inputmode: 'numeric' }),
      field('end', 'Mint end block (0 = none)', { inputmode: 'numeric' }),
      h('label', {}, 'Mint price ', mode),
      f.payMode !== '0' ? field('price', 'Price (sats)', { inputmode: 'numeric' }) : null,
      f.payMode === '2' ? field('payTo', `Paid to (${NET} address)`) : null),
    h('dl', {},
      h('dt', {}, 'Deploy burn'), h('dd', {}, burnRow),
      yours ? [h('dt', {}, 'Your SH20'), h('dd', {}, yours)] : null,
      plan.mints !== null ? [h('dt', {}, 'Public mints'), h('dd', {}, `${units(plan.mints)} × ${units(d.lim)} ${d.ticker}`)] : null,
      plan.bytes !== null ? [h('dt', {}, 'Envelope'), h('dd', {}, `${units(plan.bytes)} bytes in a tapscript witness (a commit, then the reveal ${PROFILE.deployMaturity} blocks later; ≈ ${Math.ceil(plan.bytes / 4)} vB for the envelope)`)] : null),
    plan.problems.map((p) => h('div', { class: 'warn' }, p)),
    deployButton(d, plan, D),
    resultBox('deploy-out'));
}

function deployButton(d, plan, D) {
  const need = [];
  if (plan.problems.length || plan.bytes === null) need.push('fix the terms');
  if (D === null) need.push('use indexers that follow this vault\'s profile');
  if (!st.vault) need.push('unlock the vault');
  if (!st.wallet) need.push('connect a wallet');
  if (D > 0n && !plan.inputs?.pick) need.push('hold enough unspent SH20');
  const fee = h('input', { type: 'number', min: '0.1', step: '0.1', value: '2', class: 'narrow', name: 'deploy-fee' });
  const b = h('button', { type: 'button', disabled: need.length > 0, name: 'deploy' }, D > 0n ? `Prove the burn of ${units(D)} SH20, sign and broadcast` : 'Sign and broadcast');
  b.addEventListener('click', busy(b, () => sendDeploy(d, D, Number(fee.value))));
  return [h('div', { class: 'row' }, h('label', {}, 'Fee rate (sat/vB) ', fee), b),
    need.length ? h('p', { class: 'muted' }, `First ${need.join(', ')}.`) : null,
    h('p', { class: 'muted' }, `${D > 0n
      ? 'The burn is a spend: the vault proves it on this device (about half a minute on one thread). '
      : ''}Your wallet signs a commit transaction, which hides the ticker; the vault keeps the signed reveal and broadcasts it once the commit is ${PROFILE.deployMaturity} blocks deep, so nobody who sees the ticker can deploy it first (SPEC-WIRE §5). Keep the vault open, or come back: the countdown survives a reload. A DEPLOY rejected by the indexers is not refunded.`)];
}

const termsKey = (d) => JSON.stringify(d, (_, v) => (typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? toHex(v) : v));

async function sendDeploy(shown, D, feeRate) {
  const out = 'deploy-out';
  await refresh(); // the tickers taken and the tip, now
  await requireProfile(); // every indexer on the vault's profile, asked now
  const tip = await esplora.tipHeight();
  const plan = planDeploy(shown, { nextHeight: tip + 1, taken: st.tokens.map((t) => t.ticker), deployBurn: D, notes: st.vault.state.notes });
  if (plan.problems.length) throw new Error(plan.problems.join('; '));
  if (termsKey(currentTerms().d) !== termsKey(shown)) throw new Error('the terms changed: check them again');
  if (!confirm(`Deploy ${shown.ticker}${D > 0n ? `, burning ${units(D)} SH20` : ''}? The terms are public and final.`)) return;
  const N = PROFILE.deployMaturity; // never an indexer's: one reporting less would have the reveal sent early
  // the team note, if any, is a public note of this vault, created at block `unlock`
  const team = shown.pre > 0n ? { npk: (await st.vault.reserveNote()).npk } : null;
  if (D > 0n) await checkPool('SH20', D, 'DEPLOY burn');
  const s = D > 0n ? await getSyncer() : null;
  await carry({
    kind: 'DEPLOY', out, feeRate, tip,
    plan: () => (D > 0n ? planDeployBurn({ vault: st.vault, sync: s, tip, d: shown, D, team }) : planPlainDeploy({ d: shown, team })),
    label: D > 0n ? `DEPLOY of ${shown.ticker}, burning ${units(D)} SH20` : `DEPLOY of ${shown.ticker}`,
    deploy: { terms: encodeTerms(shown), team: team ? frHex(team.npk) : null, D: String(D), N, W: PROFILE.anchorWindow, ticker: shown.ticker },
  });
}


const encodeTerms = (d) => JSON.parse(JSON.stringify(d, (_, v) => (typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? `0x${toHex(v)}` : v)));
const decodeTerms = (t) => JSON.parse(JSON.stringify(t), (_, v) => (typeof v === 'string' && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : typeof v === 'string' && /^0x[0-9a-f]*$/.test(v) ? fromHex(v.slice(2)) : v));

let deploysRunning = false;

/**
 * The only way a DEPLOY reveal is broadcast: never before its commit is N blocks deep (SPEC-WIRE §5).
 * A reveal sent early is rejected, loses its fees and shows the ticker to whoever watches the mempool.
 */
export async function broadcastDeployReveal(p) {
  await requireProfile();
  const [cs, tip] = await Promise.all([esplora.txStatus(p.commitTxid).catch(() => null), esplora.tipHeight()]);
  const sched = deploySchedule(p, { commitHeight: cs?.confirmed ? cs.block_height : null, tip });
  if (sched.state !== 'ready') throw new Error(`the DEPLOY reveal is not due: ${sched.state}${sched.blocks ? `, ${sched.blocks} block(s) to go` : ''}`);
  await esplora.broadcast(p.revealHex);
}

/**
 * The DEPLOYs waiting for their commit to mature (SPEC-WIRE §5): their reveal is signed and kept in
 * the encrypted state, and goes out once the commit is N blocks deep, if the ticker is still free.
 * A DEPLOY whose proof's anchor would be out of the window W by then must be proved again.
 * Runs on every refresh and every minute while the vault is open.
 */
export async function processDeploys() {
  const v = st.vault;
  if (!v || deploysRunning) return;
  deploysRunning = true;
  try {
    for (const p of (v.state.pending ?? []).filter((x) => x.kind === 'DEPLOY' && x.status === 'waiting maturity')) {
      const [cs, tip] = await Promise.all([esplora.txStatus(p.commitTxid).catch(() => null), esplora.tipHeight()]);
      const commitHeight = cs?.confirmed ? cs.block_height : null;
      const sched = deploySchedule(p, { commitHeight, tip }); // N and W of the vault's profile, whatever the record or the indexers say
      await v.updatePending(p.id, { commitHeight, revealIn: sched.blocks, schedule: sched.state });
      if (sched.state === 'expired') {
        await v.updatePending(p.id, { status: 'anchor expired' });
        continue;
      }
      if (sched.state !== 'ready') continue;
      // the ticker may have been taken meanwhile (another DEPLOY confirmed first): then the reveal would be rejected.
      // From the full lists: asking /token/<ticker> would tell the indexer the ticker before the reveal shows it.
      const ticker = tickerState(await Promise.allSettled(indexers.map((a) => a.tokens())), p.deploy.ticker);
      if (ticker === 'unknown') {
        await v.updatePending(p.id, { schedule: 'no indexer answered: the reveal waits' }); // never revealed blind
        continue;
      }
      if (ticker === 'taken') {
        await v.releaseInputs(p.inputs);
        await v.updatePending(p.id, { status: 'ticker taken' });
        continue;
      }
      const pc = await profileCheck(indexers);
      const act = actProblems(pc, indexer?.base);
      if (act.length) {
        await v.updatePending(p.id, { schedule: `due, but ${act.join('. ')}: the reveal waits` });
        continue;
      }
      await broadcastDeployReveal(p);
      await v.updatePending(p.id, { status: 'broadcast' });
      result('deploy-out', h('p', { class: 'ok' }, `DEPLOY of ${p.deploy.ticker}: the commit is ${PROFILE.deployMaturity} blocks deep, the reveal is broadcast.`), txLink(p.revealTxid));
    }
  } finally {
    deploysRunning = false;
    renderPending();
  }
}
/** Every minute, the DEPLOYs waiting for their commit (started by app.js, after the page's checks). */
export const startDeployTimer = () => setInterval(() => processDeploys().catch(report), 60000);

/** A DEPLOY whose proof's anchor went out of the window: proved again on today's tree, with a new commit that takes the old one's sats back. */
export async function reproveDeploy(p) {
  if (!st.wallet) throw new Error('connect the wallet first: it pays the new commit');
  const d = decodeTerms(p.deploy.terms);
  const D = BigInt(p.deploy.D);
  const team = p.deploy.team ? { npk: frFromHex(p.deploy.team) } : null;
  await st.vault.releaseInputs(p.inputs);
  await syncNotes();
  const s = await getSyncer();
  const tip = await esplora.tipHeight();
  await carry({
    kind: 'DEPLOY', out: 'deploy-out', feeRate: p.feeRate, tip,
    plan: () => planDeployBurn({ vault: st.vault, sync: s, tip, d, D, team }),
    label: `DEPLOY of ${d.ticker}, proved again`,
    deploy: p.deploy,
    sweep: p,
  });
  await st.vault.updatePending(p.id, { status: 'replaced' });
}
