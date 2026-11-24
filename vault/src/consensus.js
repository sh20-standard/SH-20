// Cross-check of several independent indexers before a mint.
//
// One indexer is enough to use the vault, but it is then trusted for what the
// chain alone cannot show the vault: which DEPLOY of a ticker came first.
// With several, the vault requires them to agree on the token's terms and,
// when they are at the same height, on the state digest.
// Any disagreement refuses the mint; an unreachable indexer or a single one
// only warns.

import { PROFILE } from './profile.js';

// Fixed at DEPLOY (plus where the indexer says it is): must be identical everywhere.
// mints and burned change every block, so they are not compared.
export const TERMS = ['ticker', 't', 'max', 'lim', 'pre', 'start', 'end', 'unlock', 'price', 'payMode', 'payScript', 'deployTxid', 'deployHeight', 'genesis'];
// What /status reports of the profile. Each value must be the vault's own (profile.js): an indexer
// that reports another one, or none, follows other rules, and the vault acts on nothing while it is
// configured. K_min is not in /status; the vault applies its own.
export const REPORTED = ['network', 'activationHeight', 'deployBurn', 'deployMaturity', 'anchorWindow', 'genesis'];

const shown = (x) => (typeof x === 'object' ? JSON.stringify(x) : String(x));

/**
 * How an indexer's /status differs from the vault's profile: [] when it follows the same one. Before
 * block A (height null) the reference indexer reports no `genesis`, the token being created in block
 * A (indexer-rs reports "SH20" from the start, as docs/API.md says): that absence is not a difference
 * until the indexer has a block. Another genesis ticker is one, before A as after.
 */
export function profileDiff(status) {
  const out = [];
  for (const k of REPORTED) {
    const got = status?.[k];
    if (k === 'genesis' && got === null && status?.height === null) continue;
    if (got === undefined || got === null || got === '') out.push(`${k} not reported (the vault has ${PROFILE[k]})`);
    else if (String(got) !== String(PROFILE[k])) out.push(`${k} ${shown(got)}, the vault has ${PROFILE[k]}`);
  }
  return out;
}

/** One line per indexer that follows another profile than the vault, naming it and each difference. */
export function profileProblems(answers) {
  return answers
    .map(({ base, status }) => ({ base, diff: profileDiff(status) }))
    .filter((x) => x.diff.length)
    .map(({ base, diff }) => `${base} follows another profile: ${diff.join('; ')}`);
}

// The one verifier that checks the proof of a spend: the PLONK verifier of circuit/, under the pinned
// key (docs/API.md, /status). Any other name, or none, is an indexer that does not verify spends
// (docs/audit/2026-11-24-verifier.md, verifier-4): `reject-all` refuses them all, `test` accepts
// the vectors' fixed bytes as the proof of anything, a name the vault does not know proves nothing.
export const SPEND_VERIFIER = 'plonk-bn254-hermez';

/**
 * Why the indexer that answered `status` does not verify spends, in words for the page, or null when
 * its verifier is SPEND_VERIFIER.
 */
export function unverifiedSpends(status) {
  const v = status?.verifier;
  if (v === SPEND_VERIFIER) return null;
  if (v === 'reject-all') return 'it refuses every spend (verifier reject-all): a transfer to you does not show, and one you send is refused';
  const named = typeof v === 'string' && v ? `verifier ${JSON.stringify(v)}` : 'it names no verifier';
  return `it does not check the proofs of spends (${named}): a note it lists may not exist`;
}

/**
 * Asks every indexer's /status now. `problems` (profileProblems) must refuse any action; an
 * indexer that does not answer is not compared, but at least one must. `unverified` names each
 * indexer that answered and does not verify spends (unverifiedSpends), in the order of `apis`.
 * Returns { answered, problems, unverified }.
 */
export async function profileCheck(apis) {
  const settled = await Promise.allSettled(apis.map((a) => a.status()));
  const answers = settled.map((r, i) => (r.status === 'fulfilled' ? { base: apis[i].base, status: r.value } : null)).filter(Boolean);
  if (!answers.length) return { answered: 0, problems: ['no indexer answered'], unverified: [] };
  const unverified = answers.map(({ base, status }) => ({ base, why: unverifiedSpends(status) })).filter((x) => x.why);
  return { answered: answers.length, problems: profileProblems(answers), unverified };
}

/**
 * Before the vault gives back the notes of a spend it believes refused (send.js refusedSpend, from the
 * primary indexer's sync): every configured indexer must answer, follow the vault's profile, have
 * passed block `atLeast`, and list none of `nullifiers` (hex) in its full list of spent nullifiers,
 * from block 0, whatever height it gives them: a note spent by this spend or by an earlier one shows
 * there, and no height the primary reported narrows the search (never a question about one
 * nullifier). A primary that hid a nullifier would otherwise have the vault offer spent notes
 * again. Asked only when a spend looks refused. Returns { ok, why }.
 */
export async function refusalAgreed(apis, nullifiers, { atLeast }) {
  if (!apis.length) return { ok: false, why: 'no indexer configured' };
  const mine = new Set(nullifiers);
  const settled = await Promise.allSettled(apis.map(async (a) => ({ status: await a.status(), list: await a.nullifiers(0) })));
  for (const [i, r] of settled.entries()) {
    const base = apis[i].base;
    if (r.status === 'rejected') return { ok: false, why: `${base} did not answer` };
    const { status, list } = r.value;
    const diff = profileDiff(status);
    if (diff.length) return { ok: false, why: `${base} follows another profile: ${diff.join('; ')}` };
    if (!Number.isInteger(status.height) || status.height < atLeast) return { ok: false, why: `${base} is at block ${status.height}, not yet ${atLeast}` };
    if (list === null) return { ok: false, why: `${base} has no /nullifiers` };
    const spent = list.find((n) => mine.has(n.nullifier));
    if (spent) return { ok: false, why: `${base} has its nullifier spent at block ${spent.height}` };
  }
  return { ok: true, why: null };
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

async function ask(api, ticker) {
  const status = await api.status();
  let token = null;
  try {
    token = await api.token(ticker);
  } catch (e) {
    if (e.status !== 404) throw e;
  }
  return { base: api.base, status, token };
}

/**
 * @param apis    IndexerApi instances, primary first
 * @returns { token, profile, agreed, problems, warnings }: `problems` must refuse the mint;
 *          `agreed` = how many indexers gave the same answer.
 */
export async function crossCheck(apis, ticker, { retries = 2, delayMs = 1500, sleep = sleepMs } = {}) {
  for (let attempt = 0; ; attempt++) {
    const settled = await Promise.allSettled(apis.map((a) => ask(a, ticker)));
    const ok = settled.filter((s) => s.status === 'fulfilled').map((s) => s.value);
    const down = apis.filter((_, i) => settled[i].status === 'rejected').map((a) => a.base);
    if (!ok.length) throw new Error(`no indexer reachable (${down.join(', ')})`);

    const problems = [];
    const warnings = [];
    problems.push(...profileProblems(ok)); // each against the vault's own profile, not against each other

    const ref = ok[0];
    if (!ref.token && ok.every((r) => !r.token)) throw new Error(`unknown ticker ${ticker}`);
    for (const r of ok.slice(1)) {
      if (!r.token !== !ref.token) {
        problems.push(`${(r.token ? ref : r).base} does not know ${ticker}, ${(r.token ? r : ref).base} does`);
        continue;
      }
      const diff = TERMS.filter((k) => String(r.token[k]) !== String(ref.token[k]));
      if (diff.length) problems.push(`${r.base} and ${ref.base} disagree on ${ticker}: ${diff.map((k) => `${k} ${r.token[k]} ≠ ${ref.token[k]}`).join(', ')}`);
    }

    const heights = new Set(ok.map((r) => r.status.height));
    if (ok.length > 1 && heights.size > 1 && attempt < retries && !problems.length) {
      await sleep(delayMs); // indexers a block apart: wait for the slower one
      continue;
    }
    if (heights.size === 1) {
      const digests = new Set(ok.map((r) => r.status.digest));
      if (digests.size > 1) problems.push(`indexers disagree on the state at block ${ok[0].status.height}: ${ok.map((r) => `${r.base} ${String(r.status.digest).slice(0, 12)}…`).join(', ')}`);
    } else {
      warnings.push(`indexers are at different blocks (${ok.map((r) => `${r.base} ${r.status.height}`).join(', ')}): state digests not compared, token terms are`);
    }
    if (down.length) warnings.push(`unreachable, not compared: ${down.join(', ')}`);
    if (ok.length === 1) warnings.push('only one indexer answered: which DEPLOY of this ticker came first is not cross-checked. Add independent indexers in Settings.');

    return { token: ref.token, profile: PROFILE, agreed: problems.length ? 0 : ok.length, problems, warnings };
  }
}

// ---- listings, before a TAKE ---------------------------------------------------------------------

/**
 * A TAKE pays the seller's price, and only the indexers decide whether it buys anything: an
 * envelope they rejected (a bad proof, spent nullifiers, the turnstile) still looks like a LIST on
 * chain, with a lock and a valid offer. So a TAKE needs this many indexers reporting the listing
 * the same way (docs/AUDIT.md §8.3).
 */
export const TAKE_QUORUM = 2;

const listingKey = (l) => JSON.stringify(l, (_, x) => (typeof x === 'bigint' ? String(x) : x));

/**
 * Asks every indexer about `listTxid`. One that answers and does not know the listing counts
 * against it, like one that reports other terms or another state: either refuses. An unreachable
 * one is not counted. Returns { listing, agreed, down, enough }: `enough` when at least
 * TAKE_QUORUM indexers agree.
 */
export async function listingCheck(apis, listTxid) {
  const settled = await Promise.allSettled(apis.map((a) => a.listing(listTxid)));
  const known = [];
  const unknown = [];
  const down = [];
  settled.forEach((s, i) => {
    const base = apis[i].base;
    if (s.status === 'rejected') down.push(base);
    else if (s.value) known.push({ base, listing: s.value });
    else unknown.push(base);
  });
  if (!known.length) throw new Error(unknown.length ? `no indexer knows this listing (${unknown.join(', ')})` : `no indexer reachable (${down.join(', ')})`);
  if (unknown.length) {
    throw new Error(`${unknown.join(', ')} ${unknown.length > 1 ? 'do' : 'does'} not know this listing, which ${known.map((k) => k.base).join(', ')} ${known.length > 1 ? 'report' : 'reports'}: it may be an envelope the indexers rejected, and a TAKE of it would pay for nothing`);
  }
  const ref = known[0];
  for (const k of known.slice(1)) {
    if (listingKey(k.listing) === listingKey(ref.listing)) continue;
    const diff = Object.keys({ ...ref.listing, ...k.listing }).filter((f) => listingKey(k.listing[f]) !== listingKey(ref.listing[f]));
    throw new Error(`${k.base} and ${ref.base} disagree on this listing: ${diff.map((f) => `${f} ${listingKey(k.listing[f])} ≠ ${listingKey(ref.listing[f])}`).join(', ')}`);
  }
  return { listing: ref.listing, agreed: known.length, down, enough: known.length >= TAKE_QUORUM };
}

// ---- the synced state, at every sync -----------------------------------------------------------------

/**
 * What the vault shows as received comes from the primary indexer's leaves, checked against that
 * indexer's own root: consistent with itself, not with the chain (docs/AUDIT.md §8.5). At every sync
 * the other indexers are asked for the note tree's root after the synced block, compared with the
 * root the vault rebuilt from those leaves (`root`), and for their digest there, compared with the
 * primary's (`digest`): the root binds what is shown to the leaves the vault checked, which a digest
 * alone would not (a lying primary could copy an honest digest). Returns { height, agreed, total,
 * disagree, behind, down }: `agreed` counts the primary; `behind` have not reached that block.
 */
export async function digestAgreement(apis, height, digest, root) {
  const want = String(digest ?? '').toLowerCase();
  const local = String(root ?? '').toLowerCase();
  const [, ...others] = apis;
  const settled = await Promise.allSettled(others.map(async (a) => [await a.digest(height), await a.rootAt(height)]));
  const out = { height, agreed: want && local ? 1 : 0, total: apis.length, disagree: [], behind: [], down: [] };
  settled.forEach((s, i) => {
    const base = others[i].base;
    if (s.status === 'rejected') return out.down.push(base);
    const [d, r] = s.value;
    if (d === null || r === null) out.behind.push(base);
    else if (want && local && d === want && r === local) out.agreed++;
    else out.disagree.push(base);
  });
  return out;
}

/** One line for the page: how many indexers agree on the state the balance comes from. */
export function agreementText(a) {
  if (a.disagree.length) return `${a.disagree.join(', ')} ${a.disagree.length > 1 ? 'disagree' : 'disagrees'} with the primary indexer on the state at block ${a.height}: notes shown here may not exist on chain.`;
  const extra = [a.behind.length ? `${a.behind.length} not there yet` : null, a.down.length ? `${a.down.length} unreachable` : null].filter(Boolean).join(', ');
  if (a.total === 1) return `One indexer only: the notes shown rest on its word. Add independent indexers in Settings.`;
  return `${a.agreed} of ${a.total} indexers agree on the state at block ${a.height}${extra ? ` (${extra})` : ''}.`;
}
