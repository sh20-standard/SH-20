// Cross-check of several independent indexers before a mint.
//
// One indexer is enough to use the vault, but it is then trusted for what the
// chain alone cannot show the vault: which DEPLOY of a ticker came first.
// With several, the vault requires them to agree on the token's terms and,
// when they are at the same height, on the state digest.
// Any disagreement refuses the mint; an unreachable indexer or a single one
// only warns.

// Fixed at DEPLOY (plus where the indexer says it is): must be identical everywhere.
// mints and burned change every block, so they are not compared.
export const TERMS = ['ticker', 't', 'max', 'lim', 'pre', 'start', 'end', 'unlock', 'price', 'payMode', 'payScript', 'deployTxid', 'deployHeight', 'genesis'];
// Profile constants from /status: the genesis token's start is the activation height,
// and every DEPLOY burns deployBurn SH20. Indexers on the same profile report the same.
export const PROFILE = ['activationHeight', 'deployBurn', 'deployMaturity', 'genesis'];

/** The profile an indexer reports, with deployBurn as a bigint (null when absent). */
export function profileOf(status) {
  const n = (x) => (x === undefined || x === null || x === '' ? null : x);
  return {
    activationHeight: Number.isInteger(status?.activationHeight) ? status.activationHeight : null,
    // anything but a whole number is unknown (never thrown: an indexer must not break the page)
    deployBurn: /^[0-9]{1,20}$/.test(String(n(status?.deployBurn))) ? BigInt(status.deployBurn) : null,
    genesis: n(status?.genesis),
    // N: a DEPLOY reveals a commit confirmed at least N blocks earlier (SPEC-WIRE §5); null if not reported
    deployMaturity: Number.isInteger(status?.deployMaturity) && status.deployMaturity >= 0 ? status.deployMaturity : null,
  };
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
    for (const r of ok) if (r.status.network && r.status.network !== 'signet') problems.push(`${r.base} follows ${r.status.network}, not signet`);

    const ref = ok[0];
    const profile = profileOf(ref.status);
    for (const r of ok.slice(1)) {
      const p = profileOf(r.status);
      const diff = PROFILE.filter((k) => String(p[k]) !== String(profile[k]));
      if (diff.length) problems.push(`${r.base} and ${ref.base} follow different profiles: ${diff.map((k) => `${k} ${p[k]} ≠ ${profile[k]}`).join(', ')}`);
    }
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

    return { token: ref.token, profile, agreed: problems.length ? 0 : ok.length, problems, warnings };
  }
}
