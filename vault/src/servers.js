// The servers a new vault starts with, for the profile it follows (profile.js). Settings replaces
// them, kept in this browser; a link can propose others for one tab, after a confirmation that names
// them (ui/context.js). Indexers are a list: the first lists tokens and notes, every one of them is
// cross-checked.
//
// No default leads to a server of the SH-20 contributors. The standard needs no server of ours, and
// a default URL of ours would make us one: everyone would ask it first, and it would see who uses
// the vault. The signet defaults are the two mirrors the site serves itself (docs/API.md, "The
// static mirror"; docs/PLAN.md, decision 3): `../api/js/` and `../api/rs/`, beside the page, the
// answers of the two indexer implementations written as files by a public workflow run. They are
// files of the page's own origin, about 10 to 30 minutes behind the chain. Your own indexer is
// fresher: `indexer/bin/follow.js --activation A --deploy-burn 1000` on your signet node (docs/API.md),
// added in Settings. A default that is down would hold back what waits for every indexer (a restored
// vault's counters, notes given back after a refused spend), so a local one is not among them. A
// public Esplora completes them; test/signet.test.js names every host a default may use.

export const SERVERS = Object.freeze({
  // dev/serve.js (a demo chain) and dev/regtest.js (Bitcoin Core): two indexers and their Esplora, on this machine
  test: Object.freeze({
    indexers: Object.freeze(['http://127.0.0.1:8020', 'http://127.0.0.1:8030']),
    esplora: 'http://127.0.0.1:8020/esplora',
  }),
  // the public signet: the site's mirrors of follow.js and of indexer-rs follow, and mempool.space's signet Esplora
  signet: Object.freeze({
    indexers: Object.freeze(['../api/js/', '../api/rs/']),
    esplora: 'https://mempool.space/signet/api',
  }),
});

/**
 * The defaults of the settings panel for `profileName`: the indexers one per line, as the panel keeps
 * them, a relative one resolved against `page` (the page's own URL), so Settings shows where it is.
 */
export function defaultSettings(profileName, page = globalThis.location?.href) {
  const s = SERVERS[profileName];
  if (!s) throw new Error(`no servers for the ${profileName} profile`);
  const at = (u) => (/^https?:\/\//.test(u) || !page ? u : new URL(u, page).href);
  return { indexer: s.indexers.map(at).join('\n'), esplora: s.esplora };
}
