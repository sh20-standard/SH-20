// The servers a new vault starts with, for the profile it follows (profile.js). Settings replaces
// them, kept in this browser; a link can propose others for one tab, after a confirmation that names
// them (ui/context.js). Indexers are a list: the first lists tokens and notes, every one of them is
// cross-checked.
//
// No default leads to the SH-20 contributors. The standard needs no server of ours, and a default
// URL of ours would make us one: everyone would ask it first, and it would see who uses the vault.
// The signet defaults are your own indexers (indexer/bin/follow.js --activation A, on your own
// signet node, docs/API.md) and a public Esplora. Indexers run by others can be added at launch
// (vault/RELEASES.md); test/servers.test.js names every host a default may use.

export const SERVERS = Object.freeze({
  // dev/serve.js (a demo chain) and dev/regtest.js (Bitcoin Core): two indexers and their Esplora, on this machine
  test: Object.freeze({
    indexers: Object.freeze(['http://127.0.0.1:8020', 'http://127.0.0.1:8030']),
    esplora: 'http://127.0.0.1:8020/esplora',
  }),
  // the public signet: follow.js on this machine (port 8020, its default), and mempool.space's signet Esplora
  signet: Object.freeze({
    indexers: Object.freeze(['http://127.0.0.1:8020']),
    esplora: 'https://mempool.space/signet/api',
  }),
});

/** The defaults of the settings panel for `profileName`: the indexers one per line, as the panel keeps them. */
export function defaultSettings(profileName) {
  const s = SERVERS[profileName];
  if (!s) throw new Error(`no servers for the ${profileName} profile`);
  return { indexer: s.indexers.join('\n'), esplora: s.esplora };
}
