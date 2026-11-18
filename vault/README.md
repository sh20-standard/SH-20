# sh20-vault

Browser vault for **SH-20** (spec draft v0.2, **signet only**): a static page with no server of
ours, which you can host on IPFS. Keys are generated and kept on the device. Bitcoin is paid
and signed by **Xverse, UniSat or Leather**. Tickers and mints are read from any SH-20 indexer API.

What works today, without proofs:

- a vault seed created in the browser, stored in `localStorage`, encrypted with AES-GCM under
  a PBKDF2-SHA256 passphrase key (600,000 iterations), with backup and restore;
- connecting a wallet and signing PSBTs that the vault builds itself;
- **MINT** end to end: the 74-byte OP_RETURN envelope of `docs/SPEC-WIRE.md`, serialised by
  `indexer/src/codec.js` itself, in one transaction;
- tickers, mint windows and mints from `GET /status`, `/tokens`, `/token/:ticker`, `/notes`;
  your own notes are matched locally, and the seed alone recovers them after a restore.

TRANSFER, BURN, LIST, TAKE and CLAIM wait for the spend circuit.

## Run

```sh
npm test                 # 43 tests (+1 skipped until /nullifiers exists), Node ≥ 20, zero dependencies
npm run build            # vault/dist/ from the working tree (development)
npm run release          # a verifiable release from the current commit (below)
```

Development (serves the repository root, a mock indexer API and a mock Esplora):

```sh
node dev/serve.js        # http://localhost:8000/vault/, API on :8020
node dev/e2e.js          # headless Chrome runs the whole mint flow with a fake UniSat
E2E_PATH=/vault/dist/vault/ node dev/e2e.js   # the same flow on the IPFS build
E2E_LIAR=1 node dev/e2e.js                    # a lying indexer in the list: the mint is refused
```

`dev/serve.js` serves the real indexer API (`indexer/src/api.js`) over a small demo chain of
serialised transactions. Its mock Esplora serves those transactions and "mines" every broadcast
one into the next block, so the e2e test checks the DEPLOY terms, that the indexer accepts the
vault's MINT, and that the vault finds the note in the tree afterwards.

## Releases and IPFS hosting

`npm run release` builds the site **from the git objects of the current commit** (not from the
working tree), packs it as `release/sh20-vault-<version>.tar` and writes the same files to
`release/sh20-vault-<version>/`. It records the source commit, the package's SHA-256 and the
folder's IPFS CID in [`RELEASES.md`](RELEASES.md), which you then commit.

- **Reproducible:** same commit → same bytes, on any machine. The tar is written by
  `tools/pack.js` with fixed metadata (sorted paths, mode 0644, uid/gid 0, mtime 0, no compression,
  since gzip output depends on the zlib build). `node release.js --check <sha256>` rebuilds and
  compares; `test/release.test.js` builds twice and requires identical bytes.
- **The CID is the fingerprint.** `tools/pack.js` computes it the way `ipfs add -r --cid-version=1`
  does (raw leaves, sha2-256, sorted dag-pb directories; checked against kubo 0.32.1), so the CID
  is known before publishing and anyone can recompute it from the commit.
- **Publish:** `ipfs add -r --cid-version=1 --pin release/sh20-vault-<version>` must print the
  recorded CID. Pin it on several nodes or pinning services; nobody needs to keep a server for it.
- **Open:** `https://<cid>.ipfs.dweb.link/vault/` (subdomain gateway: one origin per CID), or a
  local node at `http://<cid>.ipfs.localhost:8080/vault/`. A public gateway is trusted to serve the
  right bytes; a local IPFS node checks every block against the CID.
- **New version, new origin:** each CID has its own storage. Download the vault backup before
  switching, and restore it on the new CID.
- **Nothing from another domain:** the CSP allows scripts from the page's own origin and the import
  map (by hash), no CDN, no remote font or stylesheet; `test/page.test.js` and `test/release.test.js`
  check it. Network calls (`connect-src`) go only to the indexer and Esplora servers you configure.
- **Why `chrome-extension:` and `moz-extension:` stay in `script-src`:** Xverse, UniSat and Leather
  inject their wallet provider into the page as a script served from their own extension, which only
  an installed extension can serve, so allowing these schemes lets the wallets work without letting
  any website's script in.

## Hosting and keys

- Use a **subdomain gateway** (`<cid>.ipfs.dweb.link`), a local IPFS node or a local copy. On a
  path gateway (`…/ipfs/<cid>/`) every site shares one origin and could read the vault; the page
  warns about it.
- Each CID is its own origin with its own empty storage. When moving to a new version, download
  the backup first and restore it on the new page.
- The backup file is the stored record: encrypted if the vault has a passphrase. The seed derives
  every note key, so the backup does not need to be refreshed after each mint.
- Wallet extensions do not inject into `file://` pages, and ES modules do not load there: serve
  the folder over http(s), even locally.
- A strict CSP allows only same-origin scripts plus the import map (by hash); no data from the
  network is ever turned into HTML. The page refuses to run inside a frame.
- Servers given in a link (`?indexer=…&esplora=…`) are used only after a confirmation naming them,
  for that tab only, with a warning on screen: a dishonest indexer could show a wrong price or
  payment address. The suggested fee rate is capped at 200 sat/vB, the vault refuses more than
  1,000 sat/vB, and it asks before signing a fee above 20,000 sats.

## How a MINT is built

```
vout 0  OP_RETURN <"SH20" 00 02 ticker(4) npk(32) rho(32)>     value = price if payMode 1 (burn), else 0
vout 1  payScript, value = max(price, dust)                     only if payMode 2
vout n  change to the payer                                     only if above dust
```

- payMode 1 burns the price **on the envelope output itself**, so a burn mint has no extra output.
- Coins: the smallest single UTXO that pays everything, else the fewest UTXOs (largest first);
  the change output is dropped when it would be dust.
- Before anything is signed, the vault checks what the indexers will check (window open at the
  next block, not sold out, payment present), because a rejected mint is not refunded.
- It does not take the mint terms from the indexer alone: it fetches `deployTxid` from Esplora,
  checks its txid and confirmation height, decodes the DEPLOY with the indexer's own `carrier.js`
  and `codec.js`, and refuses the mint if `ticker`, `max`, `lim`, `pre`, `start`, `end`, `price`,
  `payMode` or `payScript` differ (`src/deploy.js`). This stops an indexer that lies about a real
  DEPLOY, for example with its own `payScript`. Since spec v0.2 the MINT names its token by
  `ticker` and the note's asset id is `t = tickerT(ticker)` (recomputed by the vault, and compared
  with the indexer's `t`), so nothing in the mint depends on a number only an indexer knows. What
  the chain alone cannot show is which of two DEPLOYs of a ticker came first.
- **Several indexers** (optional, Settings, one URL per line; the first lists tickers and notes).
  Before a mint the vault asks all of them (`src/consensus.js`) and refuses the mint if they
  disagree on the token's fixed terms (`ticker`, `t`, `max`, `lim`, `pre`, `start`, `end`,
  `unlock`, `price`, `payMode`, `payScript`, `deployTxid`, `deployHeight`), if one does not know the
  ticker, or if two at the same height report different `digest`s. Indexers a block apart are
  retried, then compared on terms only, with a warning. An unreachable indexer, or a single one,
  only warns.
- After signing, the vault checks that the wallet did not change the transaction, records the
  note, then broadcasts through Esplora. Xverse and Leather return partial signatures and UniSat
  finalizes; `btc.finalizePsbt` handles both.
- Locktime is the current tip (anti fee-sniping), sequence `0xfffffffd`.

Measured with a dummy signature of the real size (`test/mint.test.js`):

| Payer | payMode | Outputs | vsize |
| --- | --- | --- | --- |
| P2TR | 1 (burn) or 0 | OP_RETURN + change | **196 vB** |
| P2WPKH | 2 (pay) | OP_RETURN + payScript + change | 226 vB |

The 196 vB are 10.5 (transaction) + 57.5 (P2TR input) + 85 (OP_RETURN output, of which 74 bytes
are the envelope) + 43 (change). The wallet side has nothing left to trim: getting to the ~165 vB
target needs a smaller envelope, for example dropping `rho` from public openings (−32 vB → ~164 vB),
which is a protocol decision (CLAUDE.md, cost lever 4). With no change output: −43 vB.

## Private sync: tree, paths and spends on the device

Asking an indexer `/path/:pos` or `/nullifier/:hex` for your own notes tells it which notes are
yours. The vault never does (`test/page.test.js` fails if any source calls them, and the e2e run
checks every request the page sends). Instead `src/sync.js`:

- downloads **every leaf** (`/notes`, paged) and rebuilds the tree locally (`src/tree.js`: same tree
  as `indexer/src/tree.js`, keeping every level, so appending k leaves costs about 2k + 32 Poseidon
  hashes and a Merkle path costs none). The local root must equal the indexer's `root` at the same
  height, or the sync fails: an indexer whose leaves do not hash to its own root is refused;
- downloads **every spent nullifier** (`/nullifiers?from=H`, docs/API.md) and checks the vault's
  notes against that set on the device. Until an indexer serves the route (PR #5) spends show as
  "unknown"; the vault never falls back to per-note questions;
- computes each owned note's Merkle path from the local tree and checks it against the local root
  (`Sync.witness`, what a spend will need); nullifiers are computed inside the vault (`Vault.nullifier`),
  so the nullifier key never leaves it;
- **caches** the leaves and nullifiers in IndexedDB (public data only: everything, not what is
  yours), so the next sync downloads only new blocks. Each sync re-reads the last 6 blocks to absorb
  reorgs; a deeper reorg shows as a root mismatch and triggers one full re-download. "Rescan from
  zero" ignores the cache; a restored vault always rescans everything to find its notes.

Loading a cached tree recomputes it (about 0.2 ms per leaf) to check it against the cached root.

## Provisional note keys

`src/npk.js` holds **the only** derivation of `npk` and of the nullifier, marked `PROVISIONAL`
(scheme `provisional-0`). They must be replaced by the spend circuit's exact derivations (PR #4:
`npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)` over BabyJubJub keys, `nf = Poseidon(nk, leaf, index)`). Every stored note records its scheme. Notes
minted with `provisional-0` are for signet testing and may not be spendable by the final circuit.
`rho` is derived from the seed too (`keys.js`), so recovery needs only the seed.

## Indexer API

The vault reads the API of `indexer/bin/follow.js` ([`docs/API.md`](../docs/API.md), default port 8020); `src/api.js` is the only file that knows its shape:

- `GET /status` → `network` (must be `signet`), `height`, `digest`, `verifier`
- `GET /tokens`, `GET /token/:ticker` → the reference indexer's token records
- `GET /notes?from&limit` → `{ from, total, notes }`, read page by page (5,000 per page)
- `GET /nullifiers?from=H` → every nullifier spent from block `H` on
- never `/path/:pos` nor `/nullifier/:hex` (see Private sync)

Big integers arrive as decimal strings, field elements as 64-char hex. The vault downloads every
note and matches its own locally by `npk`, so the indexer does not learn which notes are yours.
It does not take the API's word for a note: it recomputes the leaf from `(tickerT(ticker), v, npk, rho)` and
requires it to equal the `leaf` the API reports. `OUT` notes (spend outputs) are skipped until
the `ct` format exists.

## Reusing the indexer code in the browser

`src/sh20.js` imports `indexer/src/carrier.js`, `codec.js`, `constants.js`, `notes.js`, `poseidon.js` and `tree.js`
**unchanged**. Two small shims make that possible: `src/shim/buffer.js` (the subset of Node's
`Buffer` those files use) and `src/shim/node-crypto.js` (synchronous SHA-256), which the import
map in `index.html` puts in place of `node:crypto`. `test/shim.test.js` runs the indexer's vectors
through that exact setup (no global `Buffer`, `node:crypto` remapped). The build keeps the
repository layout (`dist/vault/` and `dist/indexer/src/`) so the relative imports stay valid.

## Layout

| Path | What |
| --- | --- |
| `index.html`, `style.css` | the page |
| `src/app.js` | UI: vault, wallet, tickers, mint, notes, settings |
| `src/keys.js` | seed, encrypted storage, backup, note openings |
| `src/npk.js` | **provisional** `npk` and nullifier derivations, isolated |
| `src/sync.js`, `src/tree.js`, `src/cache.js` | private sync: local tree, paths, spends, IndexedDB cache |
| `src/mint.js` | MINT pre-flight checks, coin selection, transaction and PSBT |
| `src/deploy.js` | checks the indexer's mint terms against the DEPLOY transaction |
| `src/consensus.js` | cross-checks several indexers before a mint |
| `src/btc.js` | addresses, transactions, PSBT v0, finalization, size estimates |
| `src/wallets.js` | Xverse, UniSat, Leather adapters (injected providers, no SDK) |
| `src/api.js` | indexer API and Esplora clients |
| `src/hash.js`, `src/bytes.js`, `src/fr.js` | SHA-256, RIPEMD-160, bytes, field elements |
| `src/sh20.js`, `src/shim/` | the reused indexer modules and their browser shims |
| `build.js` | the site's file set; `npm run build` writes `dist/` |
| `release.js`, `tools/pack.js` | reproducible release: tar, SHA-256, IPFS CID, `RELEASES.md` |
| `dev/` | dev server (real indexer API, mock Esplora) and the headless-Chrome end-to-end run |

## Not tested yet

- Live extensions: the adapters follow the providers' current source and docs (checked in
  November 2026), and the flow is tested with a fake UniSat only. A first signet mint with each
  real wallet is the next step.
- A real signet broadcast, and the vault against `follow.js` on a live chain.

## License

MIT, see [`LICENSE`](../LICENSE).
