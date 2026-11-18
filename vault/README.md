# sh20-vault

Browser vault for **SH-20** (spec draft v0.3, **signet only**): a static page with no server of
ours, which you can host on IPFS. Keys are generated and kept on the device. Bitcoin is paid
and signed by **Xverse, UniSat or Leather**. Tickers and mints are read from any SH-20 indexer API.

What works today, without proofs:

- a vault seed created in the browser, stored in `localStorage`, encrypted with AES-GCM under
  a PBKDF2-SHA256 passphrase key (600,000 iterations), with backup and restore;
- connecting a wallet and signing PSBTs that the vault builds itself;
- **MINT** end to end: the 42-byte OP_RETURN envelope of `docs/SPEC-WIRE.md` (43 bytes for a
  batch of `k` mints), serialised by `indexer/src/codec.js` itself, in one transaction of 164 vB;
- note keys, the **sh20 address** (`tsh20…` on signet) and **scanning of sealed notes**, as
  `docs/SPEC-NOTES.md` defines them, computed by `circuit/js` itself (checked against
  `circuit/js/vectors.json`);
- tickers, mint windows and mints from `GET /status`, `/tokens`, `/token/:ticker`, `/notes`;
  your own notes, public or sealed to your address, are found locally, and the seed alone recovers
  them after a restore;
- the genesis token **SH20**, checked against profile constants in the vault (it has no DEPLOY);
- a **deploy screen** that checks a new ticker's terms with the indexer's rules and shows its cost,
  including the burn of `D` SH20 with a proof.

Sending a DEPLOY with a burn, and TRANSFER, BURN, LIST, TAKE and CLAIM, are spends: they need the
WebAssembly prover wired into the vault, which is not done yet.

## Run

```sh
npm test                 # 59 tests, Node ≥ 20, zero dependencies
npm run build            # vault/dist/ from the working tree (development)
npm run release          # a verifiable release from the current commit (below)
```

Development (serves the repository root, a mock indexer API and a mock Esplora):

```sh
node dev/serve.js        # http://localhost:8000/vault/, API on :8020
node dev/e2e.js          # headless Chrome runs the whole SH20 mint flow with a fake UniSat
E2E_PATH=/vault/dist/vault/ node dev/e2e.js   # the same flow on the IPFS build
E2E_LIAR=1 node dev/e2e.js                    # a lying indexer in the list: the mint is refused

node dev/serve.js --deploy-burn 0             # profile with D = 0: GENE is deployed too
E2E_D0=1 node dev/e2e.js                      # mints GENE, terms checked against its DEPLOY
```

`dev/serve.js` serves the real indexer API (`indexer/src/api.js`) over a small demo chain of
serialised transactions, with the reference profile (D = 1000): a DEPLOY needs a proof there, so
the demo chain holds SH20 and two mints of it. Its mock Esplora serves those transactions and
"mines" every broadcast one into the next block, so the e2e test checks the mint terms, that the
indexer accepts the vault's MINT, that the vault finds the note in the tree afterwards, and that
the deploy screen shows the burn.

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
vout 0  OP_RETURN <"SH20" 00 02 ticker(4) npk(32) [k(1)]>     value = k × price if payMode 1 (burn), else 0
vout 1  payScript, value = max(k × price, dust)                 only if payMode 2
vout n  change to the payer                                     only if above dust
```

- The opening is `npk` alone: a public note has `rho = 0` (wire v0.3). `npk` is the vault's next
  public note key (`docs/SPEC-NOTES.md` §5: derived from the viewing key `ivk` and a counter that
  never repeats), so a restored or watch-only vault finds it again.
- **Batch mint:** the mint panel takes `k` from 1 to 10. One envelope then asks for `k` mints and
  pays `k × price`, for one note of `k × lim` (one more byte, `k` omitted when 1). The vault never
  asks for more mints than are left: an indexer gives a late batch only what is left and keeps the
  whole payment, which the panel says when `k > 1`.
- payMode 1 burns the price **on the envelope output itself**, so a burn mint has no extra output.
- Coins: the smallest single UTXO that pays everything, else the fewest UTXOs (largest first);
  the change output is dropped when it would be dust.
- Before anything is signed, the vault checks what the indexers will check (window open at the
  next block, not sold out, `k` not above what is left, payment present), because a rejected mint is not refunded.
- **The genesis token SH20** is part of the profile, not a DEPLOY (`/tokens` lists it first, with
  `genesis: true` and `deployTxid: null`). Its terms are checked against constants in the vault
  (`src/profile.js`: `SH20`, max 21,000,000, 1,000 per mint, no team, price 0, payMode 0, no end,
  start = the activation height), which a test compares with `indexer/src/constants.js` and the
  vectors. Only `SH20` takes this path: another ticker that an indexer calls genesis, or SH20
  named with a DEPLOY, is refused. The activation height is not fixed yet; until it is, the vault
  takes the indexers' `activationHeight` and requires them to agree on it.
- For every other token the vault does not take the mint terms from the indexer alone: it fetches `deployTxid` from Esplora,
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
  `unlock`, `price`, `payMode`, `payScript`, `deployTxid`, `deployHeight`, `genesis`) or on the
  profile (`activationHeight`, `deployBurn`, the genesis ticker), if one does not know the
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
| P2TR | 1 (burn) or 0 | OP_RETURN + change | **164 vB** |
| P2WPKH | 2 (pay) | OP_RETURN + payScript + change | 194 vB |

The 164 vB are 10.5 (transaction) + 57.5 (P2TR input) + 53 (OP_RETURN output, of which 42 bytes
are the envelope) + 43 (change): the ~165 vB target of CLAUDE.md, reached by v0.3's public
openings without `rho` (it was 196 vB). A batch adds one byte for `k` mints. With no change output: −43 vB.

## Deploy screen

`src/deploy-plan.js` checks a new ticker's terms with the same rules as the indexer (free 4-character
ticker, `pre < max`, `(max − pre)` a multiple of `lim`, `start` after the DEPLOY block, `end` and
`unlock` not before `start`, payMode 0 ⇔ price 0; `test/deploy-plan.test.js` runs each case through
the reference indexer and requires the same verdict). It then shows what the DEPLOY costs:

- **`D > 0`** (the reference profile, `D = 1000`; the vault reads `deployBurn` from `/status` and
  requires every configured indexer to report the same): the DEPLOY burns `D` SH20 with a proof. It
  carries a spend (`vPub = D`, `tPub = t("SH20")`) over at most two of your SH20 notes, and the
  change comes back as a shielded note; the screen shows which unspent SH20 notes would pay it, and
  the envelope size in the witness carrier (56 bytes + `psLen`, + 32 with a team allocation, + 824
  for the spend: wire v0.3, a 32-byte X25519 `pk_eph` per output and no `proofLen`). The size comes
  from serialising a placeholder spend with the indexer's codec; nothing is sealed or sent.
- **`D = 0`**: no proof, one OP_RETURN transaction (56 bytes + `psLen`, + 32 with a team).

The button stays disabled: a DEPLOY with a burn is a spend, like a transfer, and the vault does
not prove spends yet.

## Private sync: tree, paths and spends on the device

Asking an indexer `/path/:pos` or `/nullifier/:hex` for your own notes tells it which notes are
yours. The vault never does (`test/page.test.js` fails if any source calls them, and the e2e run
checks every request the page sends). Instead `src/sync.js`:

- downloads **every leaf** (`/notes`, paged) and rebuilds the tree locally (`src/tree.js`: same tree
  as `indexer/src/tree.js`, keeping every level, so appending k leaves costs about 2k + 32 Poseidon
  hashes and a Merkle path costs none). The local root must equal the indexer's `root` at the same
  height, or the sync fails: an indexer whose leaves do not hash to its own root is refused;
- downloads **every spent nullifier** (`/nullifiers?from=H`, docs/API.md) and checks the vault's
  notes against that set on the device. An indexer without the route shows spends as "unknown";
  the vault never falls back to per-note questions;
- finds the vault's notes in what it downloaded: public notes by `npk` (the next 50 unused public
  keys are looked for, SPEC-NOTES §5), and **sealed outputs** (`OUT`) by opening each one with the
  viewing key (`circuit/js` `scan`: X25519, HKDF, AES-256-GCM, then the leaf check of §4). An output
  of `v = 0` is an unused one and is not kept. Notes are told apart by position, never by leaf;
- computes each owned note's Merkle path from the local tree and checks it against the local root
  (`Sync.witness`, what a spend will need); nullifiers are computed inside the vault (`Vault.nullifier`,
  `Poseidon(nsk + τn, leaf, pos)`), so the nullifier key never leaves it;
- **caches** the leaves and nullifiers in IndexedDB (public data only: everything, not what is
  yours), so the next sync downloads only new blocks. Each sync re-reads the last 6 blocks to absorb
  reorgs; a deeper reorg shows as a root mismatch and triggers one full re-download. "Rescan from
  zero" ignores the cache; a restored vault always rescans everything to find its notes.

Loading a cached tree recomputes it (about 0.2 ms per leaf) to check it against the cached root.
Measured in Node under the browser shims: a public note key costs about 170 ms (two BabyJubJub
multiplications in `circuit/js`), so a new vault spends about 8 s once on its first 50 keys,
which it then keeps in its encrypted state; opening someone else's sealed output costs about 1.3 ms.

## Note keys and the sh20 address

`src/notekeys.js` is the only place that turns the seed into keys, and it computes nothing of its
own: it calls `circuit/js` (`walletKeys`, `publicOpening`, `scan`, `encodeAddress`, `nullifier`), the
wallet reference that the circuit's Rust model checks. The vault's 32-byte seed is the master
secret `m` of `docs/SPEC-NOTES.md` §1. From it come `ask`, `nsk` and the viewing key `ivk`, the
address `tsh20…` (bech32m of `IVK ‖ A ‖ N`, shown in the vault section), the public notes of §5
(from `ivk` and a counter) and the per-note keys of sealed notes.
`test/keys.test.js` derives the three wallets of `circuit/js/vectors.json` from their `m` and requires
every key, address, public note, sealed output and nullifier of the vectors.

A vault made before v0.3 (scheme `provisional-0`) keeps its old notes aside in the backup and starts
its counter again: those notes cannot exist on a v0.3 chain. The vault does not take a BIP39
mnemonic yet (SPEC-NOTES §1 allows one); its seed is random and kept in the backup file.

## Indexer API

The vault reads the API of `indexer/bin/follow.js` ([`docs/API.md`](../docs/API.md), default port 8020); `src/api.js` is the only file that knows its shape:

- `GET /status` → `network` (must be `signet`), `height`, `digest`, `verifier`, `activationHeight`,
  `deployBurn`, `genesis`
- `GET /tokens`, `GET /token/:ticker` → the reference indexer's token records (SH20 first, `genesis: true`)
- `GET /notes?from&limit` → `{ from, total, notes }`, read page by page (5,000 per page); public
  notes carry `ticker`, `v`, `npk`, sealed ones (`OUT`) `pkEph` (32 bytes) and `ct` (28 bytes)
- `GET /nullifiers?from=H` → every nullifier spent from block `H` on
- never `/path/:pos` nor `/nullifier/:hex` (see Private sync)

Big integers arrive as decimal strings, field elements as 64-char hex. The vault downloads every
note and matches its own locally by `npk`, so the indexer does not learn which notes are yours.
It does not take the API's word for a note: it recomputes the leaf from `(tickerT(ticker), v, npk, 0)` and
requires it to equal the `leaf` the API reports; a sealed output counts only if it opens and its
plaintext hashes to its leaf. The vault compares state digests between indexers as opaque values
and never recomputes them, so the byte encoding of the events (SPEC-WIRE §6) does not concern it.

## Reusing the indexer and circuit code in the browser

`src/sh20.js` imports `indexer/src/carrier.js`, `codec.js`, `constants.js`, `notes.js`, `poseidon.js`
and `tree.js`, and `circuit/js/address.js`, `babyjub.js`, `notes.js` and `seal.js`, all
**unchanged**. Two shims make that possible, which the import map in `index.html` puts in place:

- `src/shim/buffer.js`: the subset of Node's `Buffer` those files use;
- `src/shim/node-crypto.js`: Node's synchronous `createHash` (SHA-256, SHA-512), `createHmac`,
  `hkdfSync`, AES-256-GCM ciphers and X25519 keys, in plain JavaScript (`src/hash.js`,
  `src/aesgcm.js`, `src/x25519.js`). WebCrypto has all of them, but only asynchronously, and
  `circuit/js` calls them synchronously. Like `circuit/js` itself, this code is **not constant
  time** (BigInt and table lookups); SPEC-NOTES §6 says so for the reference too.

`test/shim.test.js` compares every shimmed function with Node's own on random inputs, and runs the
indexer's vectors and all of `circuit/js/vectors.json` (RFC 7748, wallets, addresses a payer must
refuse, sealed outputs, public notes, a whole spend) through that exact setup (no global `Buffer`,
`node:crypto` remapped). The build keeps the repository layout (`dist/vault/`, `dist/indexer/src/`,
`dist/circuit/js/`) so the relative imports stay valid.

## Layout

| Path | What |
| --- | --- |
| `index.html`, `style.css` | the page |
| `src/app.js` | UI: vault, wallet, tickers, mint, deploy, notes, settings |
| `src/keys.js` | seed, encrypted storage, backup, the vault's notes (public and received) |
| `src/notekeys.js` | note keys, address, scanning, nullifiers: `circuit/js`, nothing of its own |
| `src/sync.js`, `src/tree.js`, `src/cache.js` | private sync: local tree, paths, spends, IndexedDB cache |
| `src/mint.js` | MINT pre-flight checks, coin selection, transaction and PSBT |
| `src/deploy.js` | checks the indexer's mint terms against the DEPLOY transaction, or SH20's against the profile |
| `src/profile.js` | profile constants the vault knows itself: the genesis token, the activation height |
| `src/deploy-plan.js` | the deploy screen: DEPLOY rules, envelope size, the burn of `D` SH20 |
| `src/consensus.js` | cross-checks several indexers before a mint |
| `src/btc.js` | addresses, transactions, PSBT v0, finalization, size estimates |
| `src/wallets.js` | Xverse, UniSat, Leather adapters (injected providers, no SDK) |
| `src/api.js` | indexer API and Esplora clients |
| `src/hash.js`, `src/bytes.js`, `src/fr.js` | SHA-256, RIPEMD-160, SHA-512, HMAC, HKDF, bytes, field elements |
| `src/aesgcm.js`, `src/x25519.js` | AES-256-GCM and X25519, synchronous, for the `node:crypto` shim |
| `src/sh20.js`, `src/shim/` | the reused indexer and `circuit/js` modules and their browser shims |
| `build.js` | the site's file set; `npm run build` writes `dist/` |
| `release.js`, `tools/pack.js` | reproducible release: tar, SHA-256, IPFS CID, `RELEASES.md` |
| `dev/` | dev server (real indexer API, mock Esplora) and the headless-Chrome end-to-end run |

## Not tested yet

- Live extensions: the adapters follow the providers' current source and docs (checked in
  November 2026), and the flow is tested with a fake UniSat only. A first signet mint with each
  real wallet is the next step.
- A real signet broadcast, and the vault against `follow.js` on a live chain.
- Receiving a real sealed note: scanning is tested on the vectors and on a spend made with the
  indexer's mock verifier; the vault cannot send one itself yet.

## License

MIT, see [`LICENSE`](../LICENSE).
