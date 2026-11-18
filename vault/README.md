# sh20-vault

Browser vault for **SH-20** (draft v0.1, **signet only**): a static page with no server of
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
npm test                 # 24 tests, Node ≥ 20, zero dependencies
npm run build            # vault/dist/ = the site to publish
ipfs add -r --cid-version=1 dist
```

Development (serves the repository root, a mock indexer API and a mock Esplora):

```sh
node dev/serve.js        # http://localhost:8000/vault/, API on :8020
node dev/e2e.js          # headless Chrome runs the whole mint flow with a fake UniSat
E2E_PATH=/vault/dist/vault/ node dev/e2e.js   # the same flow on the IPFS build
```

`dev/serve.js` replays a small demo chain with the reference indexer. Its mock Esplora "mines"
every broadcast transaction into the next block, so the e2e test checks that the indexer
accepts the vault's MINT and that the vault finds the note in the tree afterwards.

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

## How a MINT is built

```
vout 0  OP_RETURN <"SH20" 00 02 tokenNum(4) npk(32) rho(32)>   value = price if payMode 1 (burn), else 0
vout 1  payScript, value = max(price, dust)                     only if payMode 2
vout n  change to the payer                                     only if above dust
```

- payMode 1 burns the price **on the envelope output itself**, so a burn mint has no extra output.
- Coins: the smallest single UTXO that pays everything, else the fewest UTXOs (largest first);
  the change output is dropped when it would be dust.
- Before anything is signed, the vault checks what the indexers will check (window open at the
  next block, not sold out, payment present), because a rejected mint is not refunded.
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

## Provisional note keys

`src/npk.js` holds **the only** derivation of `npk` from the vault seed, marked `PROVISIONAL`
(scheme `provisional-0`). It must be replaced by the spend circuit's exact derivation (tweaked
BabyJubJub spend and nullifier keys, as in Tacit). Every stored note records its scheme. Notes
minted with `provisional-0` are for signet testing and may not be spendable by the final circuit.
`rho` is derived from the seed too (`keys.js`), so recovery needs only the seed.

## Indexer API

The vault reads the API of `indexer/bin/follow.js` (`docs/API.md` on the `indexer-api` branch,
default port 8020); `src/api.js` is the only file that knows its shape:

- `GET /status` → `network` (must be `signet`), `height`, `digest`, `verifier`
- `GET /tokens`, `GET /token/:ticker` → the reference indexer's token records
- `GET /notes?from&limit` → `{ from, total, notes }`, read page by page (5,000 per page)

Big integers arrive as decimal strings, field elements as 64-char hex. The vault downloads every
note and matches its own locally by `npk`, so the indexer does not learn which notes are yours.
It does not take the API's word for a note: it recomputes the leaf from `(t, v, npk, rho)` and
requires it to equal the `leaf` the API reports. `OUT` notes (spend outputs) are skipped until
the `ct` format exists.

Checked against the real handler of the `indexer-api` branch: `dev/serve.js` uses it
automatically when `indexer/src/api.js` is present, and the e2e run passes with it.

## Reusing the indexer code in the browser

`src/sh20.js` imports `indexer/src/codec.js`, `constants.js`, `notes.js` and `poseidon.js`
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
| `src/npk.js` | **provisional** `npk` derivation, isolated |
| `src/mint.js` | MINT pre-flight checks, coin selection, transaction and PSBT |
| `src/btc.js` | addresses, transactions, PSBT v0, finalization, size estimates |
| `src/wallets.js` | Xverse, UniSat, Leather adapters (injected providers, no SDK) |
| `src/api.js` | indexer API and Esplora clients |
| `src/hash.js`, `src/bytes.js`, `src/fr.js` | SHA-256, RIPEMD-160, bytes, field elements |
| `src/sh20.js`, `src/shim/` | the reused indexer modules and their browser shims |
| `build.js` | builds `dist/` for IPFS |
| `dev/` | mock servers and the headless-Chrome end-to-end run |

## Not tested yet

- Live extensions: the adapters follow the providers' current source and docs (checked in
  November 2026), and the flow is tested with a fake UniSat only. A first signet mint with each
  real wallet is the next step.
- A real signet broadcast, and the vault against `follow.js` on a live chain.

## License

MIT, see [`LICENSE`](../LICENSE).
