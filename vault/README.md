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
- **private TRANSFER**: proved on the device by the circuit's WebAssembly prover, carried by a
  commit transaction (signed by the wallet) and a reveal (signed by the vault);
- **DEPLOY** of a new ticker, burning `D` SH20 with a proof (or a plain OP_RETURN when `D = 0`);
- **BURN**, and a **market**: LIST tokens for BTC, share a signed offer, buy from an offer (TAKE),
  cancel a listing, CLAIM back a closed one;
- **12 recovery words** (BIP39) that restore the keys, the address, every note and every listing.

## Run

```sh
npm test                 # 81 tests (one skipped: SH20_PROVER_CHECK=1 rebuilds the prover), Node ≥ 20, zero dependencies
npm run build            # vault/dist/ from the working tree (development)
npm run release          # a verifiable release from the current commit (below)
```

Development (serves the repository root, a mock indexer API and a mock Esplora):

```sh
node dev/serve.js        # http://localhost:8000/vault/, API on :8020 (not isolated: the prover runs on one thread)
node dev/serve.js --isolate                   # with COOP/COEP: shared memory, the prover's thread pool
node dev/e2e.js          # headless Chrome: mint, TRANSFER, DEPLOY, BURN, LIST, TAKE, cancel, restore from the words
E2E_PATH=/vault/dist/vault/ node dev/e2e.js   # the same flow on the IPFS build
E2E_HOST=<cid>.ipfs.localhost node dev/e2e.js # a subdomain gateway: the page isolates itself (service worker)
E2E_PATH=/ipfs/<cid>/vault/ node dev/e2e.js   # a path gateway: no service worker, one thread
E2E_LIAR=1 node dev/e2e.js                    # a lying indexer in the list: the mint is refused

node dev/serve.js --deploy-burn 0             # profile with D = 0: GENE is deployed too
E2E_D0=1 node dev/e2e.js                      # mints GENE, terms checked against its DEPLOY
```

`dev/serve.js` serves the real indexer API (`indexer/src/api.js`) over a small demo chain of
serialised transactions, with the reference profile (D = 1000) and the real PLONK verifier (from
`vault/prover/sh20_circuit.wasm`). Its mock Esplora serves those transactions and "mines" every
broadcast one into the next block. The e2e run mints 2,000 SH20, syncs, sends 700 privately to
another wallet's sh20 address (proved in the page), finds its 1,300 of change by scanning, deploys
a ticker that burns 1,000 SH20 with a proof, finds the 300 left, burns 100, lists 150 for 5,000
sats, copies the offer, checks it and buys it back (the listing is SOLD and a public note of 150
appears), lists 50 and cancels it, then erases the vault, restores it from the 12 words alone and
requires the same address, the same notes and the same listings. Measured in headless Chrome on a
laptop: 26 s per proof on one thread, 4.7 s on the thread pool. `serve.js` answers under
`/ipfs/<cid>/…` like a path gateway, and Chrome resolves `<cid>.ipfs.localhost` to this machine,
so both kinds of gateway are tested without IPFS.

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
  check it. Network calls (`connect-src`) go to the page's own origin (the prover and its key) and to
  the indexer and Esplora servers you configure. `'wasm-unsafe-eval'` lets the page compile the
  prover's WebAssembly (from its own origin); it does not allow `eval` of strings.
- **The prover is in the release:** `vault/prover/*.wasm` (1.1 and 1.3 MB) and the proving key
  `circuit/artifacts/spend.pk` (8.4 MB, checked by the module against its pinned SHA-256). The CID
  covers them like every other file (`tools/pack.js` chunks files above 256 KiB as kubo does).
- **Threads need isolation:** the thread pool needs shared memory, which browsers give only to pages
  served with `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy:
  require-corp`. IPFS gateways do not send them. On a **subdomain gateway** (`<cid>.ipfs.dweb.link`,
  one origin per CID) the vault registers `vault/sw.js`, the phone test page's service worker
  (byte for byte `circuit/web/sw.js`, which a test checks), which re-serves the page's own responses
  with the headers; the page reloads once and proves on the pool (4.7 s instead of 26 s on a
  laptop). On a **path gateway** (`…/ipfs/<cid>/`) it never does: every site there shares one
  origin, and a service worker would sit in front of all of them (`src/isolation.js`). The pool has
  `defaultThreads()` threads (`circuit/web/host.js`): the cores the browser reports, and at least 6
  on an iPhone, whose Safari reports 4.
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

With `D > 0` the button proves the burn and sends it the way a transfer is sent (below): the spend
takes the SH20 notes, the change and two unused outputs are sealed to the vault itself, and the
envelope is the DEPLOY. With `D = 0` it signs one OP_RETURN transaction. A team allocation gets one
of the vault's public note keys, found by the sync when its block comes. Before signing, the vault
asks the indexers again for `D`, the tickers taken and the tip.

## Private transfers

The send panel takes a ticker, an amount and an sh20 address (`tsh20…`, checked as SPEC-NOTES §2
requires). `src/send.js` then:

1. **plans** (`src/spend.js`): one or two unspent notes of the ticker (a second, unused input of
   0 is made up when one note pays); three outputs in random order, the recipient's, the change and
   an unused 0, each sealed with a fresh X25519 key (`circuit/js` `seal`); the envelope laid out by
   the indexer's codec; the body hash and an EdDSA-Poseidon signature per input (`circuit/js`); the
   Merkle paths from the local tree, whose root is the indexer's at the synced block (the anchor;
   the vault refuses a tree more than 90 blocks old, the indexers accept 100). The 3,232-byte
   witness is packed in the order `circuit/src/model.rs` reads it;
2. **proves** (`src/prover.js`, `src/prover-worker.js`): the circuit's WebAssembly prover, wired as
   the phone test page wires it (`circuit/web/host.js` and `thread-worker.js`, unchanged), on a
   thread pool when the page is cross-origin isolated, else on one thread; the proof is checked
   against its public inputs before anything is signed;
3. **carries** (`src/taproot.js`): a commit transaction, built by the vault and signed by the
   wallet, pays a taproot output whose one leaf is `<E> OP_CHECKSIG OP_0 OP_IF "SH20" … OP_ENDIF`;
   the reveal spends it by that leaf, signed by the vault with the one-time key `E`, and returns the
   dust to the wallet. The one-time key is saved in the vault before the wallet signs, so a reveal
   can be sent again ("Spends sent from this vault"); `E` is also the internal key, so the commit
   output can be taken back by the key path if a reveal is never used.

Sizes: an 830-byte TRANSFER envelope, a 339 vB reveal (P2TR return output), plus the commit (an
ordinary payment). The notes spent show as spent at the next sync; the change is found by scanning.

What is checked, with real proofs (`test/spend.test.js`): the public inputs the vault computes for
the circuit's own TRANSFER and BURN of `indexer/test/fixtures/plonk-scenario.json` verify with the
pinned verifying key; a TRANSFER the vault builds, proves and reveals is accepted by the reference
indexer with the pinned PLONK verifier, the recipient's scan finds its note and the vault its
change; and a DEPLOY that burns 1,000 SH20 is accepted the same way. Taproot (tweak, leaf hash,
control block, signature message) is checked against the BIP341 vectors (`test/taproot.test.js`).

## BURN and the market

`src/market.js`, with the same spend machinery as a transfer for the two proof-carrying envelopes:

- **BURN** (send panel, "Burn"): a spend with `vPub` = the amount and `tPub = t(ticker)`; the change
  and two unused outputs are sealed to the vault. 842-byte envelope, 342 vB reveal.
- **LIST** (send panel, "Sell for BTC"): a spend that moves the amount into a public escrow
  (`vPub` = amount), with the price and the payee (a signet address, the wallet's by default). The
  reveal's output 0 is the **lock**, a BIP86 key-path output of 330 sats whose key only this vault
  holds: `HMAC-SHA512("sh20/vault/lock", m ‖ u32le(i))`, so the words restore it (these are Bitcoin
  keys of the vault, not note keys: SPEC-NOTES does not define them). 886-byte envelope, 353 vB reveal.
- **Offer** ("Copy offer", once the listing is ACTIVE): the lock key signs a spend of the lock with
  `SIGHASH_SINGLE | ANYONECANPAY` that pays the price to the payee at the same index (version 2,
  locktime 0), shared as one line, `sh20offer1:<listing>:<signature>`.
- **TAKE** ("Buy from an offer"): the vault reads the LIST from the chain (Esplora) and requires
  every configured indexer to report the same listing, ACTIVE; it checks the seller's signature for
  that price and payee, then builds the buyer's transaction: the lock at input 0 with the seller's
  signature, the price at output 0, the TAKE (an OP_RETURN with a public note key of this vault) and
  the wallet's own inputs, which are the only ones the wallet signs. The tokens become a public note
  of the buyer. A lock is spent once: a sale can be neither doubled nor left unpaid.
- **Cancel**: a TAKE by the seller itself, the lock signed by the vault (SIGHASH_DEFAULT): the
  tokens come back as a public note. The indexers count it CANCELLED, or SOLD when the change
  returns to the payee's own address with at least the price (a sale to oneself: nothing is lost).
- **CLAIM** ("Claim back", for a CLOSED listing, whose lock was spent with no TAKE): a BIP340
  signature by the lock key over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)`, in an OP_RETURN.

The vault follows its listings in the indexer's full `/listings` list, matched on the device (it
never asks `/listing/:txid` about one of its own), and after a restore finds them again by their
lock keys (the first `nextLock + 10`). `/listing/:txid` is asked only about an offer to buy, from
every configured indexer. What is checked against the reference indexer (`test/market.test.js`):
a BURN and a LIST with real proofs and the pinned verifier; an offer that another vault takes,
SOLD, with the buyer's public note in the tree; an offer refused for another price or payee; a
cancel (CANCELLED); and a CLAIM of a closed listing, whose signature the indexer checks, with a
claim by another key refused. The sighash for `SIGHASH_SINGLE | ANYONECANPAY` and the BIP86 tweak
are checked against the BIP341 vectors.

## Recovery words

A new vault gets 12 BIP39 words (128 bits of entropy), shown once on creation and again on
request. They give the master secret of SPEC-NOTES §1: `m` = the first 32 bytes of
HMAC-SHA512("sh20/v0/seed", BIP39 seed), with the BIP39 seed from PBKDF2-HMAC-SHA512 (2,048 rounds,
no BIP39 passphrase). Restoring from the words on an empty page derives the same keys and address
and rescans every leaf: public notes by their keys, sealed ones by opening them. A phrase with a
mistyped word or a wrong checksum is refused, never turned into other keys. `src/bip39.js`, with the
English list in `src/bip39-english.js` (checked against its SHA-256) and the BIP39 vectors
(`test/bip39.test.js`). The device passphrase only encrypts the vault in this browser; it is not
part of the words.

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

`src/notekeys.js` is the only place that turns the master secret into keys, and it computes nothing
of its own: it calls `circuit/js` (`walletKeys`, `publicOpening`, `scan`, `encodeAddress`,
`nullifier`), the wallet reference that the circuit's Rust model checks. The master secret `m` of
`docs/SPEC-NOTES.md` §1 comes from the recovery words. From it come `ask`, `nsk` and the viewing key `ivk`, the
address `tsh20…` (bech32m of `IVK ‖ A ‖ N`, shown in the vault section), the public notes of §5
(from `ivk` and a counter) and the per-note keys of sealed notes.
`test/keys.test.js` derives the three wallets of `circuit/js/vectors.json` from their `m` and requires
every key, address, public note, sealed output and nullifier of the vectors.

A vault made before v0.3 (scheme `provisional-0`) keeps its old notes aside in the backup and starts
its counter again: those notes cannot exist on a v0.3 chain. A vault made before the recovery words
has a random `m` and no words: its backup file restores it.

## Indexer API

The vault reads the API of `indexer/bin/follow.js` ([`docs/API.md`](../docs/API.md), default port 8020); `src/api.js` is the only file that knows its shape:

- `GET /status` → `network` (must be `signet`), `height`, `digest`, `verifier`, `activationHeight`,
  `deployBurn`, `genesis`
- `GET /tokens`, `GET /token/:ticker` → the reference indexer's token records (SH20 first, `genesis: true`)
- `GET /notes?from&limit` → `{ from, total, notes }`, read page by page (5,000 per page); public
  notes carry `ticker`, `v`, `npk`, sealed ones (`OUT`) `pkEph` (32 bytes) and `ct` (28 bytes)
- `GET /nullifiers?from=H` → every nullifier spent from block `H` on
- `GET /listings` → every listing (the vault's own are matched on the device); `GET /listing/:txid`
  only for an offer to buy
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
| `src/app.js` | UI: vault, wallet, tickers, mint, deploy, notes, send, market, settings |
| `src/keys.js` | master secret, recovery words, encrypted storage, backup, the vault's notes, spends under way |
| `src/bip39.js`, `src/bip39-english.js` | the 12 recovery words |
| `src/send.js` | a TRANSFER or a DEPLOY with a burn, end to end: plan, prove, commit and reveal |
| `src/market.js` | BURN, LIST, offers, TAKE, cancel and CLAIM |
| `src/isolation.js`, `sw.js` | cross-origin isolation on subdomain gateways (the test page's service worker) |
| `src/spend.js` | inputs, dummy inputs, sealed outputs, body, signatures and the prover's witness |
| `src/prover.js`, `src/prover-worker.js` | the WebAssembly prover, threads or one thread (circuit/web/host.js) |
| `src/taproot.js` | the witness carrier: commit output, reveal, BIP341 signature message |
| `prover/`, `tools/prover.sh` | the two prover modules, built from `circuit/` with remapped paths |
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
- A real phone: the prover was measured in headless Chrome on a laptop only (26 s on one thread,
  4.7 s on the pool); it needs about 230 MB.
- Real wallets signing a commit or a TAKE: tested with the fake UniSat, which signs the inputs it is
  asked to. Whether a wallet extension still injects its provider into a page isolated by the
  service worker (COEP `require-corp`) was not tried with the real extensions.

## License

MIT, see [`LICENSE`](../LICENSE).
