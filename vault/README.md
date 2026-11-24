# sh20-vault

Browser vault for **SH-20** (spec draft v0.3, **signet only**): a static page with no server of
ours, which you can host on IPFS. Keys are generated and kept on the device. Bitcoin is paid
and signed by **Xverse, UniSat or Leather**. Tickers and mints are read from any SH-20 indexer API.

What works today, without proofs:

- a vault seed created in the browser, stored in `localStorage`, encrypted with AES-GCM under
  a PBKDF2-SHA256 passphrase key (600,000 iterations), which can be added or changed at any time,
  with backup (only ever encrypted) and restore. Each note is a record of its own in IndexedDB,
  encrypted under the same key with its id as associated data, written when it changes and only
  then (`src/notestore.js`); a sync writes once, and a note's path and spent status, which every sync
  computes again, are not stored (docs/audit/2026-11-24-vault.md, vault-3: notes anyone sends no
  longer make each sync rewrite the whole vault, nor fill the 5 MB of `localStorage`);
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
npm test                 # 200 tests (one skipped: SH20_PROVER_CHECK=1 rebuilds the prover), Node ≥ 20, zero dependencies
npm run build            # vault/dist/ from the working tree (development, the test profile)
node build.js --signet   # the same on the signet profile (once its activation height is fixed)
node build.js --mainnet --activation A   # the same on the mainnet profile from block A (or the A fixed in src/profile.js)
npm run release          # a verifiable release from the current commit, on the signet profile (below)
```

The whole flow on Bitcoin Core regtest (what the CI runs, job `vault-regtest`):

```sh
node dev/regtest.js --isolate   # bitcoind (tools/bitcoind.sh: a pinned release, SHA-256 checked), two indexers, the page
node dev/e2e.js                 # headless Chrome: mint, TRANSFER, DEPLOY, BURN, LIST, TAKE, cancel, CLAIM, restore
node dev/regtest.js --isolate --mirror   # the same, the page reading the indexers' static mirrors only
E2E_MIRROR=1 node dev/e2e.js
node dev/before-a.js            # no chain: the signet release before its block A, on two mirrors before A; an indexer that verifies no spend named beside the balance
```

`dev/regtest.js` runs Bitcoin Core on a regtest chain of its own (in a temporary folder) with the
network's relay policy (`-acceptnonstdtxn=0`), two reference indexers that each follow it over RPC as
`indexer/bin/follow.js` does, with the real PLONK verifier, and an Esplora API over the RPC that
mines every broadcast in a block of its own. The page's wallet is `dev/test-wallet.js`: one taproot
key that signs for real (BIP341), so Bitcoin Core checks every transaction the page and the wallet
sign: the commits, the reveals by script path, the offers signed `SIGHASH_SINGLE | ANYONECANPAY`, the
TAKE, the cancel and the CLAIM. No real wallet, no signet coins.

The demo chain (a mock Esplora that takes any transaction), for the variants:

```sh
node dev/serve.js        # http://localhost:8000/vault/, API on :8020 (not isolated: the prover runs on one thread)
node dev/serve.js --isolate                   # with COOP/COEP: shared memory, the prover's thread pool
node dev/e2e.js          # the same flow as on regtest, on the demo chain
E2E_PATH=/vault/dist/vault/ node dev/e2e.js   # the same flow on the IPFS build
E2E_HOST=<cid>.ipfs.localhost node dev/e2e.js # a subdomain gateway: the page isolates itself (service worker)
E2E_PATH=/ipfs/<cid>/vault/ node dev/e2e.js   # a path gateway: the page refuses to run and names its subdomain address
E2E_LIAR=1 node dev/e2e.js                    # a lying indexer in the list: the mint is refused

node dev/serve.js --deploy-burn 0 [--deploy-maturity 0]   # every indexer on another profile, lying together
E2E_OTHER_PROFILE=1 node dev/e2e.js           # the page names each one and what differs, mints and deploys nothing
```

`dev/serve.js` serves the real indexer API (`indexer/src/api.js`) over a small demo chain of
serialised transactions, with the reference profile, the vault's own (`DEFAULT_PROFILE`: D = 1000, N = 6; the chain starts at
the activation height), and the real PLONK verifier (from
`vault/prover/sh20_circuit.wasm`). Its mock Esplora serves those transactions and "mines" every
broadcast one into the next block. The e2e run mints 2,000 SH20, syncs, sends 700 privately to
another wallet's sh20 address (proved in the page), finds its 1,300 of change by scanning, deploys
a ticker that burns 1,000 SH20 with a proof (the commit, a countdown, a reload of the page in the
middle of the wait, then the reveal once the commit is 6 blocks deep: `POST /esplora/mine?n=` makes
the mock chain advance), finds the 300 left, burns 100, lists 150 for 5,000
sats, copies the offer, checks it and buys it back (the listing is SOLD and a public note of 150
appears), lists 50 and cancels it, lists 40 and has the offer completed without its TAKE (the
seller is paid, the listing CLOSED), claims the 40 back, then erases the vault, restores it from the 12 words alone and
requires the same address, the same notes and the same listings, then moves the page's clock on
until the vault locks itself, and opens it again with its passphrase. Measured in headless Chrome on a
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
- **On the signet profile:** a release replaces `src/profile-name.js` with `'signet'`, the one file
  that differs from `npm run build` (`build.js`), and refuses while `src/profile.js` has no signet
  activation height (`test/signet.test.js`).
- **Publish, never from your own machine:** an IPFS node announces its IP address for every block it
  provides. `release/sh20-vault-<version>.car` holds the blocks of the CID (CARv1, imported by kubo
  0.32.1 with the same root); a pinning service takes it from the `release` workflow's artifact.
  [`RELEASES.md`](RELEASES.md) has the whole procedure.
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
  one origin per CID) the vault registers the phone test page's service worker (byte for byte
  `circuit/web/sw.js`, which a test checks), which re-serves the page's own responses with the
  headers; the page reloads once and proves on the pool (4.7 s instead of 26 s on a laptop). The
  build puts it at the root of the site (`sw.js`, from `vault/sw.js`), with the root as its scope: the
  pool's threads (`circuit/web/thread-worker.js`) are outside `vault/`, and a worker it did not
  control would get neither the headers nor the shared memory. On a subdomain gateway that root is
  the CID's own. On a **path gateway** (`…/ipfs/<cid>/`) it never does: every site there shares one
  origin, and a service worker would sit in front of all of them (`src/isolation.js`). The pool has
  `defaultThreads()` threads (`circuit/web/host.js`): the cores the browser reports, and at least 6
  on an iPhone, whose Safari reports 4.
- **Why `chrome-extension:` and `moz-extension:` stay in `script-src`:** Xverse, UniSat and Leather
  inject their wallet provider into the page as a script served from their own extension, which only
  an installed extension can serve, so allowing these schemes lets the wallets work without letting
  any website's script in.

## Hosting and keys

- Use a **subdomain gateway** (`<cid>.ipfs.dweb.link`), a local IPFS node or a local copy. On a
  path gateway (`…/ipfs/<cid>/`) every site shares one origin and could read the vault, change its
  servers or drive it once unlocked: the page refuses to run there (no vault is created, restored
  or unlocked, the settings are not read) and names the same CID on a subdomain gateway and on a
  local node (`src/isolation.js` `ownOrigins`). A vault stored at that origin by an earlier version
  is flagged: treat its words as exposed.
- Each CID is its own origin with its own empty storage. When moving to a new version, download
  the backup first and restore it on the new page.
- The backup file is the whole vault, its notes in it, in one record as earlier versions wrote it,
  and is only written encrypted: a vault without a
  passphrase has to set one first ("Set a passphrase"; "Change passphrase" asks the current one).
  A clear backup from an earlier version, restored with a passphrase, is encrypted with it. On an
  encrypted vault the recovery words are shown after the passphrase. A tab that holds the vault
  locks when another tab writes it, and never writes its older copy back. The seed derives every
  note key, so the backup does not need to be refreshed after each mint.
- The vault locks itself after 10 minutes without use (`src/autolock.js`), never during an action
  nor while a DEPLOY waits for the reveal the page sends. A lock (by the button, by time or by
  another tab) zeroes the master secret, the viewing key and the lock keys, lets go of the rest, and
  stops the prover, whose memory holds the last witness; the prover is stopped after every proof too.
  What JavaScript cannot overwrite (`BigInt` scalars, the words as a string) stays in memory,
  unreachable, until it is reused (docs/AUDIT.md §8.8).
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
  never repeats), so a restored or watch-only vault finds it again. A restored vault (a backup, which
  has the counters of its day, or the words, which start at 0) reserves no note key and no lock key
  until a sync has read every leaf and every listing; it then skips 10 note keys and 3 lock keys past
  the last one used, for what another device may have had broadcast and not yet mined (docs/AUDIT.md §8.9).
- **Batch mint:** the mint panel takes `k` from 1 to 10. One envelope then asks for `k` mints and
  pays `k × price`, for one note of `k × lim` (one more byte, `k` omitted when 1). The vault never
  asks for more mints than are left: an indexer gives a late batch only what is left and keeps the
  whole payment, which the panel says when `k > 1`.
- payMode 1 burns the price **on the envelope output itself**, so a burn mint has no extra output.
- Coins: confirmed ones only, by Esplora's word, a wallet's own list included (`ui/spends.js`
  `walletUtxos`): an unconfirmed coin can be replaced by whoever paid it, and the transaction funded
  with it leaves every mempool. Of those, the smallest single UTXO that pays everything, else the
  fewest UTXOs (largest first); the change output is dropped when it would be dust.
- Before anything is signed, the vault checks what the indexers will check (window open at the
  next block, not sold out, `k` not above what is left, payment present), because a rejected mint is not refunded.
- **The genesis token SH20** is part of the profile, not a DEPLOY (`/tokens` lists it first, with
  `genesis: true` and `deployTxid: null`). Its terms are checked against constants in the vault
  (`src/profile.js`: `SH20`, max 21,000,000, 1,000 per mint, no team, price 0, payMode 0, no end,
  start = the activation height), which a test compares with `indexer/src/constants.js` and the
  vectors. Only `SH20` takes this path: another ticker that an indexer calls genesis, or SH20
  named with a DEPLOY, is refused. The start is the vault's own activation height, never an indexer's.
- **The profile** is embedded (`src/profile.js`): `A`, `D = 1000`, `N = 6`, `W`, `K_min` and the
  genesis ticker, from the reference indexer's constants (`indexer/src/constants.js`
  `DEFAULT_PROFILE`), never from `/status`. Every value `/status` reports (`network`,
  `activationHeight`, `deployBurn`, `deployMaturity`, `anchorWindow`, `genesis`) is compared with it
  (`src/consensus.js` `profileCheck`): an indexer that reports another value, or none, is named on
  the page with what differs, and while it is configured the vault does nothing. It mints, deploys,
  reveals, burns, lists, transfers, buys, cancels and claims nothing, and asks every indexer again just
  before each of these. Several indexers that agree with each other but not with the vault are all refused.
- **Three profiles, one rule set.** `PROFILES.test` is `DEFAULT_PROFILE` as it is (`A` = 0: the dev
  servers, the tests, the CI); `PROFILES.signet` is the same with the public signet's activation
  height, `SIGNET_ACTIVATION_HEIGHT`, fixed at its launch (`RELEASES.md`); `PROFILES.mainnet` the same
  with Bitcoin mainnet's, `MAINNET_ACTIVATION_HEIGHT` or `build.js --mainnet --activation A`, and the
  network its indexers report, `main` (Bitcoin Core's chain name; `follow.js --network main` with an
  Esplora source). The page follows the one `src/profile-name.js` names: `test` in the source tree,
  with a warning on screen; `signet` or `mainnet` in a release. Its indexers run
  `follow.js --activation <that height> --deploy-burn 1000`.
- **The network follows the profile** (`src/profile.js` `CHAIN`): Bitcoin addresses (`btc.js`, `tb1…`
  on signet, `bc1…`, `1…`, `3…` on mainnet), SH-20 addresses (`tsh20…` or `sh20…`, SPEC-NOTES §2),
  what Xverse, UniSat and Leather are asked for, and the network a vault records: a vault or a backup
  made on another network is not opened (its 12 words restore it).
- **Default servers** (`src/servers.js`), for the profile the page follows: on signet, the two mirrors
  the site serves beside the page (`../api/js/` and `../api/rs/`, `docs/API.md`, "The static mirror")
  and mempool.space's signet Esplora; on mainnet, no indexer (Settings asks for one: your own
  `follow.js`, or indexers you trust) and mempool.space's Esplora; on the test profile, the two dev
  indexers and their Esplora.
  None is run by the SH-20 contributors, and `test/signet.test.js` names every host a URL in the site
  may use. Settings replaces them; your own `follow.js` is fresher than a mirror, which lags the chain
  by 10 to 30 minutes.
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
  `unlock`, `price`, `payMode`, `payScript`, `deployTxid`, `deployHeight`, `genesis`), if one follows
  another profile than the vault's, if one does not know the
  ticker, or if two at the same height report different `digest`s. Indexers a block apart are
  retried, then compared on terms only, with a warning. An unreachable indexer, or a single one,
  only warns. After every sync, the others are asked for the tree's root and the digest after
  the synced block (`/roots`, `/digest/:height`), compared with the root the vault rebuilt from the
  primary's leaves and with the primary's digest: the notes panel shows how many agree next to the
  balance, and a disagreement in red.
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

- **`D > 0`** (the vault's profile, `D = 1000`; an indexer that reports another `deployBurn` stops
  the deploy screen): the DEPLOY burns `D` SH20 with a proof. It
  carries a spend (`vPub = D`, `tPub = t("SH20")`) over at most two of your SH20 notes, and the
  change comes back as a shielded note; the screen shows which unspent SH20 notes would pay it, and
  the envelope size in the witness carrier (56 bytes + `psLen`, + 32 with a team allocation, + 824
  for the spend: wire v0.3, a 32-byte X25519 `pk_eph` per output and no `proofLen`). The size comes
  from serialising a placeholder spend with the indexer's codec; nothing is sealed or sent.
- **`D = 0`**: no spend and no proof, but still a commit and a reveal (56 bytes + `psLen`, + 32 with a team).

**DEPLOY maturity** (SPEC-WIRE §5, against ticker sniping). A DEPLOY is never in an OP_RETURN, where
its ticker would show before anything is confirmed: it is always the reveal of a commit, and the
indexers accept it only if the commit was confirmed at least `N` blocks before the reveal's block
(`N = 6`, from the vault's profile: the reveal waits that many blocks whatever an indexer or an old
record says, `send.js` `deploySchedule`). Someone
who copies the ticker from the mempool needs a commit of their own, too young by the time the
original goes in. So the vault:

1. proves the burn (`D > 0`) the way a transfer is proved (below): the spend takes the SH20 notes,
   the change and two unused outputs are sealed to the vault itself, and the envelope is the DEPLOY;
2. has the wallet sign the commit and broadcasts it, and keeps the signed reveal, with the
   one-time key and the terms, in the encrypted state: a reload, or closing the tab, loses nothing;
3. reserves the SH20 notes the burn spends while it waits (status `spending`): no other spend takes
   them;
4. on every refresh, sync and minute while the vault is open (`processDeploys`), reads the commit's
   height from Esplora and shows a countdown ("reveal in 5 blocks"); once the reveal can land at a
   height `≥ commit + N` (`deploySchedule`, `N` of the vault's profile) it checks that every indexer
   still follows the vault's profile and that the ticker is still free, then broadcasts the reveal.
   A ticker taken meanwhile gives the reserved notes back;
5. if the proof's anchor would be out of the window `W = 100` by then (a commit that stayed
   unconfirmed for long), marks the DEPLOY "Prove again": the vault proves it on today's tree and
   makes a new commit, which spends the old commit output by its key path (the one-time key, tweaked
   with the leaf), so its sats come back; the new commit matures in its turn.

A team allocation gets one of the vault's public note keys, found by the sync when its block comes.
Before signing, the vault asks the indexers again for their profile, the tickers taken and the tip.
A DEPLOY (or any spend) the indexers refused anyway records no nullifier, so it burns nothing: once its
reveal is 6 blocks below the synced tip and none of its notes is spent there, the sync gives the notes
back and says so (`send.js` `refusedSpend`; only the network fees are lost). Not on the word of the
indexer it synced from: every configured indexer must answer, follow the vault's profile and list none
of those nullifiers in its full list from block 0, where an earlier spend of one would show too
(`consensus.js` `refusalAgreed`); else the notes
stay reserved and the next sync asks again. A spend that is never mined (its commit or its reveal
dropped, or replaced with the coin that paid it) gives its notes back the same way once the synced
tip is `W + 6` blocks past its anchor: a spend lands only where `anchorHeight ≥ H − W`, so no block
can take it any more, in that transaction or in a copy, and every indexer must have passed its
anchor plus `W` (docs/audit/2026-11-24-vault.md, vault-2). One the wallet never signed gives them
back at once: the vault signs the reveal only after the commit, so its envelope went nowhere. One
left "prepared" (the page closed while the wallet asked) is listed with **Give up**.
`test/deploy-maturity.test.js` checks the schedule (the countdown, the anchor window), a DEPLOY
without a burn refused one block early and accepted at `N`, one in an OP_RETURN refused, the key-path
sweep of an old commit, and the reserved notes kept across a reload; `test/spend.test.js` runs a
DEPLOY that burns 1,000 SH20 with a real proof through the same wait.

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
   against its public inputs before anything is signed. Each proof gets a seed of 32 bytes from
   `crypto.getRandomValues`, drawn for it alone (`proveWithFreshSeed`): the same seed with two
   witnesses would give the same blinding and unblind the difference of their commitments
   (`docs/AUDIT.md`, doubt 6.6). It is never reused, never stored, never derived from a key or the
   witness; `test/prover-seed.test.js` checks it, and the same witness proved twice gives two
   different valid proofs (`test/spend.test.js`);
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

- **The turnstile** (SPEC-WIRE §5): the indexers keep `pool[ticker]`, what the shielded pool holds of
  a ticker, and reject a BURN, a LIST or a DEPLOY burn that takes out more. Before proving one, the
  vault reads `pool` in `/token/:ticker` from every configured indexer and refuses, saying so, when
  the amount is above the lowest: the transaction would be rejected and its fees lost. Another
  spend in the same block can still lower the pool before this one confirms.
- **BURN** (send panel, "Burn"): a spend with `vPub` = the amount and `tPub = t(ticker)`; the change
  and two unused outputs are sealed to the vault. 842-byte envelope, 342 vB reveal.
- **LIST** (send panel, "Sell for BTC"): a spend that moves the amount into a public escrow
  (`vPub` = amount), with the price and the payee (a signet address, the wallet's by default). The
  reveal's output 0 is the **lock**, a BIP86 key-path output of 330 sats whose key only this vault
  holds: `HMAC-SHA512("sh20/vault/lock", m ‖ u32le(i))`, so the words restore it (these are Bitcoin
  keys of the vault, not note keys: SPEC-NOTES does not define them). The lock's x-only key,
  `lockKey`, is in the LIST's signed body (right after `lockVout`), and the indexers refuse a LIST
  whose output `lockVout` is not `OP_1 <lockKey>`: a copy of the envelope in another transaction
  cannot point the lock at its copier's key. The vault reads it back the same way before signing an
  offer or a TAKE. 918-byte envelope, 361 vB reveal.
- **Offer** ("Copy offer", once the listing is ACTIVE): the lock key signs a spend of the lock with
  `SIGHASH_SINGLE | ANYONECANPAY` that pays the price to the payee at the same index (version 2,
  locktime 0), shared as one line, `sh20offer1:<listing>:<signature>`. A txid does not cover the
  witness, where the LIST is, so the terms signed are ones the vault vouches for (`offerTerms`):
  those of its own record for a listing it sent, refused if the chain or the indexer say otherwise;
  for a listing found again after a restore, a LIST whose nullifiers include one of this vault's
  notes and whose proof verifies for its body against the local tree's root at its anchor; a proof
  that fails there is refused. Only when the vault cannot check (no nullifier of its notes, a local
  tree that does not reach the anchor, a prover that cannot run) does the page show the price and
  payee and ask. The signed terms are shown with the offer.
- **TAKE** ("Buy from an offer"): the vault reads the LIST from the chain (Esplora) and requires
  every indexer that answers to report the same listing, ACTIVE: one that does not know it refuses
  it, and at least two must agree (`consensus.js` `listingCheck`, `TAKE_QUORUM`), since a LIST the
  indexers rejected still looks like one on chain. Only an indexer whose verifier is
  `plonk-bn254-hermez` counts toward the two: one that verifies no spend would vouch for a LIST
  whose proof is anything (docs/audit/2026-11-24-vault.md, vault-16). It can refuse a listing, never
  make it enough; the same holds for a mint and for a spend the vault believes refused, and nothing
  is proved or sent while the primary indexer verifies no spend. It checks the seller's signature for
  that price and payee. And it waits: Buy stays off, with the count, until the LIST is six blocks
  deep at every indexer that answers and at Esplora (`consensus.js` `PAY_DEPTH`). A TAKE pays the
  seller whatever the indexers later decide, and a reorg of the LIST's block can leave the LIST
  transaction in the chain with its envelope refused: the price would be paid for nothing. The payee shows as an address only when its script is a whole standard
  template (P2PKH, P2SH, P2WPKH, P2WSH, P2TR; `btc.js` `scriptType`); any other script shows as its
  hex, and Buy stays off with the reason, since the network would not relay a TAKE that pays it
  (`market.js` `payeeProblem`). Then it builds the buyer's transaction: the lock at input 0 with the seller's
  signature, the price at output 0, the TAKE (an OP_RETURN with a public note key of this vault) and
  the wallet's own inputs, which are the only ones the wallet signs. The tokens become a public note
  of the buyer. A lock is spent once: a sale can be neither doubled nor left unpaid for the seller.
  The buyer relies on the LIST being accepted where the TAKE lands: two indexers that agree, and
  six blocks. A MINT that pays its deployer or burns its price waits the same six blocks after the
  DEPLOY, for the same reason; a free mint, SH20's among them, does not wait.
- **Cancel**: a TAKE by the seller itself, the lock signed by the vault (SIGHASH_DEFAULT): the
  tokens come back as a public note. A TAKE whose outputs pay the payee at least the price counts
  as SOLD, so the cancel sends its change to the wallet's other address when it has one and the
  payee is the paying address (Xverse's and Leather's taproot address): the listing is then
  CANCELLED. With one address only (UniSat), the change stays there and the indexers count a sale to
  oneself; nothing is lost either way.
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

- downloads **every leaf** (`/notes`, paged) and rebuilds the tree locally with the indexer's own
  `NoteTree` (`indexer/src/tree.js`, in the bundle: an append hashes only the subtrees it completes,
  about one Poseidon hash per leaf, a Merkle path is 32 lookups, a reorg a truncation). The local root must equal the indexer's `root` at the same
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
  reorgs; a deeper reorg shows as a root mismatch and triggers one full re-download. Leaves the
  vault has not scanned yet (a sync while it was locked, or a scan that could not be made because
  WebCrypto failed, which is an error, not "not ours") are read again until it has. A note whose
  scan fails does not stop the others: they are scanned, the page shows the error, and the next
  sync reads again from that note (`match.js`). "Rescan from
  zero" ignores the cache; a restored vault always rescans everything to find its notes;
- asks every server what it needs **before the scan, and nothing after it** (`ui/notes-panel.js`
  `syncOnce`; docs/audit/2026-11-24-sealing.md, sealing-1). An output that opens costs its owner about
  0.2 s to scan and one that does not a fraction of a millisecond, and the `pkEph` and `ct` beside a
  leaf are the indexer's word: a request that waited on the scan would tell the indexer, by its own
  clock, whether the vault holds an address and how many outputs are its own. So the notes already
  held, the spends refused, the listings, the DEPLOY reveals and a restored vault's count of keys are
  all read first; the scan then runs with nothing to send until the next sync, which the user or an
  unlock starts, and the DEPLOY timer keeps its own minute (`test/scan-timing.test.js`). The scan
  runs on the page's thread, between WebCrypto calls: a timer that falls during it waits at most one
  output's leaf check, about 0.2 s. (A worker would remove that too; `circuit/js` imports
  `node:crypto`, which only the page's import map resolves.)

Loading a cached tree recomputes it (about 0.2 ms per leaf) to check it against the cached root.
A public note key costs about 170 ms (two BabyJubJub multiplications in `circuit/js`), so a new
vault spends about 8 s once on its first 50 keys, which it then keeps in its encrypted state.

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

The vault reads the API of `indexer/bin/follow.js` ([`docs/API.md`](../docs/API.md), default port 8020), or a static
mirror of it: a base whose `mirror.json` has the format `sh20-api-mirror/1` is read through
`indexer/src/mirror-read.js`, which answers each route below from the mirror's files, each fetched with
`cache: 'no-cache'`. `src/api.js` is the only file that knows its shape:

- `GET /status` → `height`, `digest`, `verifier`, and the profile it follows, compared with the
  vault's: `network`, `activationHeight`, `deployBurn`, `deployMaturity`, `anchorWindow`, `genesis`
- `GET /tokens`, `GET /token/:ticker` → the reference indexer's token records (SH20 first, `genesis: true`;
  `pool`, the turnstile, read from every indexer before a BURN, LIST or DEPLOY burn)
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

`src/sh20.js` imports `indexer/src/carrier.js`, `codec.js`, `constants.js`, `notes.js`, `poseidon.js`,
`schnorr.js` and `tree.js`, and `circuit/js/webcrypto.js`, the wallet reference's browser entry point,
all **unchanged**. Everything that touches a secret goes through the platform's WebCrypto there
(`circuit/js/subtle.js`): X25519 for the viewing key and sealing, HKDF, AES-256-GCM, HMAC-SHA512 for
the master secret and the lock keys, and the EdDSA nonce's SHA-256. What stays in JavaScript is
BabyJubJub and Poseidon, which no browser offers (BigInt, not constant time), and the public hashes.
At start the page calls `available()` and stops with a message if the browser has no X25519 in
WebCrypto (Chrome 133, Firefox 130, Safari 17 or newer) or no secure context. Two shims, which the
import map in `index.html` puts in place:

- `src/shim/buffer.js`: the subset of Node's `Buffer` those files use;
- `src/shim/node-crypto.js`: `createHash('sha256')`, which the indexer's constants call when they
  load (`src/hash.js`). `circuit/js/address.js` and `seal.js` import the names of their synchronous
  functions too; the vault calls none of them, and in the shim they throw.

`test/shim.test.js` checks the shim's SHA-256 against Node's, and runs the indexer's vectors and all
of `circuit/js/vectors.json` (RFC 7748, `available()`, wallets, addresses a payer must refuse, sealed
outputs, public notes, a whole spend) through `webcrypto.js` in that exact setup (no global `Buffer`,
`node:crypto` remapped, Node's `crypto.subtle`). The build keeps the repository layout (`dist/vault/`, `dist/indexer/src/`,
`dist/circuit/js/`) so the relative imports stay valid.

## Layout

| Path | What |
| --- | --- |
| `index.html`, `style.css` | the page |
| `src/app.js` | the page's checks (frame, isolation, WebCrypto), then the boot of the panels |
| `src/ui/context.js` | what the panels share: the servers, the state, the DOM helpers, the warnings |
| `src/ui/vault-panel.js`, `tokens-panel.js` | the vault and wallet; the tickers and the mint |
| `src/ui/deploy-panel.js` | the deploy screen and the DEPLOYs waiting for their commit to mature |
| `src/ui/send-panel.js`, `spends.js` | TRANSFER, BURN, LIST, the spends sent; proving, the commit and the reveal |
| `src/ui/notes-panel.js`, `market-panel.js` | the notes and the private sync; listings and buying from an offer |
| `src/ui/settings-panel.js`, `render.js` | the servers; `renderAll` |
| `src/keys.js` | master secret, recovery words, encrypted storage, backup, the vault's notes, spends under way |
| `src/notestore.js` | where the notes are kept: one record each, in IndexedDB beside the page's localStorage |
| `src/bip39.js`, `src/bip39-english.js` | the 12 recovery words |
| `src/send.js` | a TRANSFER or a DEPLOY with a burn, end to end: plan, prove, commit and reveal |
| `src/market.js` | BURN, LIST, offers, TAKE, cancel and CLAIM |
| `src/autolock.js` | the lock after 10 minutes without use, and what holds it off |
| `src/isolation.js`, `sw.js` | cross-origin isolation on subdomain gateways (the test page's service worker, served at the site's root) |
| `src/spend.js` | inputs, dummy inputs, sealed outputs, body, signatures and the prover's witness |
| `src/prover.js`, `src/prover-worker.js` | the WebAssembly prover, threads or one thread (circuit/web/host.js) |
| `src/taproot.js` | the witness carrier: commit output, reveal, BIP341 signature message |
| `src/secp256k1.js` | what touches a secp256k1 secret, in constant time, no `BigInt`: lock and one-time keys, their tweaks, BIP340 signatures (docs/AUDIT.md §8.7) |
| `prover/`, `tools/prover.sh`, `tools/rustc-host.sh` | the two prover modules, built from `circuit/` with remapped paths and one host line, so that every machine gives the same bytes |
| `src/notekeys.js` | note keys, address, scanning, nullifiers: `circuit/js`, nothing of its own |
| `src/sync.js`, `src/cache.js` | private sync: the local tree (the indexer's `NoteTree`), paths, spends, IndexedDB cache |
| `src/mint.js` | MINT pre-flight checks, coin selection, transaction and PSBT |
| `src/deploy.js` | checks the indexer's mint terms against the DEPLOY transaction, or SH20's against the profile |
| `src/profile.js`, `src/profile-name.js` | the test and signet profiles (`DEFAULT_PROFILE`: A, D, N, W, K_min, the genesis token), never taken from an indexer; which one the page follows |
| `src/servers.js` | the default indexers and Esplora of each profile |
| `src/deploy-plan.js` | the deploy screen: DEPLOY rules, envelope size, the burn of `D` SH20 |
| `src/consensus.js` | cross-checks several indexers: before a mint, before a TAKE, and the state after every sync |
| `src/btc.js` | addresses, transactions, PSBT v0, finalization, size estimates |
| `src/wallets.js` | Xverse, UniSat, Leather adapters (injected providers, no SDK) |
| `src/api.js` | indexer API and Esplora clients |
| `src/hash.js`, `src/bytes.js`, `src/fr.js` | SHA-256 (32-bit operations, no table indexed by data: it also hashes a signature's nonce) and RIPEMD-160, bytes, field elements |
| `src/sh20.js`, `src/shim/` | the reused indexer and `circuit/js` modules and their browser shims |
| `build.js` | the site's file set; `npm run build` writes `dist/` |
| `release.js`, `tools/pack.js` | reproducible release: tar, CAR, SHA-256, IPFS CID, `RELEASES.md` |
| `dev/regtest.js`, `tools/bitcoind.sh` | the vault on Bitcoin Core regtest: two indexers over RPC, an Esplora API, a pinned bitcoind |
| `dev/serve.js`, `dev/static.js` | the demo chain (real indexer API, mock Esplora) and the static server |
| `dev/e2e.js`, `dev/test-wallet.js` | the headless-Chrome end-to-end run and its wallet (a test key that signs for real) |

## Not tested yet

- Live extensions: the adapters follow the providers' current source and docs (checked in
  November 2026), and the flow is tested with a UniSat stand-in only, whose key signs for real on
  regtest. A first signet mint with each real wallet is the next step.
- A real signet broadcast. On regtest, Bitcoin Core accepts every transaction of the flow.
- A real phone: the prover was measured in headless Chrome on a laptop only (26 s on one thread,
  4.7 s on the pool); it needs about 230 MB.
- Real wallets signing a commit or a TAKE: tested with the UniSat stand-in, which signs the inputs
  it is asked to. Whether a wallet extension still injects its provider into a page isolated by the
  service worker (COEP `require-corp`) was not tried with the real extensions.

## License

MIT, see [`LICENSE`](../LICENSE).
