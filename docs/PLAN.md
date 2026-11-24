# Plan: from here to mainnet

Written on 2026-11-23, when the maintainer asked for the best plan and left the open choices to it.
Each step has an owner and a test of done. The decisions it takes are at the end, with their reasons;
the maintainer's "no" to any of them reopens it. How to launch, command by command: `docs/SIGNET.md`.

Owners: **maintainer** (the only one who can open accounts or hold a wallet), **coordination** (the
reference indexer, the spec, the API, the explorer, the docs, merges), **indexer-rs**, **vault**, **circuit**.

## Where things stand

Done: the protocol (wire v0.3), two indexers that agree on every vector, on random chains and route by
route through reorgs, a hardened circuit that proves in 6 seconds on a recent iPhone, a vault that mints,
proves, sells and claims on regtest with every transaction checked by Bitcoin Core.

What stops a launch today: the CI has no runner minutes left on the private repository; no real
wallet has signed yet; the project has no account of its own. Since this plan was written, `indexer-rs`
verifies the real proofs (#66), a relayer exists (#65), and the relation refuses one note as both
inputs, with new keys (#73): the keys of the signet are those of #73.

## 1. Before the move: now, in parallel

| Owner | Work | Done when |
| --- | --- | --- |
| indexer-rs | The PLONK verifier, from the `circuit/` crate only, under the name `plonk-bn254-hermez` | done (#66): `indexer-rs` replays `indexer/vectors/plonk-v0.3.json` as the reference does |
| coordination | `follow.js --data <folder>`: a restart goes on from the blocks it kept instead of replaying from `A` (the "Scale" item of `CLAUDE.md`) | done (2026-11-23): `test/blockfile.test.js`, `test/follow-data.test.js` |
| coordination | The mirror (decision 3): its static profile in `docs/API.md`, then the step of `pages.yml` that builds it | done (2026-11-24): `docs/API.md`, "The static mirror"; `indexer/bin/mirror-check.js` builds both mirrors from a random chain and the explorer reads them in headless Chrome (CI) |
| vault | Reading a mirror: no query string (`indexer/src/mirror-read.js` answers each route from the files), the mirror of the page's own origin first in the signet defaults | the regtest flow passes against a mirror |
| circuit | Nothing blocks on the circuit. The v0.4 transfer body (one ephemeral key, a bare leaf for the relayer: 92 bytes less) on paper, not in code | done (2026-11-23): `circuit/README.md`, "The transfer body of wire v0.4, on paper" |
| everyone | No runner minutes until the move: run the CI's suites locally before pushing, and say which ones ran | — |

## 2. The move: one sitting

1. **maintainer**: an email address made for the project, opened over a VPN, linked to nothing of yours.
   With it and over the same VPN, the GitHub account `sh20-standard` (done 2026-11-24: `SH-20` and `sh20` were
   taken, and GitHub no longer takes Outlook or Hotmail addresses for new accounts): free plan, no payment method,
   two-factor by an authenticator app. Then an empty public repository named `SH-20` (no README, no licence: the
   history brings them).
2. **maintainer**: connect Claude to that account, with access to `sh20-standard/SH-20`. Anthropic then knows that
   both accounts are one person; GitHub and everyone else do not.
3. **coordination**: no pull request left open on the old repository; `rewrite.sh` on its last `main`
   (ready and checked on 2026-11-23: 213 commits, one author, every date in UTC, no session link, the
   new address in `vault/RELEASES.md` and `vault/release.js`); pushed from the session, so that no
   machine of ours touches the new repository; the CI green there.
4. **every tab**: clones `sh20-standard/SH-20` and works there only.
5. **maintainer**: archives the old repository, and deletes it once the new one is checked.

## 3. Soft launch: one or two days, not announced

1. **coordination**: `A` = the signet tip + 6 (about an hour), committed. **maintainer**: Settings → Pages →
   GitHub Actions; the variable `PAGES` = `on`.
2. The mirror running, or, if it is not ready, a computer running both indexers (`docs/SIGNET.md`, step 3).
3. **maintainer**, on a computer, with each of Xverse, UniSat and Leather set to signet: a MINT of SH20, a
   transfer received and one sent, a sale and a purchase. Each failure goes back with the vault's message.
   No DEPLOY (decision 7): the regtest flow already proves and signs one, in private, and a DEPLOY is the
   same commit and reveal for a wallet as a transfer.
4. Fixes, each with its test. A fix that changes a rule takes a new `A`.

What the first testers find has to work: nothing is announced before step 3 passes.

## 4. Announce

`A`, the site's address, the release's SHA-256, and the explorer's link, and that the project's only token
is SH20 and its contributors deploy none (decision 7). From an identity made for the project: a Nostr key
needs no email and no phone number. The repository's README says the same.

## 5. The signet run: two to four weeks

- Testers' phone measurements go in the table of `circuit/README.md`: mid-range phones and Android first.
- Every bug report gets a fix and a test that would have caught it.
- **vault**, with coordination for the spec: the relayer. The code is ours; running one is anyone's.
- **coordination**: pagination of `/nullifiers`, `/roots` and `/listings`.
- **maintainer**: `docs/AUDIT.md` to two auditors for a quote, from the project's identity.

## 6. Mainnet

The audit's findings fixed; a relayer that ran on signet; the mainnet profile (its own `A`, not mined
when it is announced, with `D`, `N`, `W` and `K_min` unchanged); the release pinned on IPFS by a service,
from a workflow (`vault/RELEASES.md`, step 7).

## Decisions taken here (2026-11-23)

1. **The account is `sh20-standard` (`SH-20` was taken), public from the first push.** A public repository gets GitHub's runners and
   Pages for nothing, so no payment method ties the account to a person; the signet is public anyway,
   and SH-20's answer to its competitors is code that anyone can run.
2. **The batch target.** About 223 vB for each relayed transfer on signet (wire v0.3, unchanged); about
   200 vB in the next version of the wire (the 92 bytes above); a transfer that pays several people (52 vB
   for each of ten) designed after the signet and after the first audit. The 150 vB target is dropped:
   it takes three transfers under one proof, which only a relayer who sees its users' amounts, tickers
   and recipients could make.
3. **Phones and the public explorer read a mirror that the site serves itself.** A scheduled run of
   `pages.yml` (every 10 minutes) has both indexers follow a public signet Esplora from the blocks kept in
   its cache, and writes their answers as static files at `/api/js/` and `/api/rs/`. It is not a server of
   ours: GitHub serves it and sees the traffic, the contributors see nothing, anyone can read the run that
   built it, and a fork turns on its own with the same switch. It lags the chain by about 10 to 30
   minutes, since scheduled runs often start late. The vault still names its servers and lets anyone
   replace them, and the launch does not wait for the mirror.
4. **`A` of the soft launch is the tip + 6.** Signet coins are worth nothing, so the maintainer's mints
   before the announcement harm nobody. The rule "not mined when announced" is for mainnet.
5. **No IPFS before mainnet.** On signet the site and the release's SHA-256 are enough; a pinning service
   would be one more account.
6. **No Claude session links** in commits or pull requests (`CLAUDE.md`, rule 5): they tie the work to one
   account. The rewrite drops those of the past.
7. **The contributors deploy no token, on signet or on mainnet.** A ticker the project deployed, even as a
   test, could be found, copied on mainnet and sold as "the project's token". The project's token is SH20,
   and it comes first by construction: it exists from the activation block without a DEPLOY, no DEPLOY can
   take its ticker ("ticker already deployed"), and every DEPLOY burns 1,000 SH20, so every other token is
   born from it, after it. DEPLOY is tested on regtest, where nothing is public.
