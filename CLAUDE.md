# CLAUDE.md — SH-20

Read this first. It is the handoff for anyone (human or agent) continuing the work.

## What SH-20 is

An open metaprotocol for **fungible shielded tokens on Bitcoin L1**. Anyone deploys a unique
4-character ticker (first valid DEPLOY wins, like BRC-20), anyone mints it for a public price in BTC,
and after the mint every transfer hides the amount, the sender, the recipient **and the ticker**,
because all tickers share one note tree. Tokens sell for BTC atomically through signed offers.
No soft fork, no sidechain, no bridge, no admin key, no co-signer, no required server:
the standard is meant to run with nobody from the team after activation.

Design rationale: [`docs/DESIGN.md`](docs/DESIGN.md). Normative bytes and rules: [`docs/SPEC-WIRE.md`](docs/SPEC-WIRE.md).

## Hard requirements — do not change without the maintainer

1. **Public mint is mandatory.** A DEPLOY must leave a public mint (`pre < max`).
2. **Fully decentralized after activation.** No admin key, blacklist, freeze, co-signer, platform
   signature, required server or upgrade switch. A fix is a new version byte that indexers opt into.
3. **Honest supply.** Max supply, team allocation and its unlock block are public at DEPLOY. Never add
   anything that hides insider supply or insider selling schedules from buyers.
4. **No project-run trusted setup.** Proofs are PLONK-KZG on the Hermez `pot18` SRS (universal, no
   ceremony); the verifier must stay cross-checked against snarkjs.
5. **Contributor anonymity.** Commit as `SH-20 contributors <contributors@sh20.invalid>`. Never commit
   personal names, emails, IP addresses, wallet addresses or machine paths. No Claude session links in
   commits or pull requests either: they tie the work to one account (`docs/PLAN.md`, decision 6).
6. **Determinism.** Any change to bytes or rules updates `docs/SPEC-WIRE.md`, the tests and
   `indexer/vectors/v0.3.json` (regenerate with `npm run vectors`; bump the draft version if the format changes).

## Repository map

| Path | What |
| --- | --- |
| `docs/DESIGN.md` | why SH-20 is built this way, competitors, open decisions |
| `docs/SPEC-WIRE.md` | wire format and acceptance rules, draft v0.3 (normative for the indexer) |
| `docs/SPEC-NOTES.md` | wallet keys, addresses, note sealing (`pk_eph`, `ct`) and scanning, draft v0.3 (normative for wallets; reviewed once by the circuit session, §8 lists the changes; not audited) |
| `indexer/` | reference indexer, Node ≥ 20, zero dependencies |
| `indexer/vectors/v0.3.json` | deterministic vectors for a second implementation: primitives, envelopes with `bodyHash`, carrier cases, a CLAIM, a 17-block scenario with every root, `eventsH`, digest, refusal and verifier input, and a reorg of its last two blocks; `sections` says what each part means |
| `indexer/vectors/plonk-v0.3.json` | a chain with one spend of each kind under a real proof (a TRANSFER, a BURN, a LIST and the burn of a DEPLOY, with `D = 1000` and every note in SH20), with each verifier call, its nine inputs and its answer (a tampered TRANSFER, LIST and DEPLOY refused), and every root and digest: for an implementation that wires the PLONK verifier (`circuit/README.md`, "The verifier as a library") |
| `indexer-rs/` | a second indexer in Rust, written from the spec alone (clean room): `cargo test --release` replays the vectors |
| `docs/SPEC-GAPS.md` | what the clean-room indexer found open in the spec, and where each point is now settled |
| `docs/AUDIT.md` | the dossier for an external zero-knowledge auditor: scope, the relation constraint by constraint, threat model, open doubts; §8 is a first reading of the vault's cryptography, with its findings |
| `docs/AUDIT-PROMPT.md` | the audits we run ourselves, one part per session: security (`/audit circuit`, `verifier`, `sealing`, `vault`, `indexer`: the attacker, the severities) and code (`/audit code <part>`: what is more than the spec needs, clearer, faster), each leaving a report in `docs/audit/` |
| `docs/PLAN.md` | the plan from here to mainnet: who does what, in which order, and the decisions of 2026-11-23 |
| `docs/SIGNET.md` | the public signet, step by step: what must be true first, the launch, what testers do, when the run stops |
| `docs/API.md` | read-only HTTP API served by `indexer/bin/follow.js` and `indexer-rs follow` (for the vault, the explorer and relayers): one JSON shape for both, checked by `indexer/bin/api-diff.js`; and its static mirror, files a static host serves (`indexer/src/mirror-read.js` answers each route from them) |
| `explorer/` | block explorer: one static page (blocks, transactions, tokens, supply check, indexer comparison) |
| `vault/` | browser vault: keys on the device, mints signed by Xverse / UniSat / Leather, verifiable releases ([`vault/RELEASES.md`](vault/RELEASES.md)) |
| `circuit/` | the spend circuit: PLONK prover and verifier in Rust, WebAssembly build, measurements ([`circuit/README.md`](circuit/README.md)) |
| `circuit/js/` | what a wallet computes, in dependency-free JavaScript: the witness of a spend, and the addresses, sealing and scanning of `SPEC-NOTES.md`. Two entry points with the same names and the same vectors: `index.js` (synchronous, `node:crypto`) and `webcrypto.js` (asynchronous, WebCrypto, for browsers). Checked against vectors written by the Rust models (`cd circuit/js && npm test`, 48 tests) |
| `circuit/circom/` | the same relation in circom, used only to cross-check the Rust circuit |
| `circuit/web/` | the phone test page, and the host side of the threaded WebAssembly prover |
| `relayer/` | a minimal relayer: takes proved TRANSFERs over HTTP, checks them as an indexer would (its fee output, the proof), and publishes them in batches from its own coins ([`docs/RELAYER.md`](docs/RELAYER.md)) |

```sh
cd indexer
npm test            # 83 tests (4 check real proofs, with circuit/'s WebAssembly verifier or the copy in vault/prover/)
npm run vectors     # regenerate the vectors (must be byte-identical across runs)
npm run fuzz        # random chains through both indexers (build indexer-rs first: cargo build --release)
npm run bench       # timings of the hot paths: Poseidon, the tree, a replay, the codec, the API
node bin/replay.js <folder of `bitcoin-cli getblock <hash> 3` JSON files> --deploy-burn D

cd circuit
cargo test --release    # 41 tests, with the shipped proving key (artifacts/spend.pk)
./build-wasm.sh         # two WebAssembly builds: one thread with no imports, and a thread pool over Web Workers
bench/cross-check.sh    # snarkjs against our verifier, both ways (hard requirement 4)
web/build.sh            # the phone test page, in web/dist/ (see circuit/web/README.md)
```

`.github/workflows/ci.yml` runs the tests of `indexer`, `indexer-rs`, `circuit`, `circuit/js` and `vault` on each pull request and on `main` (once per commit, a newer commit cancels the older run), checks that the vectors and the
explorer's demo data regenerate byte for byte, and holds `indexer-rs` and `circuit` to `cargo fmt` and `clippy -D warnings`
(`circuit/rustfmt.toml`: lines of 160, so that formatting moves no line `docs/AUDIT.md` cites). Both crates pin their Rust in
`rust-toolchain.toml` (1.95.0, with rustfmt and clippy): the CI and every machine use the same compiler and the same lints.
`circuit/rust-toolchain.toml` also names the two WebAssembly targets, and the CI rebuilds the two modules the vault ships
(`vault/tools/prover.sh --check`): it fails unless they are the committed bytes, so a change to `circuit/` goes with rebuilt
`vault/prover/*.wasm` in the same pull request. The script builds as from an x86_64 Linux host on every machine
(`vault/tools/rustc-host.sh` says why the host triple would otherwise change the bytes).

`.github/workflows/pages.yml` publishes the vault (`/vault/`, on the signet profile), the explorer (`/explorer/`), the
phone test page (`/phone/`) and a mirror of both indexers (`/api/js/`, `/api/rs/`: `docs/API.md`, "The static mirror") as one
static site on GitHub Pages from `main`, once the repository variable `PAGES` is `on`: no server to rent for the signet's
pages. Every 10 minutes it runs both followers from the block files its last run cached, to the tip of a public signet
Esplora, and writes their answers as files (`indexer/bin/mirror-site.js`; `indexer/bin/mirror-check.js` checks it in the CI,
with the explorer reading both mirrors in headless Chrome). It publishes nothing while the signet's `A` is unset. The vault and the phone page isolate
themselves with their service worker there (Pages sends no isolation headers). The launch, step by step: `docs/SIGNET.md`.

Any pull request that moves a line `docs/AUDIT.md` cites, or renames a test it quotes, updates `docs/AUDIT.md` with it: the CI checks it
(`docs/tools/check-audit-refs.py`; `--fix` rewrites the numbers of lines that only moved).

## Status (draft v0.3)

Done in `indexer/`:
- Strict codec for the 7 envelope types (DEPLOY, MINT, TRANSFER, BURN, LIST, TAKE, CLAIM). Tokens are named by their ticker
  everywhere (since v0.2): the asset id is `t = tickerT(ticker)`, the 4 ASCII bytes as a big-endian u32; `t = 0` is reserved for BTC,
  types `0x08`–`0x0f` for extensions.
- Two carriers: OP_RETURN (small proof-less envelopes, one transaction) and a tapscript witness on input 0 (proof-carrying envelopes, 830 bytes for a TRANSFER).
- Wire v0.3: `pk_eph` is a 32-byte X25519 key and the spend section has no `proofLen` (the proof is always 480 bytes).
  `docs/SPEC-NOTES.md` (draft, reviewed once, not audited) specifies keys, addresses, sealing and scanning for wallets;
  `circuit/src/notes.rs` is its model and `circuit/js` its reference, with shared vectors.
- State machine: tickers, mints with payment checks, team unlocks, the shared Poseidon tree (depth 32), nullifiers, listings (ACTIVE → SOLD / CANCELLED / CLOSED → CLAIMED), per-block undo log for reorgs, running digest over a byte encoding of the events (v0.3, `SPEC-WIRE.md` §6; the GENESIS record commits to the profile's rules), and a turnstile per ticker: no BURN, LIST or DEPLOY burn takes out more than entered the pool in public (`SPEC-WIRE.md` §5), so a circuit bug cannot inflate the supply in the open.
- Poseidon over BN254 written from scratch for 2 to 5 inputs (constants generated with the Grain LFSR, checked against circomlibjs for every width; `poseidon2` is unchanged), BIP340 written from scratch (matches BIP340 vectors 0 and 1).
- Live chain follower (Bitcoin Core RPC or Esplora, reorgs with 288 blocks of undo) and a read-only HTTP API with a per-leaf note log for wallets (`docs/API.md`).
- Explorer (`explorer/index.html`): a block explorer in one static page with no dependency; reads any indexer; demo data built from real indexer output.
- Proof verification is an interface (`verifier.verifySpend`). **The default verifier still rejects every spend.**
  `src/adapters/plonk.js` is the real one: the WebAssembly build of `circuit/`, keyed by the pinned verifying-key digest.
  `test/plonk.test.js` replays a chain with a real TRANSFER and a real BURN. `bin/follow.js` and `bin/replay.js` take it with `--verifier <wasm>`; without the flag they reject every spend.

Done in `circuit/` (2026-11-18):
- The proof system was chosen by measurement: **PLONK-KZG on the Hermez `pot18` setup, 480-byte proofs**.
  Halo2 (2,080 bytes as Tacit lays it out, 800 at the very least), fflonk (608 bytes, and it needs more powers than `pot18` holds)
  and snarkjs' own PLONK prover (73–80 s) were measured and set aside. Table and method: `circuit/README.md`.
- The relation of `docs/SPEC-WIRE.md` §4 as 86,250 PLONK gates (domain 2^17), with its reference model, a prover, a verifier,
  deterministic key generation and the pinned digest `64eaf3fe…513b31f4`.
- Measured on an M1 Pro laptop: proving 1.8 s (10 threads), 9.6 s (1 thread); as WebAssembly 25 s on one thread,
  7.2 s on 4 threads, 4.4 s on 10; verification 1.5 ms; TRANSFER reveal transaction 340 vB.
- The proving key is shipped (`circuit/artifacts/spend.pk`, 8.4 MB, pinned by SHA-256): it loads in 1.4 s in WebAssembly
  instead of 19.5 s of key generation, and a test checks that key generation reproduces it byte for byte.
- Two WebAssembly builds: one thread with no imports (the indexer's verifier, and the fallback), and a thread pool over Web
  Workers on a shared memory. Prover memory: 224 MB.
- A test page for phones (`circuit/web/`): threaded where the page is cross-origin isolated (by headers, or by its service
  worker), one thread otherwise. Checked in headless Chrome for each case.
- Checks: 35 adversarial witnesses, refused by the Rust gates and by circomlib's statement of the relation alike; every
  variable moved one at a time, alone and with what follows recomputed (free: only a dummy input's Merkle siblings and one
  inverse witness); the gadgets at their limits; and snarkjs both ways: its verifier accepts our proofs, our verifier
  accepts its proofs (`bench/cross-check.sh`).
- Hardened before the signet (2026-11-19): `Ak` and `R8` are checked to be on the curve (16 gates, new keys).
  `docs/AUDIT.md` §6 says what that closes and what stays open.
- `nf0 ≠ nf1` is in the relation (maintainer, 2026-11-23; 2 gates, new keys, digest `64eaf3fe…513b31f4`): one note
  cannot be both inputs of a spend, which until then only the indexers' rule refused
  (`docs/audit/2026-11-23-circuit.md`, circuit-1). The indexers still check it, before the proof.
- A wallet reference in dependency-free JavaScript (`circuit/js/`): note keys and `npk`, the nullifier, the body hash, the
  EdDSA-Poseidon signature. Its vectors are written by the Rust model (`circuit/src/vectors.rs`) and a test fails if they drift.

Measured on a phone (2026-11-19, iPhone 18 Pro Max, Safari, through the test page, on its charger, Low Power Mode off):
5.7 s per proof on 6 threads, 7.4 s on 4, 15.5 s on one; key load under 1 s; 240 MB. On the M1 Pro in Chrome: 4.5 s on
10 threads, 25.5 s on one. Safari reports 4 cores on that phone and 6 threads are faster, so `defaultThreads()` in
`circuit/web/host.js` takes at least 6 on an iPhone. A first session on 2026-11-18 gave figures twice as slow (14.5 s on 4
threads, 31.9 s on one); they did not reproduce and the code runs as fast on the laptop: Low Power Mode or heat are the
likely causes, so note the conditions with every phone figure. Growing the memory costs nothing on the phone (224 MB in
223 steps: 62 ms): `sh20_reserve` stays unused.

Done since: a second indexer in Rust (`indexer-rs/`), written from `SPEC-WIRE.md` and the vectors alone without opening
`indexer/`; it reproduces every vector, and the 28 points it found open (`docs/SPEC-GAPS.md`) are settled in the spec
(2026-11-19). The vault proves transfers, burns, listings and DEPLOY burns, buys, cancels and claims (`vault/`).
The audit dossier is `docs/AUDIT.md`. Its §8 (2026-11-19) lists what a reading of the vault's cryptography found, most
serious first. 8.1 to 8.6 are fixed (#33; #40 for what 8.6 left in `circuit/js`), and each fix is followed by what its
author's reading checked and what it leaves. 8.7 to 8.9 are fixed too (#57, #58, #59): the vault's secp256k1 secrets go
through `vault/src/secp256k1.js` (no `BigInt`, no division, no branch or index on a secret; read again on 2026-11-23, with
what an interpreter still showed removed), the vault locks itself, and a restored vault checks its counters before it
reserves an index. 8.10 lists what is so by design.

Not done: an external audit (our own, `docs/AUDIT-PROMPT.md`, has run its part `circuit`: no finding above a Note, `docs/audit/2026-11-23-circuit.md`, and the code audit of `indexer`, `docs/audit/2026-11-23-code-indexer.md`); a mid-range phone; an outside review of the note sealing (`docs/SPEC-NOTES.md`, reviewed once by the
circuit session; its reference code and vectors are in `circuit/js`); a real wallet signing in the vault; the vault sending through a relayer (the relayer itself exists, #65); the
profile constant `A`; a public signet run.

## Next task: the public signet

The plan, with an owner and a test of done for each step: `docs/PLAN.md` (2026-11-23).

The protocol, two indexers that agree on every vector, a hardened circuit and a vault that mints, proves, sells and
claims exist. What is left before people can try it, in order (review of 2026-11-19):

1. **Public copy: done (2026-11-24).** The work stays in this private repository; `github.com/sh20-standard/SH-20` is a
   copy of its `main`, rewritten so that nothing in it points to a person (one author and committer, `SH-20 contributors
   <contributors@sh20.invalid>`, every date in UTC, no session link), pushed by the maintainer over a VPN. The CI and
   Pages run there. To publish again: `.private/publish.sh` (`docs/PLAN.md` §2), which stops unless the push only adds
   commits. `.private/` is left out of the copy: keep only the publishing tools in it. Nothing pinned on IPFS from a
   personal machine (a pinning node announces its IP).
2. **Public signet.** Fix the signet profile (`A`, `D`), run `indexer/bin/follow.js` and `indexer-rs`, publish the
   explorer and the vault release, and have a real wallet (Xverse, UniSat, Leather) sign a MINT, a transfer and a sale.
   Testers send the phone page's JSON: that is where mid-range and Android phones get measured.
3. **Before mainnet** (each with an owner and a test):
   - **Sender privacy: relayers.** The Bitcoin inputs that pay a transfer show who sent something; a relayer pays them
     and is paid in tokens by the third output. Specified (2026-11-20, `SPEC-WIRE.md` §3): two or more TRANSFERs in the
     witness of one transaction are a batch, applied in tapscript order, each accepted or refused alone; no count limit
     beyond Bitcoin's own; every other type stays one per transaction. Vectors: block 17 and four carrier cases.
     The relayer exists (#65, `relayer/`, `docs/RELAYER.md`: it checks each TRANSFER as an indexer would, its own fee
     output and the proof last, and publishes batches from its own coins). Still to build: the vault sending through
     one, limits per sender, a queue that survives a restart.
   - **Differential fuzzing: running (2026-11-21).** `indexer/bin/fuzz.js` makes random chains (valid, damaged and cut
     envelopes of every type, both carriers, batches, listings bought, closed and claimed, refused proofs, reused
     nullifiers, anchors at and past the window, DEPLOY commits old enough or not, missing heights), applies them in the
     reference and through `indexer-rs replay --json`, and compares every block's root, digest and refusals. The CI runs
     30 chains of 40 blocks on a fixed seed and 30 on a new seed each run; a divergence keeps the chain and prints the
     command that replays it. First long run: 200 chains, 7,883 blocks, no divergence. Reorgs: `indexer/bin/api-diff.js`
     serves a random chain as an Esplora API to both followers, then a fork (longer, or of the same height), and compares
     every route of the API before and after, and the end against a reference that only saw the fork. Its first run
     with a fork of the same height found that the reference follower stayed on the old tip (fixed, with a test).
   - **Scale.** The note tree is no longer the limit (2026-11-19: an append hashes only the subtrees it completes,
     129 µs on average, a path is O(depth); a million leaves in about 2 minutes, was about 1.5 hours). A restart no
     longer reads the chain again from the source: both followers keep the blocks they read (`--data`, a block file
     of chain data only) and apply them again from disk (2026-11-23). What is left: the state itself is rebuilt on
     every start, and `/nullifiers`, `/roots` and `/listings` return everything at once. Pagination before mainnet volumes.
   - **External audit** of the circuit, the verifier and the note sealing (`docs/AUDIT.md`).

Rules that stay in force for the circuit and the vault:

3. **Fewer gates.** A 2^16 domain (65,536 gates) would halve the proving time. Sparse Poseidon partial rounds, 2-bit windows
   for fixed-base multiplication and bitwise comparisons against constants are estimated to reach about 66,600 gates: still
   above the limit, and the three outputs stay (maintainer, 2026-11-18). Find the last thousand gates without changing a rule,
   or leave the domain at 2^17. On hold (maintainer, 2026-11-19).
4. **Keep it honest.** Any change to the gates changes the keys: rebuild `circuit/artifacts/spend.pk` and `spend.vk`
   (`sh20-circuit pk`, `keygen`), update `VK_DIGEST` and `PK_SHA256` in `circuit/src/lib.rs`, `indexer/src/constants.js`,
   `indexer-rs/src/verifier.rs` (its own pin of the digest), `docs/SPEC-WIRE.md` §4, regenerate
   `indexer/test/fixtures/plonk-scenario.json` (`sh20-circuit scenario`) and then `npm run vectors` in `indexer/`
   (`plonk-v0.3.json`), and rebuild `vault/prover/*.wasm` (`vault/tools/prover.sh`). `circom/spend.circom` and
   `examples/batch_cost.rs` state the same relation: change them with it.
   Then run `circuit/bench/cross-check.sh`: hard requirement 4 says the verifier stays cross-checked against snarkjs.
   `spend.pk` is 8.4 MB of binary: commit a new one only when the gates change (maintainer, 2026-11-18), never for a rebuild
   that gives the same bytes.
5. The soundness-critical code is `circuit/src/gadgets.rs`, `circuit/src/spend.rs` and `circuit/src/plonk/verifier.rs`.
   It is new and unaudited. Do not weaken a check to save gates without the maintainer. `docs/AUDIT.md` maps each
   constraint to its gates and lists what its author would check first; keep its line numbers and counts true when the
   code moves (`sh20-circuit info` prints the gates of each part).
6. The vault embeds the prover the way the test page does: `circuit/web/host.js` and the two workers, with the thread count
   of `defaultThreads()` (not `navigator.hardwareConcurrency`, which Safari under-reports on an iPhone). It computes note keys,
   nullifiers and signatures as `circuit/js/` does, and checks itself against `circuit/js/vectors.json`.
7. In the browser the vault should take `circuit/js/webcrypto.js` instead of `index.js` behind stand-ins: the same names,
   asynchronous, with X25519, HKDF, AES-GCM and the hashes of secrets run by WebCrypto rather than by JavaScript that is not
   constant-time. Its `node:crypto` stand-in then only hashes public tags (`circuit/js/README.md`, "Two entry points").

Where the relation comes from: Tacit's Bitcoin shielded pool (MIT, `https://github.com/z0r0z/tacit`),
`dapp/circuits/btc-pool/spend.circom` and `contracts/sp1/confidential/btc-pool-halo2/`. SH-20 changed the ticker to a private `t`
(one for the five notes, tied to `tPub` by `vPub × (t − tPub) = 0`), the leaf formula, the public inputs, and dropped the
transparent boundary and the empty slots. Kept: note keys, the nullifier, EdDSA-Poseidon over `bodyHash`.
Keep Tacit's MIT copyright notice in any file derived from it.



## Cost budget — keep it light

Goal from the maintainer: an SH-20 transaction should cost about what a normal Bitcoin payment costs,
and the mint must stay cheap. Reference: a P2TR payment with 1 input and 2 outputs is about 154 vB.
Keep only what the protocol needs; add nothing that costs bytes without a clear use.

| Action | Today (v0.3) | Target |
| --- | --- | --- |
| MINT (proof-less, OP_RETURN) | 42-byte envelope (v0.3), about 164 vB with one input and one change output; up to 10 mints in 43 bytes, about 165 vB | ~165 vB |
| TRANSFER, alone | 830-byte envelope (480-byte PLONK proof), about 339 vB + commit | ≤ ~350 vB |
| TRANSFER, in a relayer batch | allowed (`SPEC-WIRE.md` §3): `(515 + 840 n) / 4` vB for `n` transfers, about 223 vB each at `n = 10`, plus a share of the commit | ~200 vB in the next wire version (decided 2026-11-23; was ≤ ~150 vB) |

Sizes are computed from serialized envelopes by `circuit/bench/tx-vsize.mjs` (a P2TR payment comes out at 154 vB by the same
count); nothing has been broadcast yet.

The batch target was measured on 2026-11-21 (`circuit/README.md`, "Batches and the 150 vB target"): with a proof for each
transfer it is out of reach whatever is done to the rest, since 150 vB leaves 54 bytes for a spend whose nullifiers and leaves
are 160. It takes three transfers under one proof. `pot18` allows that (a domain of 2^18) and no more, and only someone who
holds the three witnesses can make the proof: a relayer that sees its users' transfers. Within the requirements: about 200 vB
for a relayed transfer (92 bytes off its body), and 52 vB for each person paid when one payer pays ten (a transfer with more
outputs, in the same domain and the same proving time). Those 92 bytes are on paper, not in code (`circuit/README.md`, "The
transfer body of wire v0.4, on paper"): one ephemeral key for a spend, no ciphertext on chain for its third output, a TRANSFER
of 738 bytes, and no change to the circuit or its keys.

Levers, biggest first. Measure each one and keep every hard requirement above:
1. **Proof size.** Done: PLONK with KZG on the same public Hermez setup, 480 bytes, against Tacit's 2,080
   (fflonk and tighter Halo2 layouts were measured too: `circuit/README.md`). Still to confirm: that it proves on a phone in
   reasonable time.
2. **Batching.** Allow several envelopes in one witness transaction so relayers share the commit/reveal overhead.
3. **Arity.** Decided: three outputs stay. The third pays a relayer in tokens.
4. **Mint bytes.** Done in v0.3: public openings are `npk` alone, public notes use `rho = 0` (74 → 42 bytes, about 32 vB less
   per mint); the review of `docs/SPEC-NOTES.md` (§6) found nothing else that relied on a random `rho` there. Batch mint (maintainer, 2026-11-19): a MINT may end
   with `k` (2 to 10), one note of `k × lim` for `k × price`, about 16.5 vB per mint at `k = 10`.
5. **Small fields.** Done in v0.3: 32-byte X25519 `pk_eph`, no `proofLen`. `ct` stays 28 bytes (amount, ticker, 16-byte tag).
6. **Never** put proof-carrying envelopes in OP_RETURN (four times the witness rate).

Tacit transactions were reported at 25,000–30,000 sats in May 2026. Do not copy what makes them heavy:
SH-20 has no transparent layer, so no Bulletproofs+, no cross-curve boundary and no Ethereum bridge.

## Model

Use Fable 5.2 for the circuit and anything security-critical; Opus 5.5 is fine for the indexer, tooling and docs.

## Competitors (why speed matters)

- **Tacit** (live on mainnet since May 2026): confidential amounts, fair mint, a Bitcoin shielded pool, but the asset id is public in every spend; hiding it is on their roadmap.
- **zkCoins / Shielded CSV**: hides amount, asset and parties, but only an asset's creator can mint, and the receiver must be online.
- **Shielded Ordinals** (Ord Dropz): private NFTs; the platform signs mints and buys; "shielded runes" listed as not yet built.
- **Shielded Bitcoin** ([alloc] init, paper September 2026, ePrint 2026/2749): Zcash-style private BTC transfers as a metaprotocol;
  BTC only, no tokens, BTC entry and exit left to a later paper, nothing deployed yet.
- **SBRC-20** (sbrc20.com, announced 2026-09-28): the closest one, "BRC-20, but shielded": fair mints like BRC-20, then a shielded
  pool shared by every ticker, so private transfers hide the ticker too. Their token $SHLD (21M, 1,000 per mint, a paid mint
  whose fee doubles over time) is deployed on mainnet at block 970,040. As checked on 2026-11-18, the spec is a "draft v0.1"
  with no proof system chosen, and their downloadable indexer handles only public deploy, mint and transfer: no shield, no
  private transfer, no proof verification, despite an announcement that shielding is live. No team named, no code for the
  private part. SH-20's answer: be the first whose private part anyone can run and verify (open code, a public signet).

SH-20's edge: ticker hidden, unique tickers, private by default from the mint (no public balance stage), Bitcoin only, and a
private part that already proves and verifies, in open code.

## Open decisions (ask the maintainer)

Still to fix before the signet: the activation height `A` (the tip + 6 at the soft launch, `docs/PLAN.md` §3).

Decided (2026-11-23, `docs/PLAN.md`, the maintainer having left the choice to the plan): the account `sh20-standard` (`SH-20` was taken), public from the
first push, the work staying in a private repository published to it; the batch target is about 223 vB per relayed transfer on signet and about 200 vB in the next wire version, a
transfer paying several people after the signet and the first audit, and 150 vB is dropped (it needs a relayer that sees its
users' transfers); phones and the public explorer read a mirror the Pages site serves itself; no IPFS before mainnet; no
Claude session links in commits; the contributors deploy no token on any network, SH20 being the project's only token
(decision 7: a test ticker of ours could be copied on mainnet and sold as ours; DEPLOY is tested on regtest).

Decided (2026-11-20): the name stays **SH-20** and the magic `SH20`; tickers are 4 characters only; `D = 1000` SH20
burned per DEPLOY, so at most 21,000 tokens can ever be deployed (21,000,000 / `D`); several TRANSFER envelopes per
transaction, each judged alone (every other type stays one per transaction).

Decided by the maintainer: the genesis token is **SH20**, fixed in the activation profile (no DEPLOY, no race):
21,000,000 max, 1,000 per mint, free mint (network fees only), no team allocation.
Decided (2026-11-18): PLONK-KZG is the proof system (hard requirement 4). Three outputs stay; the third pays a relayer in
tokens. `proofLen` is removed in wire v0.3, together with the 32-byte X25519 `pk_eph`.
Decided (technical, v0.3): the events inside the digest have a fixed byte encoding (`src/events.js`, `SPEC-WIRE.md` §6).
Decided (2026-11-19): batch mint, at most 10 mints per MINT (`MINT_BATCH_MAX`); a last batch gets what is left and pays for that.
Decided (2026-11-19): a turnstile per ticker (`pool` in each token record), enforced by the indexer.
Decided (2026-11-19, against ticker sniping): a DEPLOY reveals a commit confirmed at least `N = 6` blocks earlier
(`deployMaturity`), in the witness carrier only, as Runes does; indexers read the spent output's height (`getblock` 3).
Fixed (2026-11-19): a LIST carries its lock's output key (`lockKey`, +32 bytes) in the signed body; without it a copy of the
envelope could lock the listed tokens to the copier.
