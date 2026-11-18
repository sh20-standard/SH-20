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
   personal names, emails, IP addresses, wallet addresses or machine paths.
6. **Determinism.** Any change to bytes or rules updates `docs/SPEC-WIRE.md`, the tests and
   `indexer/vectors/v0.2.json` (regenerate with `npm run vectors`; bump the draft version if the format changes).

## Repository map

| Path | What |
| --- | --- |
| `docs/DESIGN.md` | why SH-20 is built this way, competitors, open decisions |
| `docs/SPEC-WIRE.md` | wire format and acceptance rules, draft v0.2 (normative for the indexer) |
| `indexer/` | reference indexer, Node ≥ 20, zero dependencies |
| `indexer/vectors/v0.2.json` | deterministic vectors for a second implementation |
| `docs/API.md` | read-only HTTP API served by `indexer/bin/follow.js` (for the vault and relayers) |
| `explorer/` | block explorer: one static page (blocks, transactions, tokens, supply check, indexer comparison) |
| `vault/` | browser vault: keys on the device, mints signed by Xverse / UniSat / Leather, verifiable releases ([`vault/RELEASES.md`](vault/RELEASES.md)) |
| `circuit/` | the spend circuit: PLONK prover and verifier in Rust, WebAssembly build, measurements ([`circuit/README.md`](circuit/README.md)) |
| `circuit/circom/` | the same relation in circom, used only to cross-check the Rust circuit |

```sh
cd indexer
npm test            # 46 tests (4 need the verifier module below and are skipped without it)
npm run vectors     # regenerate the vectors (must be byte-identical across runs)
node bin/replay.js <folder of `bitcoin-cli getblock <hash> 2` JSON files>

cd circuit
cargo test --release    # 16 tests; uses build/hermez-pot18-2p17.srs when present (see circuit/README.md)
./build-wasm.sh         # prover and verifier as one WebAssembly module, no imports
```

## Status (draft v0.2)

Done in `indexer/`:
- Strict codec for the 7 envelope types (DEPLOY, MINT, TRANSFER, BURN, LIST, TAKE, CLAIM). Tokens are named by their ticker
  everywhere (v0.2): the asset id is `t = tickerT(ticker)`, the 4 ASCII bytes as a big-endian u32; `t = 0` is reserved for BTC,
  types `0x08`–`0x0f` for extensions.
- Two carriers: OP_RETURN (small proof-less envelopes, one transaction) and a tapscript witness on input 0 (proof-carrying envelopes, 835 bytes for a TRANSFER).
- State machine: tickers, mints with payment checks, team unlocks, the shared Poseidon tree (depth 32), nullifiers, listings (ACTIVE → SOLD / CANCELLED / CLOSED → CLAIMED), per-block undo log for reorgs, running digest.
- Poseidon over BN254 written from scratch (constants generated with the Grain LFSR, matches circomlib's `poseidon([1,2])`), BIP340 written from scratch (matches BIP340 vectors 0 and 1).
- Live chain follower (Bitcoin Core RPC or Esplora, reorgs with 288 blocks of undo) and a read-only HTTP API with a per-leaf note log for wallets (`docs/API.md`).
- Explorer (`explorer/index.html`): a block explorer in one static page with no dependency; reads any indexer; demo data built from real indexer output.
- Proof verification is an interface (`verifier.verifySpend`). **The default verifier still rejects every spend.**
  `src/adapters/plonk.js` is the real one: the WebAssembly build of `circuit/`, keyed by the pinned verifying-key digest.
  `test/plonk.test.js` replays a chain with a real TRANSFER and a real BURN. `bin/follow.js` and `bin/replay.js` take it with `--verifier <wasm>`; without the flag they reject every spend.

Done in `circuit/` (2026-11-18):
- The proof system was chosen by measurement: **PLONK-KZG on the Hermez `pot18` setup, 480-byte proofs**.
  Halo2 (2,080 bytes as Tacit lays it out, 800 at the very least), fflonk (608 bytes, and it needs more powers than `pot18` holds)
  and snarkjs' own PLONK prover (73–80 s) were measured and set aside. Table and method: `circuit/README.md`.
- The relation of `docs/SPEC-WIRE.md` §4 as 86,232 PLONK gates (domain 2^17), with its reference model, a prover, a verifier,
  deterministic key generation and the pinned digest `da847145…a302492d`.
- Measured on an M1 Pro laptop: proving 1.6 s (10 threads), 8.6 s (1 thread), 22 s as single-thread WebAssembly in Node;
  verification 1.5 ms; TRANSFER reveal transaction 340 vB.
- Checks: 26 adversarial witnesses, every variable pinned by a gate, snarkjs' verifier accepts the proofs,
  circomlib's statement of the relation accepts the witnesses.

Not done: an audit; proving on a real phone (threads, the shipped proving key and the phone test page are in PR #6); the `ct`
sealing format; transfers in the vault (it mints and syncs privately today); a relayer; a second independent indexer; the
profile constants (activation height, `D`); the canonical event encoding inside the digest.

## Next task: the circuit on a phone

The relation, the proof system and the verifier exist. What decides whether they are usable is still open:

1. **Measure on real devices.** Load `sh20_circuit.wasm` in a browser page (keys: `sh20_keygen`, then `sh20_prove`; the ABI is
   in `circuit/src/ffi.rs`) on a recent phone and a mid-range one. Add a threaded build (rayon over Web Workers, needs
   cross-origin isolation). Laptop figures are not phone figures.
2. **Memory.** The module peaks at 425 MB. Compute the quotient in four cosets of size n and the selector evaluations on the
   fly; the target is about 150 MB.
3. **Fewer gates.** A 2^16 domain (65,536 gates) would halve the proving time. Sparse Poseidon partial rounds, 2-bit windows
   for fixed-base multiplication and bitwise comparisons against constants are estimated to reach about 66,600 gates: still
   above the limit, and the three outputs stay (maintainer, 2026-11-18). Find the last thousand gates without changing a rule,
   or leave the domain at 2^17.
4. **Keep it honest.** Any change to the gates changes the verifying-key digest: update `circuit/src/lib.rs` (`VK_DIGEST`),
   `circuit/artifacts/spend.vk`, `indexer/src/constants.js`, `docs/SPEC-WIRE.md` §4 and regenerate
   `indexer/test/fixtures/plonk-scenario.json` (`sh20-circuit scenario`). The circom relation must keep accepting the Rust
   witnesses (`circuit/bench/circom-check.mjs`) and snarkjs' verifier the proofs (`circuit/bench/cross-verify.mjs`).
5. The soundness-critical code is `circuit/src/gadgets.rs`, `circuit/src/spend.rs` and `circuit/src/plonk/verifier.rs`.
   It is new and unaudited. Do not weaken a check to save gates without the maintainer.

Where the relation comes from: Tacit's Bitcoin shielded pool (MIT, `https://github.com/z0r0z/tacit`),
`dapp/circuits/btc-pool/spend.circom` and `contracts/sp1/confidential/btc-pool-halo2/`. SH-20 changed the ticker to a private `t`
(one for the five notes, tied to `tPub` by `vPub × (t − tPub) = 0`), the leaf formula, the public inputs, and dropped the
transparent boundary and the empty slots. Kept: note keys, the nullifier, EdDSA-Poseidon over `bodyHash`.
Keep Tacit's MIT copyright notice in any file derived from it.

After that: `ct` sealing, the browser vault (keys on device, PSBTs signed by Xverse / UniSat / Leather),
a public signet run, an audit.

## Cost budget — keep it light

Goal from the maintainer: an SH-20 transaction should cost about what a normal Bitcoin payment costs,
and the mint must stay cheap. Reference: a P2TR payment with 1 input and 2 outputs is about 154 vB.
Keep only what the protocol needs; add nothing that costs bytes without a clear use.

| Action | Today (v0.2) | Target |
| --- | --- | --- |
| MINT (proof-less, OP_RETURN) | 74-byte envelope, 196 vB with one input and one change output | ~165 vB |
| TRANSFER, alone | 835-byte envelope (480-byte PLONK proof), 340 vB + commit | ≤ ~350 vB |
| TRANSFER, in a relayer batch | not supported yet | ≤ ~150 vB per transfer |

Sizes are computed from serialized envelopes by `circuit/bench/tx-vsize.mjs` (a P2TR payment comes out at 154 vB by the same
count); nothing has been broadcast yet. The batch target is out of reach of lever 1 alone: a spend section is 829 bytes, 207 vB
of witness even when every other byte is shared, so it needs lever 5 and probably one proof for several transfers.

Levers, biggest first. Measure each one and keep every hard requirement above:
1. **Proof size.** Done: PLONK with KZG on the same public Hermez setup, 480 bytes, against Tacit's 2,080
   (fflonk and tighter Halo2 layouts were measured too: `circuit/README.md`). Still to confirm: that it proves on a phone in
   reasonable time.
2. **Batching.** Allow several envelopes in one witness transaction so relayers share the commit/reveal overhead.
3. **Arity.** Decided: three outputs stay. The third pays a relayer in tokens.
4. **Mint bytes.** Drop `rho` from public openings if the security review agrees (a fresh `npk` already
   makes each public leaf unique), and consider a batch mint (k mints in one envelope, paying k × price).
5. **Small fields.** 32-byte x-only `pk_eph`, the shortest safe `ct`.
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

SH-20's edge: ticker hidden, unique tickers, private by default from the mint, Bitcoin only.

## Open decisions (ask the maintainer)

Final name and 4-byte magic · value of `D` (SH20 burned per DEPLOY) or no burn · ticker length (4 only, or 5–12) ·
several envelopes per transaction · exact event encoding in the digest.

Decided by the maintainer: the genesis token is **SH20**, fixed in the activation profile (no DEPLOY, no race):
21,000,000 max, 1,000 per mint, free mint (network fees only), no team allocation.
Decided (2026-11-18): PLONK-KZG is the proof system (hard requirement 4). Three outputs stay; the third pays a relayer in
tokens. `proofLen` is left alone in the circuit work: the indexer work removes it afterwards.
