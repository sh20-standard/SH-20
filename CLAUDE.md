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
4. **No project-run trusted setup.** Proofs use a universal public setup (the Hermez `pot18` SRS):
   Halo2-KZG today; PLONK or fflonk on the same SRS if it gives smaller proofs (see the cost budget).
5. **Contributor anonymity.** Commit as `SH-20 contributors <contributors@sh20.invalid>`. Never commit
   personal names, emails, IP addresses, wallet addresses or machine paths.
6. **Determinism.** Any change to bytes or rules updates `docs/SPEC-WIRE.md`, the tests and
   `indexer/vectors/v0.1.json` (regenerate with `npm run vectors`; bump the draft version if the format changes).

## Repository map

| Path | What |
| --- | --- |
| `docs/DESIGN.md` | why SH-20 is built this way, competitors, open decisions |
| `docs/SPEC-WIRE.md` | wire format and acceptance rules, draft v0.1 (normative for the indexer) |
| `indexer/` | reference indexer, Node ≥ 20, zero dependencies |
| `indexer/vectors/v0.1.json` | deterministic vectors for a second implementation |

```sh
cd indexer
npm test            # 27 tests
npm run vectors     # regenerate the vectors (must be byte-identical across runs)
node bin/replay.js <folder of `bitcoin-cli getblock <hash> 2` JSON files>
```

## Status (draft v0.1)

Done in `indexer/`:
- Strict codec for the 7 envelope types (DEPLOY, MINT, TRANSFER, BURN, LIST, TAKE, CLAIM).
- Two carriers: OP_RETURN (small proof-less envelopes, one transaction) and a tapscript witness on input 0 (proof-carrying envelopes, ~2.4 KB).
- State machine: tickers, mints with payment checks, team unlocks, the shared Poseidon tree (depth 32), nullifiers, listings (ACTIVE → SOLD / CANCELLED / CLOSED → CLAIMED), per-block undo log for reorgs, running digest.
- Poseidon over BN254 written from scratch (constants generated with the Grain LFSR, matches circomlib's `poseidon([1,2])`), BIP340 written from scratch (matches BIP340 vectors 0 and 1).
- Proof verification is an interface (`verifier.verifySpend`). **The default verifier rejects every spend**, so TRANSFER, BURN, LIST and non-genesis DEPLOY are not accepted yet.

Not done: the spend circuit and its pinned verifier, the `ct` sealing format, a live chain follower
(Bitcoin Core RPC / Esplora), the browser vault, a relayer, a second independent indexer, the
profile constants (activation height, `D`), the canonical event encoding inside the digest.

## Next task: the spend circuit

**Base:** Tacit's Bitcoin shielded pool (MIT, `https://github.com/z0r0z/tacit`):
- `contracts/sp1/confidential/btc-pool-halo2/` — Rust, PSE `halo2_proofs` v0.3.0, KZG + SHPLONK, BLAKE2b transcript, `k = 13`, Hermez `pot18` SRS, 2,080-byte proofs.
- `dapp/circuits/btc-pool/spend.circom` — the relation it implements.
- `contracts/sp1/confidential/DESIGN-btc-shielded-pool.md` and `…-security.md` — design and analysis.
Keep Tacit's MIT copyright notice in any file derived from it.

**What must change** (target statement: `docs/SPEC-WIRE.md` §4):
1. **Private ticker.** Tacit makes `asset_f` a public input. SH-20 has one private `t` shared by all
   five notes (2 inputs, 3 outputs), a public `tPub`, and the constraint `vPub × (t − tPub) = 0`.
2. **Leaf formula** must equal `indexer/src/notes.js`:
   `leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))`, `H` = circomlib Poseidon with 2 inputs,
   `TAG_LEAF = SHA256("sh20/v0/leaf") mod r`. Tacit's leaf is `Poseidon(asset_f, v, npk, rho)`: different.
3. **Public inputs**, in this order: `root, nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`,
   with `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r` (`body` = envelope bytes before `proofLen`).
4. **Conservation** `v_in0 + v_in1 = v_out0 + v_out1 + v_out2 + vPub`, every value range-checked to 64 bits.
   An input with `v = 0` is a dummy and skips membership.
5. **Keep from Tacit:** note keys (`npk` from tweaked BabyJubJub spend and nullifier keys),
   nullifier `Poseidon(nk_note, leaf, leaf_index)`, EdDSA-Poseidon authorization over `bodyHash`.
6. **Drop from Tacit:** the transparent boundary (cross-curve sigma, Bulletproofs+, shield/exit, `depC`/`exitC`).
   SH-20 has no transparent layer: value enters as proof-less public notes and leaves through `vPub`.

**Deliverables:** `circuit/` crate with prover and verifier; adversarial-witness tests (wrong `t`,
inflation, double spend, bad range, wrong signature); a WASM prover for the browser; a native
verifier the indexer can call as `verifySpend`; the pinned verifying-key hash; measured proof size,
proving time (laptop and phone) and transaction vsize. Update `docs/SPEC-WIRE.md` if anything differs.

After that: wire the verifier into the indexer, specify `ct` sealing, a chain follower, the browser vault
(keys on device, PSBTs signed by Xverse / UniSat / Leather), a public signet run, an audit.

## Cost budget — keep it light

Goal from the maintainer: an SH-20 transaction should cost about what a normal Bitcoin payment costs,
and the mint must stay cheap. Reference: a P2TR payment with 1 input and 2 outputs is about 154 vB.
Keep only what the protocol needs; add nothing that costs bytes without a clear use.

| Action | Today (v0.1) | Target |
| --- | --- | --- |
| MINT (proof-less, OP_RETURN) | 74-byte envelope, ~200–240 vB transaction | ~165 vB |
| TRANSFER, alone | 2,435-byte envelope (2,080-byte Halo2 proof), ~800 vB + commit | ≤ ~350 vB |
| TRANSFER, in a relayer batch | not supported yet | ≤ ~150 vB per transfer |

Levers, biggest first. Measure each one and keep every hard requirement above:
1. **Proof size.** Try PLONK or fflonk with KZG on the same public Hermez setup (universal, so still no
   ceremony; snarkjs-style PLONK proofs are roughly 0.5–0.8 KB, to verify), or a tighter Halo2 circuit,
   against Tacit's 2,080 bytes. Pick the smallest that needs no project-run ceremony and proves on a phone in reasonable time.
2. **Batching.** Allow several envelopes in one witness transaction so relayers share the commit/reveal overhead.
3. **Arity.** 2 inputs / 2 outputs instead of 3 outputs if wallets do not need the third (−93 bytes).
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

SH-20's edge: ticker hidden, unique tickers, private by default from the mint, Bitcoin only.

## Open decisions (ask the maintainer)

Final name and 4-byte magic · value of `D` (genesis burn per DEPLOY) or no burn · ticker length (4 only, or 5–12) ·
genesis team allocation (zero or small) · several envelopes per transaction · exact event encoding in the digest.
