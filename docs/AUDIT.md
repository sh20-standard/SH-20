# SH-20 audit dossier

For a zero-knowledge auditor starting on SH-20: what to read, what the code claims, how the claims
are tested, how to rebuild everything, and where its author would look first.

Status: draft v0.3, nothing is activated on any network. The code in scope was written in November
2026, largely by an AI coding agent working under the maintainer (the "circuit session" of
[`CLAUDE.md`](../CLAUDE.md)). **Nobody else has reviewed it.** Line numbers below are those of `main`
at `e5b0f42`, which includes the LIST fix of §6.1 (PR #20); the commit that adds this file changes
no rule and no gate.

Background, in this order: [`DESIGN.md`](DESIGN.md) (why), [`SPEC-WIRE.md`](SPEC-WIRE.md) (bytes and
rules, normative for indexers), [`SPEC-NOTES.md`](SPEC-NOTES.md) (keys, addresses and sealing,
normative for wallets), [`circuit/README.md`](../circuit/README.md) (the proof system and its
measurements).

**The system in one paragraph.** Notes of every ticker sit in one append-only Poseidon tree of depth
32. A note is a leaf `H(H(H(TAG, t), v), H(npk, rho))`: asset id, amount, owner key, randomness.
Public actions (MINT, TAKE, CLAIM, team unlocks) append leaves the indexer computes itself from
public data. A spend consumes two notes and creates three, with one 480-byte PLONK proof; it
publishes two nullifiers and three leaves, and nothing else about the notes. A spend may also move a
public amount `vPub` of a public asset `tPub` out of the pool (BURN, LIST, the DEPLOY burn). Indexers
replay Bitcoin blocks and keep the tree, the nullifier set and a running digest; there is no
contract and no operator.

## 1. Scope

### In scope

| Path | Lines | What it is | Why it matters |
| --- | ---: | --- | --- |
| [`circuit/src/gadgets.rs`](../circuit/src/gadgets.rs) | 281 | Poseidon, bit decompositions, BabyJubJub addition and multiplication, EdDSA-Poseidon, the Merkle path, as PLONK gates | every gate of the relation is emitted here or in `cs.rs` |
| [`circuit/src/spend.rs`](../circuit/src/spend.rs) | 116 | the spend relation: which gadget is applied to which variable, and the nine public inputs | the statement itself |
| [`circuit/src/plonk/verifier.rs`](../circuit/src/plonk/verifier.rs) | 71 | the PLONK verifier | consensus: every indexer runs it |
| [`indexer/src/adapters/plonk.js`](../indexer/src/adapters/plonk.js) | 49 | loads the verifier (WebAssembly), checks the verifying-key digest, orders the public inputs | the only bridge between the rules and the proof |
| [`docs/SPEC-NOTES.md`](SPEC-NOTES.md) | 179 | wallet keys, the address, sealing an output, scanning, public notes | theft and privacy on the wallet side |
| [`circuit/js/`](../circuit/js/) | 880 | the wallet reference: `seal.js`, `address.js`, `notes.js`, `eddsa.js`, `babyjub.js`, and the browser entry point `webcrypto.js` on `subtle.js` | what the vault computes; the Rust model of the same is `circuit/src/notes.rs` |

### What those files stand on

Not listed by the maintainer, but a finding in any of them is a finding in scope.

| Path | Why |
| --- | --- |
| [`circuit/src/cs.rs`](../circuit/src/cs.rs) | the constraint system: one gate form, copy constraints by shared variables, public-input rows |
| [`circuit/src/plonk/keys.rs`](../circuit/src/plonk/keys.rs) | selectors and the permutation from the gates (`structure`, l. 99), the verifying key and its digest |
| [`circuit/src/plonk/transcript.rs`](../circuit/src/plonk/transcript.rs), [`plonk/mod.rs`](../circuit/src/plonk/mod.rs) | Fiat-Shamir challenges; strict decoding of the 480 proof bytes |
| [`circuit/src/plonk/srs.rs`](../circuit/src/plonk/srs.rs) | reads the Hermez file, pins its BLAKE2b, checks the powers are consistent |
| [`circuit/src/ffi.rs`](../circuit/src/ffi.rs) `sh20_verify` (l. 129) and [`lib.rs`](../circuit/src/lib.rs) `verify`, `load_key` | what the indexer calls; the pinned digests |
| [`circuit/src/model.rs`](../circuit/src/model.rs), [`poseidon.rs`](../circuit/src/poseidon.rs) | the reference the gadgets are compared with; Poseidon constants from the Grain LFSR |
| [`indexer/src/indexer.js`](../indexer/src/indexer.js) `_checkSpend` (l. 243) and its callers, [`codec.js`](../indexer/src/codec.js) | the rules around a proof: anchors, nullifiers, public amounts, the turnstile; canonical parsing |
| [`circuit/circom/spend.circom`](../circuit/circom/spend.circom) | the same relation with circomlib, used only as a cross-check |

### Out of scope here

`circuit/src/plonk/prover.rs` for soundness (a wrong prover cannot make a false proof verify; it
matters for zero-knowledge, §6.6), `circuit/web/`, `circuit/bench/`, `vault/`, `explorer/`, and the
rest of the indexer (chain follower, HTTP API). The vault needs its own review.

## 2. The statement

### Notation

- `F`: the BN254 scalar field, of order `r` (the code calls the same number `p` in `model.rs`).
- `E`: BabyJubJub, `a·x² + y² = 1 + d·x²·y²` over `F` with `a = 168700`, `d = 168696`; `l` the order of
  its prime subgroup, `B8` its generator, `8l` the order of the curve. `a` is a square in `F`, `d` and
  `a·d` are not.
- `H_n`: circomlib's Poseidon with `n` inputs (width `n + 1`, `R_F = 8`, `R_P = 57, 56, 60, 60` for
  `n = 2..5`, S-box `x^5`). `H = H_2`.
- `TAG = SHA256("sh20/v0/leaf") mod r`.
- `Root(leaf, index, path)`: the root reached from `leaf` at position `index` (32 bits, level 0
  first) with the 32 siblings `path`, each node `H(left, right)`.

### Public inputs, in order

`root, nf_0, nf_1, leaf'_0, leaf'_1, leaf'_2, m, vPub, tPub`

`m` is `bodyHash = SHA256("sh20/v0/body" ‖ every envelope byte before the proof) mod r`.

### Witness

`t`; for each input `i ∈ {0, 1}`: `v_i, nk_i, Ak_i ∈ F², rho_i, index_i, path_i ∈ F³², R8_i ∈ F², S_i`;
for each output `k ∈ {0, 1, 2}`: `v'_k, npk'_k, rho'_k`.

### The relation, and where each line is enforced

All in `synthesize`, [`circuit/src/spend.rs`](../circuit/src/spend.rs) l. 36. "Gates" is the output
of `sh20-circuit info`; the circuit has 86,232, on a domain of 2^17 rows.

| # | Constraint | `spend.rs` | Gadget (`gadgets.rs`) | Gates |
| --- | --- | --- | --- | ---: |
| C0 | the nine public inputs sit on rows 0 to 8 | l. 40–46 | `Cs::public_input` (`cs.rs` l. 105) | 9 |
| C1 | `head = H(TAG, t)`, one `t` for the five notes | l. 48–50 | `poseidon` (l. 32) | 620 |
| C2 | `0 ≤ v_i < 2^64` | l. 54–56 | `range` → `to_bits` (l. 102) | 127 each |
| C3 | `0 ≤ nk_i < l` and `NK_i = nk_i·B8` | l. 58–61 | `scalar_bits` (l. 136), `fixed_mul` (l. 222) | 3,255 each |
| C4 | `npk_i = H_4(Ak_i.x, Ak_i.y, NK_i.x, NK_i.y)` and `leaf_i = H(H(head, v_i), H(npk_i, rho_i))` | l. 63–67 | `poseidon_vars`, `note_leaf` (`spend.rs` l. 29) | 3,505 each |
| C5 | `0 ≤ index_i < 2^32` and `(Root(leaf_i, index_i, path_i) − root)·(1 − [v_i = 0]) = 0` | l. 69–77 | `to_bits`, `merkle_root` (l. 269), `Cs::is_zero` (`cs.rs` l. 192) | 20,131 each |
| C6 | `nf_i = H_3(nk_i, leaf_i, index_i)` | l. 79–81 | `poseidon_vars`, `Cs::assert_eq` | 1,017 each |
| C7 | EdDSA under `Ak_i` over `m`: `0 ≤ S_i < l`; `h_i = H_5(R8_i.x, R8_i.y, Ak_i.x, Ak_i.y, m)` taken as its integer below `r`; `(4·Ak_i).x ≠ 0`; `S_i·B8 = R8_i + h_i·(8·Ak_i)` | l. 83–86 | `eddsa_verify` (l. 248): `scalar_bits`, `fixed_mul`, `canonical_bits_254` (l. 145), `ec_add` (l. 174), `var_mul` (l. 233) | 11,704 each |
| C8 | `0 ≤ v'_k < 2^64` and `leaf'_k = H(H(head, v'_k), H(npk'_k, rho'_k))` | l. 92–102 | `range`, `note_leaf` | 1,997 each |
| C9 | `0 ≤ vPub < 2^64` and `vPub·(t − tPub) = 0` | l. 104–108 | `range`, `Cs::assert_mul_zero` | 129 |
| C10 | `v_0 + v_1 = v'_0 + v'_1 + v'_2 + vPub` in `F` | l. 110–113 | `Cs::add`, `Cs::lc`, `Cs::assert_eq` | 5 |

C10 is an equation in `F`; with C2, C8 and C9 both sides are below `2^66`, so it is an equation
between integers. An input with `v_i = 0` is a dummy: C5 lets it skip membership, and it still has a
nullifier (C6) and a signature (C7). `t` and `tPub` are not range-checked: `t` only reaches the
tree through leaves that already carry it, and `tPub` is chosen by the indexer.

### What each gadget is claimed to enforce

Every gate has the form `qL·a + qR·b + qO·c + qM·a·b + qC = 0` (`Cs::gate`, `cs.rs` l. 114). There are
no custom gates and no lookups.

| Gadget | Claim | Rests on |
| --- | --- | --- |
| `to_bits(x, n)`, `range` | each bit is boolean and `Σ bit_i·2^i = x` in `F`; for `n ≤ 253` this gives `x < 2^n` | `2^253 < r` |
| `scalar_bits(x)` | `x < 2^251` and `l − 1 − x < 2^251`, hence `0 ≤ x ≤ l − 1` | `2^250 < l < 2^251` |
| `canonical_bits_254(x)` | the 254 bits are those of the integer of `x` below `r`: with `r = r_hi·2^128 + r_lo`, the high 126 bits are at most `r_hi`, and when they equal `r_hi` the low 128 bits are below `r_lo` | `r` has 254 bits, `r_hi` 126 (test `field_helpers`) |
| `ec_add`, `finish_add`, `add_const_if` | `x3·(1 + d·τ) = w` and `y3·(1 − d·τ) = δ` with `τ = x1·x2·y1·y2`, `w = x1·y2 + y1·x2`, `δ = y1·y2 − a·x1·x2`. A denominator cannot vanish together with its numerator: `w = 0` and `1 + d·τ = 0` give `d·(y1·x2)² = 1`, and `δ = 0` and `1 − d·τ = 0` give `a·d·(x1·x2)² = 1`. So `(x3, y3)` is determined by the operands, **for any operands, on the curve or not** | `d` and `a·d` are not squares |
| `fixed_mul(bits, B)` | `Σ bit_i·2^i·B` for a constant `B`, by adding constants `2^i·B` | boolean bits; the accumulator stays on the curve |
| `var_mul(bits, P)` | `(Σ bit_i·2^i)·P` by double-and-add from the top bit, with the same unified addition for doubling | boolean bits |
| `Cs::is_zero(x)` | `out = 1 − x·inv`, `x·out = 0`, hence `out = [x = 0]`; `inv` is free when `x = 0` | — |
| `poseidon` | the permutation of `circuit/src/poseidon.rs`, three gates per S-box, constants folded into the linear layer | the constants (test `poseidon_matches_circomlibjs_for_every_width`) |
| `merkle_root` | `(left, right) = bit ? (sibling, cur) : (cur, sibling)` at each level | boolean index bits |
| public inputs | row `i < 9` has `qL = 1` and the verifier adds `−x_i·L_i` | `Cs::public_input` asserts they come before every other gate |
| variable 0 | fills unused wire slots and padding rows, in one permutation cycle; it carries no constraint because every slot holding it has a zero selector | read `cs.rs`: each helper that passes `Var(0)` sets the matching selector to zero |

`Ak_i` and `R8_i` are **not** constrained to be on the curve (§6.4).

### The rules an indexer adds around a proof

A proof alone does not make a spend valid. [`indexer/src/indexer.js`](../indexer/src/indexer.js):

| # | Rule | Where |
| --- | --- | --- |
| R1 | field elements on the wire are below `r`, envelopes re-serialise to the same bytes, no trailing byte | `codec.js` `fr()` l. 62; `sh20_verify` refuses a public input that is not canonical (`ffi.rs` l. 133) |
| R2 | `H − 100 ≤ anchorHeight ≤ H − 1`; `root` is the root after that block, or the empty root before activation | `_checkSpend` l. 244–248 |
| R3 | nullifiers non-zero, different from each other, never seen; then recorded | l. 249–252, `_commitSpend` l. 265 |
| R4 | output leaves non-zero; room for three leaves | l. 253–255 |
| R5 | `m` is computed by the indexer from the bytes before the proof | l. 256 |
| R6 | `(vPub, tPub)` come from the envelope type: TRANSFER `(0, 0)`, BURN `(vPub, t(ticker))`, LIST `(amount, t(ticker))`, DEPLOY with `D > 0` `(D, t("SH20"))` | l. 203, 362, 376, 320 |
| R7 | turnstile: a spend with `vPub > pool[ticker]` is rejected before its proof is looked at | `_outOfPool` l. 297, called at l. 319, 361, 375 |
| R8 | the verifying key must hash to the pinned digest | `adapters/plonk.js` l. 26–27 |
| R9 | one envelope per transaction; the default verifier rejects every spend | `carrier.js`; `rejectAllVerifier` l. 22 |
| R10 | the lock of a LIST is the output `OP_1 <lockKey>`, for the `lockKey` its body names (PR #20, §6.1) | `_list` l. 373; `codec.js` l. 231 |

### The proof system

PLONK as in ePrint 2019/953 §8 (three wires, selectors `qM qL qR qO qC`, coset shifts `k1 = 2`,
`k2 = 3`, the linearisation trick), KZG over BN254, domain `2^17`.

- **Setup.** The first 131,078 G1 powers and `τ·G2` of Hermez `powersOfTau28_hez_final_18.ptau`,
  pinned by BLAKE2b-512 (`srs.rs` l. 21). Keys are a deterministic function of the gates and these
  powers (`keys.rs` `setup`, l. 160): no circuit ceremony.
- **Verifying key.** 712 bytes; `SHA256("sh20/v0/vk" ‖ key)` =
  `da847145dbc5aa847af92ce5696fbd60bd57e6fbdf0e077cc1b62a0ba302492d`, pinned in `circuit/src/lib.rs`,
  `indexer/src/constants.js` and `SPEC-WIRE.md` §4.
- **Proof decoding** (`plonk/mod.rs` l. 115). Exactly 480 bytes: nine G1 points as `x` little-endian
  with bit 255 for the larger `y`, `x` below the base-field modulus and on the curve, no encoding for
  infinity; six scalars below `r`. One byte string per proof.
- **Verifier** (`verifier.rs` l. 16). Rejects a wrong number of public inputs and any commitment at
  infinity or off the curve; derives `β, γ, α, ξ, v, u`; computes `Z_H(ξ)`, `L_1(ξ)` and
  `PI(ξ) = −Σ x_i·L_i(ξ)`; then checks
  `e(W_ξ + u·W_ξω, [τ]₂) = e(ξ·W_ξ + u·ξω·W_ξω + F − E, [1]₂)` with `F` and `E` as in the paper.
  A zero denominator (ξ on the domain) is a rejection.
- **Transcript** (`transcript.rs` l. 43). Keccak-256 over big-endian encodings, each challenge
  reduced mod `r`: `β = K(Qm Ql Qr Qo Qc S1 S2 S3 ‖ publics ‖ A B C)`, `γ = K(β)`, `α = K(β γ Z)`,
  `ξ = K(α T1 T2 T3)`, `v = K(ξ a b c s1 s2 zω)`, `u = K(Wξ Wξω)`. This is snarkjs' transcript, kept
  byte for byte so that snarkjs verifies these proofs. Each challenge chains through the previous
  one only; `u` hashes the two opening commitments alone.

## 3. Threat model

### What the attacker controls

| Capability | Means |
| --- | --- |
| the witness | any assignment to the 86,290 variables, not only those the honest synthesis produces; any 480 bytes as a proof |
| the envelope | any bytes in an OP_RETURN or in the tapscript of input 0, in any transaction it can pay for; copies of other people's envelopes taken from the mempool |
| transaction order | it mines, or outbids: it chooses which valid Bitcoin transactions enter a block and in what order, and can delay a transaction past its anchor window |
| an indexer | it runs the indexer a victim's wallet talks to, and answers what it likes |
| notes | it sends notes to the victim, and receives notes from it |

It does not control: SHA-256, Keccak-256, Poseidon as a collision-resistant hash and as a PRF, the
discrete logarithm on BabyJubJub and BN254, the Hermez ceremony (one honest participant), Bitcoin
consensus, the victim's device.

### What must hold

| Goal | Statement | Rests on |
| --- | --- | --- |
| G1, no inflation | for every ticker, the sum of unspent note amounts never exceeds what was issued in public and not taken out in public | C1 (one `t`), C2, C8, C9, C10; C4 and C5 (the inputs exist in the tree); R2, R6; soundness of the proof; and the public rules for MINT, TAKE, CLAIM |
| G2, no double spend | a note is consumed at most once | C3 and C4 (one `nk` per note: `NK` is inside `npk`, and `nk < l`); C5 and C6 (the position is the one in the tree); R1, R3 |
| G3, no theft | only the holder of a note's two secrets moves it, and only to the outputs it chose | C4 (`npk` binds `Ak` and `NK`), C6 (needs `nk`), C7 (a signature over `m`), R5 (`m` covers every byte before the proof), and that every value an envelope gives away is named in those bytes: the output leaves, `payScript`, and for a LIST the key of its lock (R10). Until PR #20 the lock was not: §6.1 |
| G4, no link | from what is published, nobody learns which notes a spend consumed, who receives the outputs, their amounts, or the ticker of a TRANSFER | zero-knowledge of the proof; `nf` is a PRF under `nk`, which the sender of the note does not have; sealing (`SPEC-NOTES.md` §3, §6) |

### What is public, and what a lying indexer can do

Public by design: the type of every envelope, `anchorHeight`, the ticker and amount of a MINT, BURN,
LIST and TAKE, the time and fee of every transaction, and the Bitcoin inputs that paid for it.

An indexer that lies cannot move or create notes, and honest indexers do not follow it (they
compare digests, `SPEC-WIRE.md` §6). To its own users it can: hide notes; show a note that was never
on chain (scanning checks a leaf against the wallet's keys, not against Bitcoin); give a stale root
or a wrong path, so that a spend is mined, pays its fee and is rejected; and learn which leaves a
wallet asks about (`/path/:pos`, `/nullifier/:hex`). The vault downloads the whole note log and
builds the tree itself, as [`API.md`](API.md) tells wallets to; one that asked for single paths
would tell the indexer which notes are its own. None of this is cryptographically prevented.

## 4. Defences in place, and their tests

`T` = `circuit/tests/`, `I` = `indexer/test/`, `J` = `circuit/js/test/`.

| Defence | Test | What the test does not show |
| --- | --- | --- |
| the relation rejects bad witnesses | `T/spend.rs` `adversarial_witnesses_are_rejected`: 26 altered witnesses (7 inflation, 2 ticker, 8 membership and nullifiers, 7 authorisation, 2 outputs), then 3 on BURN and 3 on dummies | each case alters witness *inputs* and re-runs the honest synthesis. No test assigns an intermediate variable (a bit, an inverse, an `x3`) maliciously |
| honest spends satisfy it | `valid_spends_satisfy_the_circuit` (transfer, dummies, burn, largest amounts) | — |
| the gates are the same for every witness | `the_gates_do_not_depend_on_the_witness` | — |
| no variable is unused | `T/prove.rs` `no_variable_is_free`: adding 1 to any single variable breaks a gate | necessary only: two variables changed together are not tried |
| a bad witness has no proof; every public input and proof byte is bound | `rejected_witnesses_have_no_proof`, `transfer_burn_and_dummies_prove_and_verify`, `T/plonk.rs` `prove_and_verify` | sampled bytes, real proofs only |
| the model agrees with the indexer's constants | `leaf_tag_matches_the_indexer`, `ticker_ids_match_the_indexer` | — |
| Poseidon is circomlib's | `T/vectors.rs` `poseidon_matches_circomlibjs_for_every_width`; `I/primitives.test.js` | one vector per width, from circomlibjs |
| small-order keys do not sign | `T/vectors.rs` `small_order_keys_do_not_verify` | on the model; the circuit's gate (`eddsa_verify` l. 257) has no test of its own |
| a second verifier agrees | `bench/cross-check.sh`: snarkjs verifies a spend proof made here and rejects a tampered input; this verifier accepts a snarkjs proof and rejects tampered ones (also `a_proof_made_by_snarkjs_is_accepted`) | the snarkjs proof is of a toy circuit (`circom/cubic.circom`), not of the spend relation |
| a second statement of the relation agrees | `bench/cross-check.sh` step 3: circomlib's `spend.circom` accepts a witness built by the Rust model, with the same nine public signals | one sample witness, and only in the accepting direction |
| the keys are the pinned ones and reproducible | `shipped_key_is_reproducible` (key generation gives `artifacts/spend.pk` byte for byte, the SRS is a consistent sequence of powers), `a_key_file_that_is_not_the_pinned_one_is_refused`; `I/plonk.test.js` `a verifying key other than the pinned one is refused` | that the powers are Hermez' is shown by rebuilding from the pinned file (§5), not by a test |
| real proofs through the indexer | `I/plonk.test.js`: `real TRANSFER and BURN proofs are accepted, and only once`, `a proof does not carry over to an altered envelope`, `a TRANSFER proof cannot be replayed as a BURN` | no real LIST or DEPLOY-burn proof |
| the rules around a proof | `I/indexer.test.js` `TRANSFER: anchor window, nullifiers, proof`; `the default verifier accepts no proof at all`; `I/codec.test.js` `strict parsing rejects malformed envelopes`, `carrier rules: one envelope per transaction` | with a test verifier that accepts a tag |
| the turnstile (PR #16) | `I/indexer.test.js` `turnstile: no spend takes more of a ticker out of the pool than went in, even with a broken circuit` and `turnstile: TAKE, CLAIM and team unlocks bring units back into the pool, and a rollback restores it` | it bounds what leaves in public, not who loses (§6.5) |
| a copied LIST cannot take the lock (PR #20) | `I/indexer.test.js` `a LIST copied into another transaction cannot point its lock at the copier`, `LIST needs a P2TR lock to its lockKey, of at least 330 sats`; `I/codec.test.js` | with the test verifier. That a rewritten `lockKey` changes the body hash is shown for other fields by `a proof does not carry over to an altered envelope`; no real LIST proof exists |
| reorgs | `I/reorg.test.js` (three tests) | — |
| sealing and scanning | `T/notes.rs` (7 tests) and `J/notes.test.js`, on vectors written by the Rust model; each JavaScript test runs on `node:crypto` and on WebCrypto; `scanning refuses anything altered`, `a note whose plaintext lies about its leaf is ignored` | X25519, HKDF and AES-GCM are the platform's; Safari and Firefox not run |
| the wallet's spend values | `J/vectors.test.js`, `J/reference.test.js`; `the_wallet_vectors_are_the_ones_the_model_writes` | — |

Counts: `cargo test --release` 28, `indexer` 55 (those of `plonk.test.js` are skipped without the
verifier module), `circuit/js` 44.

## 5. Reproducing everything from zero

Checked as written on 2026-11-19, on macOS with Rust 1.95, Node 22, circom 2.2.3 and snarkjs 0.7.5
(pinned in `circuit/bench/package.json`).

**Keys.** The Hermez file is 302 MB; whatever its source, it is identified by its BLAKE2b-512,
which the `srs` command checks.

```sh
cd circuit && mkdir -p build
curl -L -o pot18.ptau https://circom.info/powersOfTau28_hez_final_18.ptau
cargo build --release --bin sh20-circuit
B=target/release/sh20-circuit
$B srs pot18.ptau build/pot18-2p17.srs      # 131078 powers, sha256 e97b92f3…3852a238
$B keygen build/pot18-2p17.srs build/spend.vk   # vk digest da847145…a302492d
$B pk build/pot18-2p17.srs build/spend.pk       # sha256 a376301b…4d9e430a
cmp build/spend.vk artifacts/spend.vk && cmp build/spend.pk artifacts/spend.pk
$B info                                      # 86232 gates, and the gates of each part of the relation
```

The three digests are constants of `circuit/src/lib.rs` (`SRS_SHA256`, `VK_DIGEST`, `PK_SHA256`).

**Tests.**

```sh
cd circuit && cargo test --release           # 28 tests
./build-wasm.sh                              # needs the targets wasm32-unknown-unknown and wasm32-wasip1-threads
cd ../indexer && npm test                    # 55 tests; those of plonk.test.js need the module just built
cd ../circuit/js && npm test                 # 44 tests
npm run test:browser                         # the WebCrypto primitives in headless Chrome
```

**Vectors.** Each command rewrites a committed file; `git status` must stay clean.

```sh
cd circuit && cargo run --release --example vectors -- js/vectors.json
cd ../indexer && npm run vectors             # vectors/v0.3.json
```

`indexer/test/fixtures/plonk-scenario.json` holds real proofs
(`sh20-circuit scenario artifacts/spend.pk <out>`). Proofs are randomised, so regenerating it gives
other bytes that verify the same.

**Cross-check with snarkjs and circom.**

```sh
cd circuit/bench && npm ci && cd ..
PTAU=$PWD/pot18.ptau bench/cross-check.sh    # needs circom on the PATH
```

Expected: `snarkjs verify = true, tampered = false`; `accepted; a tampered public input is
rejected`; `circom accepts the Rust witness; public signals identical`.

## 6. Where the author would look first

Ranked from the most serious down. These are the author's own doubts, not findings of a review.

### 6.1 The lock of a LIST was not covered by the proof — fixed by PR #20, to be verified

**Status: fixed** by PR #20 (`0287b62`, "LIST binds its lock key in the signed body"). The problem
is kept here in full so that the fix can be checked against it.

**The problem, as it stood at `e8b4450`.** A LIST moves `amount` out of the pool into a listing
controlled by a Bitcoin output, the lock: output `lockVout` of the transaction that carries the
envelope. Whoever spends the lock decides: a TAKE that pays is a sale, a TAKE that does not pay is a
cancellation, and in both cases the tokens go to the opening the TAKE names (`_take`, `indexer.js`
l. 389).

The envelope held the index `lockVout`, not the lock's key. The proof signs the envelope body, and
none of its nine public inputs depends on the transaction's outputs. So the same envelope was valid
in any transaction:

1. the seller broadcasts its LIST;
2. someone copies the envelope from the mempool into a transaction of their own, whose output
   `lockVout` pays their own Taproot key, and gets it mined first;
3. `_list` recorded the key of that output as the lock; the seller's own transaction was then
   rejected, because its nullifiers were spent;
4. the copier spends its lock with a TAKE that pays nothing, and receives `amount` as a public note.

Reproduced on 2026-11-19 against the reference indexer at `e8b4450` with its test verifier: the copy
was accepted with the copier's key, and the cancelling TAKE gave the copier the note. It is under
the threat model (transaction order, copied envelopes) and broke G3.

**The fix.** The LIST body now carries `lockKey`, the 32-byte x-only output key of the lock, after
`lockVout` (`SPEC-WIRE.md` §4; `codec.js` l. 231 and l. 295), so the body hash the proof signs
covers it. `_list` rejects the envelope unless output `lockVout` is exactly `OP_1 <lockKey>`
(`indexer.js` l. 373), and records the key from the envelope, not from the transaction (l. 382). A
CLAIM is verified against that recorded key (`_claim`, l. 406). A LIST is 32 bytes longer.

The same experiment against PR #20: the copy is rejected with "lock output must be P2TR to lockKey"
and the seller's LIST is accepted under the seller's key.

**What to verify.**

- That `lockKey` is inside `body`: it is read before `payScript` and the spend section, and `body`
  ends where the proof starts (`codec.js` `readSpend`, `bodyEnd`).
- That nothing else of the lock comes from the transaction alone. The amount of sats on the lock
  does (at least 330), and so does the index; neither gives control of the listing.
- That a copy which also rewrites `lockKey` fails. It changes `m`, so the proof no longer verifies.
  The indexer's tests show this with a real proof for other fields of a body
  (`a proof does not carry over to an altered envelope`), not for a LIST: no real LIST proof exists
  in the fixtures.
- `lockKey` is any 32 bytes; it is not checked to be a point of secp256k1. A seller who names a key
  nobody can sign for has locked its own tokens for good. That is the seller's choice, but a wallet
  should not let it happen by accident.

**The rule behind it.** Among the envelopes that carry a proof, LIST was the only one that took
something from the transaction that its body did not name. A copied TRANSFER, BURN or DEPLOY burn
does what its author signed for. MINT, TAKE and CLAIM carry no proof: a MINT and a TAKE are paid for
by whoever broadcasts them, and a CLAIM is signed by the lock key over the opening it names.
`DESIGN.md` now states the rule ("Copied envelopes"); an auditor should check it envelope by
envelope rather than take this list on trust.

### 6.2 Under-constrained gadgets cannot be ruled out by the tests

The gadgets are hand-written PLONK gates in a small constraint system of our own. Nothing analyses
them for assignments the honest synthesis never produces. The 26 adversarial witnesses go through
that synthesis, and `no_variable_is_free` only shows each variable occurs in a gate that notices it.
Where a missing or wrong gate would be most costly:

- `finish_add` (l. 187): `x3` and `y3` are witnesses of two divisions. The argument that they are
  determined is the one in §2; it has not been checked by anyone else.
- `canonical_bits_254` (l. 145): the comparison with `r`, guarded by `is_zero`. A second
  decomposition of `h` would give a second scalar for the same signature.
- `scalar_bits` (l. 136) on `nk`: `nk + l` is the same point and another nullifier (tested as a
  witness, "nullifier key shifted by the group order").
- `add_const_if` (l. 207): the algebra of adding `(bit·cx, 1 + bit·(cy − 1))` in six gates.
- `poseidon` (l. 32): the partial rounds keep lanes as "variable plus constant" and fold constants
  into the next linear layer.
- `spend.rs` l. 77: the gate that waives membership for dummies.

### 6.3 The second implementation agrees on less than it seems

`spend.circom` is checked against one sample witness, in the accepting direction. It does not show
that the two circuits reject the same assignments. An under-constraint analyser run on the circom
file would say nothing about the Rust gates. The snarkjs proof our verifier accepts is of a toy
circuit. And acceptance by snarkjs is not the consensus rule: the rule is this verifier with the
strict decoding of `SPEC-WIRE.md` §4, and an indexer that used snarkjs' own parsing could accept
bytes this one rejects.

### 6.4 `Ak` and `R8` are not checked to be on the curve

`spend.rs` l. 64 and l. 84 allocate them freely. The additions stay determined (§2), but they are
then a rational map, not a group law. The author's argument that this is harmless: a victim's
`Ak` is fixed by `npk` inside its leaf, so it is on the curve; an off-curve `Ak` is only reachable
for a note the attacker made for itself; and for an off-curve `R8` the equation
`S·B8 = R8 + h·8·Ak` still has `h` as a hash of `R8`, which leaves no freedom to solve for it.
Nobody else has examined this. An on-curve check is four gates per point, sixteen in all, and would
end the question, at the price of a new verifying key. `Ak` is not checked to be in the prime subgroup
either; only orders dividing 8 are refused.

### 6.5 The turnstile caps the damage of a soundness bug; it does not share it fairly

If hidden notes could be forged, the forger could BURN or LIST them up to `pool[ticker]`. The
counter stops the total there, so supply in the open never exceeds issuance. But what the forger
takes out, honest holders can no longer take out. Read it as a bound on inflation, not as
protection of holders.

### 6.6 Zero-knowledge has had no review

- The blinding randomness comes from a 32-byte seed the host passes to `sh20_prove` (`ffi.rs`
  l. 190). The same seed with two witnesses gives the same blinding scalars, and the differences of
  the commitments are then unblinded. The page and the vault draw the seed from
  `crypto.getRandomValues`; nothing makes a careless host safe. Mixing a hash of the witness into
  the generator would.
- The prover (`plonk/prover.rs`) adds eleven blinding scalars as snarkjs does (two per wire, three
  for `Z`, two across the split quotient). Whether that is enough for the six openings has been
  taken from the paper, not re-derived.
- The multi-scalar multiplications and field operations are arkworks', in variable time over
  witness values. An attacker on the same device is out of the model; a hosted prover is not safe.

### 6.7 Per-note keys are additive tweaks the sender knows

`nk = nsk + τn` and `sk = ask + τa`, with `τ` derived from the shared secret (`SPEC-NOTES.md` §3,
§6). The sender of a note knows both tweaks. If a per-note `nk` ever leaves the wallet, its sender
recovers `nsk` and can compute every nullifier of that wallet, present and future; the same with
`sk` and `ask`, which is the spending key. The spend witness contains `nk` in clear, so proving must
stay on the device. `SPEC-NOTES.md` §6 says so; it is a property an auditor should weigh rather
than a bug.

### 6.8 Dummy inputs are left to the wallet

An input with `v = 0` needs a nullifier that was never seen. The specifications do not say how a
wallet draws the dummy note. A repeated dummy is a rejected transaction that has paid its fee; a
predictable one links the wallet's transactions.

### 6.9 Gates with no test of their own

The small-order check (`assert_nonzero` on `(4·Ak).x`, `gadgets.rs` l. 257) is tested on the model
only. No test feeds a gadget its boundary values directly: `l − 1` and `l` to `scalar_bits`, `r − 1`
and a high half equal to `r_hi` to `canonical_bits_254`, `2^64 − 1` and `2^64` to `range` other than
through a whole spend.

### 6.10 Order of transactions, beyond 6.1

- DEPLOY: the first valid one wins, so a ticker seen in the mempool can be taken by someone else
  with their own parameters. With `D = 0` this costs a fee only.
- TAKE: a buyer's transaction can be outrun by another buyer who pays the same price.
- A spend delayed more than 100 blocks past its anchor is rejected after paying its fee.
- A block can hold about 3,000 envelopes of 830 bytes with invalid proofs; the WebAssembly verifier
  takes about 13 ms each. That slows an indexer, it does not split them.

### 6.11 The wallet reference

BabyJubJub and Poseidon are `BigInt` arithmetic in `circuit/js`, in variable time, in both entry
points; signing leaks timing to an attacker who can measure it. X25519, HKDF and AES-GCM run in the
platform's library through `webcrypto.js`. AES-GCM does not commit to its key; a ciphertext that
opens under two keys is harmless here because scanning recomputes the leaf from the wallet's own
keys (`seal.js` `scan`, the last line).

### 6.12 What is trusted without having been looked at

arkworks 0.5 (pairing, field and curve arithmetic, FFT); the Hermez ceremony, of which this code
checks the file's hash and the consistency of the powers, not the provenance; and the Poseidon
parameters, generated here by our own Grain LFSR and compared with circomlibjs on one input per
width.

## 7. Not final

The verifying-key digest moves with any change to the gates, and is not frozen. The fix of 6.1
added 32 bytes to a LIST (PR #20); the check suggested in 6.4 would change the key. `SPEC-WIRE.md`
§7 lists what else is open.
