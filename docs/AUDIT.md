# SH-20 audit dossier

For a zero-knowledge auditor starting on SH-20: what to read, what the code claims, how the claims
are tested, how to rebuild everything, and where its author would look first.

Status: draft v0.3, nothing is activated on any network. The code in scope was written in November
2026, largely by an AI coding agent working under the maintainer (the "circuit session" of
[`CLAUDE.md`](../CLAUDE.md)). **Nobody else has reviewed it.** Line numbers, gate counts and test
names below are those of the tree this file is in. The CI runs
[`docs/tools/check-audit-refs.py`](tools/check-audit-refs.py) on every change: it fails when a line
this file cites no longer holds the text it held, when a test it names is gone, or when a link leads
nowhere. It does not check that the sentence about a line is still true. Gate counts, file sizes and
test counts are outside it; they were last checked on 2026-11-21. The gates are those of 2026-11-19,
when the on-curve checks of §6.4 and the tests of §6.2 and §6.3 were added and the verifying key
moved.

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
| [`circuit/src/gadgets.rs`](../circuit/src/gadgets.rs) | 297 | Poseidon, bit decompositions, BabyJubJub addition and multiplication, EdDSA-Poseidon, the Merkle path, as PLONK gates | every gate of the relation is emitted here or in `cs.rs` |
| [`circuit/src/spend.rs`](../circuit/src/spend.rs) | 116 | the spend relation: which gadget is applied to which variable, and the nine public inputs | the statement itself |
| [`circuit/src/plonk/verifier.rs`](../circuit/src/plonk/verifier.rs) | 71 | the PLONK verifier | consensus: every indexer runs it |
| [`indexer/src/adapters/plonk.js`](../indexer/src/adapters/plonk.js) | 49 | loads the verifier (WebAssembly), checks the verifying-key digest, orders the public inputs | the only bridge between the rules and the proof |
| [`docs/SPEC-NOTES.md`](SPEC-NOTES.md) | 198 | wallet keys, the address, sealing an output, scanning, public notes | theft and privacy on the wallet side |
| [`circuit/js/`](../circuit/js/) | 908 | the wallet reference: `seal.js`, `address.js`, `notes.js`, `eddsa.js`, `babyjub.js`, and the browser entry point `webcrypto.js` on `subtle.js` | what the vault computes; the Rust model of the same is `circuit/src/notes.rs` |

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
| [`indexer/src/indexer.js`](../indexer/src/indexer.js) `_checkSpend` (l. 267) and its callers, [`codec.js`](../indexer/src/codec.js) | the rules around a proof: anchors, nullifiers, public amounts, the turnstile; canonical parsing |
| [`circuit/circom/spend.circom`](../circuit/circom/spend.circom) | the same relation with circomlib, used only as a cross-check |

### Out of scope here

`circuit/src/plonk/prover.rs` for soundness (a wrong prover cannot make a false proof verify; it
matters for zero-knowledge, §6.6), `circuit/web/`, `circuit/bench/`, `explorer/`, and the rest of
the indexer (chain follower, HTTP API). The vault (`vault/`) is a separate piece of work for an
auditor: §8 is a first reading of its cryptography by the circuit's author, with what it found.

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
of `sh20-circuit info`; the circuit has 86,248, on a domain of 2^17 rows.

| # | Constraint | `spend.rs` | Gadget (`gadgets.rs`) | Gates |
| --- | --- | --- | --- | ---: |
| C0 | the nine public inputs sit on rows 0 to 8 | l. 40–46 | `Cs::public_input` (`cs.rs` l. 105) | 9 |
| C1 | `head = H(TAG, t)`, one `t` for the five notes | l. 48–50 | `poseidon` (l. 32) | 620 |
| C2 | `0 ≤ v_i < 2^64` | l. 54–56 | `range` → `to_bits` (l. 102) | 127 each |
| C3 | `0 ≤ nk_i < l` and `NK_i = nk_i·B8` | l. 58–61 | `scalar_bits` (l. 136), `fixed_mul` (l. 232) | 3,255 each |
| C4 | `npk_i = H_4(Ak_i.x, Ak_i.y, NK_i.x, NK_i.y)` and `leaf_i = H(H(head, v_i), H(npk_i, rho_i))` | l. 63–67 | `poseidon_vars`, `note_leaf` (`spend.rs` l. 29) | 3,505 each |
| C5 | `0 ≤ index_i < 2^32` and `(Root(leaf_i, index_i, path_i) − root)·(1 − [v_i = 0]) = 0` | l. 69–77 | `to_bits`, `merkle_root` (l. 285), `Cs::is_zero` (`cs.rs` l. 192) | 20,131 each |
| C6 | `nf_i = H_3(nk_i, leaf_i, index_i)` | l. 79–81 | `poseidon_vars`, `Cs::assert_eq` | 1,017 each |
| C7 | EdDSA under `Ak_i` over `m`: `Ak_i ∈ E` and `R8_i ∈ E`; `0 ≤ S_i < l`; `h_i = H_5(R8_i.x, R8_i.y, Ak_i.x, Ak_i.y, m)` taken as its integer below `r`; `(4·Ak_i).x ≠ 0`; `S_i·B8 = R8_i + h_i·(8·Ak_i)` | l. 83–86 | `eddsa_verify` (l. 261): `assert_on_curve` (l. 173), `scalar_bits`, `fixed_mul`, `canonical_bits_254` (l. 145), `ec_add` (l. 184), `var_mul` (l. 243) | 11,712 each |
| C8 | `0 ≤ v'_k < 2^64` and `leaf'_k = H(H(head, v'_k), H(npk'_k, rho'_k))` | l. 93–100 | `range`, `note_leaf` | 1,997 each |
| C9 | `0 ≤ vPub < 2^64` and `vPub·(t − tPub) = 0` | l. 104–108 | `range`, `Cs::assert_mul_zero` | 129 |
| C10 | `v_0 + v_1 = v'_0 + v'_1 + v'_2 + vPub` in `F` | l. 110–113 | `Cs::add`, `Cs::lc`, `Cs::assert_eq` | 5 |

C10 is an equation in `F`; with C2, C8 and C9 both sides are below `2^66`, so it is an equation
between integers. An input with `v_i = 0` is a dummy: C5 lets it skip membership, and it still has a
nullifier (C6) and a signature (C7). `t` and `tPub` are not range-checked: `t` only reaches the
tree through leaves that already carry it, and `tPub` is chosen by the indexer. `Ak_i` is on the
curve but not necessarily in its prime subgroup: C7 refuses the eight points of order dividing 8 and
nothing else (§6.4).

### What each gadget is claimed to enforce

Every gate has the form `qL·a + qR·b + qO·c + qM·a·b + qC = 0` (`Cs::gate`, `cs.rs` l. 114). There are
no custom gates and no lookups.

| Gadget | Claim | Rests on |
| --- | --- | --- |
| `to_bits(x, n)`, `range` | each bit is boolean and `Σ bit_i·2^i = x` in `F`; for `n ≤ 253` this gives `x < 2^n` | `2^253 < r` |
| `scalar_bits(x)` | `x < 2^251` and `l − 1 − x < 2^251`, hence `0 ≤ x ≤ l − 1` | `2^250 < l < 2^251` |
| `canonical_bits_254(x)` | the 254 bits are those of the integer of `x` below `r`: with `r = r_hi·2^128 + r_lo`, the high 126 bits are at most `r_hi`, and when they equal `r_hi` the low 128 bits are below `r_lo` | `r` has 254 bits, `r_hi` 126 (test `field_helpers`) |
| `assert_on_curve(P)` | `a·x² + y² = 1 + d·x²·y²`, in four gates. Applied to `Ak` and `R8` at the top of `eddsa_verify` | — |
| `ec_add`, `finish_add`, `add_const_if` | `x3·(1 + d·τ) = w` and `y3·(1 − d·τ) = δ` with `τ = x1·x2·y1·y2`, `w = x1·y2 + y1·x2`, `δ = y1·y2 − a·x1·x2`. A denominator cannot vanish together with its numerator: `w = 0` and `1 + d·τ = 0` give `d·(y1·x2)² = 1`, and `δ = 0` and `1 − d·τ = 0` give `a·d·(x1·x2)² = 1`. So `(x3, y3)` is determined by the operands, for any operands; since every point that enters an addition is now on the curve (a constant, `Ak`, `R8`, or a sum of those), each addition is the group law | `d` and `a·d` are not squares |
| `fixed_mul(bits, B)` | `Σ bit_i·2^i·B` for a constant `B`, by adding constants `2^i·B` | boolean bits; the accumulator stays on the curve |
| `var_mul(bits, P)` | `(Σ bit_i·2^i)·P` by double-and-add from the top bit, with the same unified addition for doubling | boolean bits |
| `Cs::is_zero(x)` | `out = 1 − x·inv`, `x·out = 0`, hence `out = [x = 0]`; `inv` is free when `x = 0` | — |
| `poseidon` | the permutation of `circuit/src/poseidon.rs`, three gates per S-box, constants folded into the linear layer | the constants (test `poseidon_matches_circomlibjs_for_every_width`) |
| `merkle_root` | `(left, right) = bit ? (sibling, cur) : (cur, sibling)` at each level | boolean index bits |
| public inputs | row `i < 9` has `qL = 1` and the verifier adds `−x_i·L_i` | `Cs::public_input` asserts they come before every other gate |
| variable 0 | fills unused wire slots and padding rows, in one permutation cycle; it carries no constraint because every slot holding it has a zero selector | read `cs.rs`: each helper that passes `Var(0)` sets the matching selector to zero |

Which variables of an assignment a prover can move freely is tested, not only argued: §6.2.

### The rules an indexer adds around a proof

A proof alone does not make a spend valid. [`indexer/src/indexer.js`](../indexer/src/indexer.js):

| # | Rule | Where |
| --- | --- | --- |
| R1 | field elements on the wire are below `r`, envelopes re-serialise to the same bytes, no trailing byte | `codec.js` `fr()` l. 63; `sh20_verify` refuses a public input that is not canonical (`ffi.rs` l. 133) |
| R2 | `H − 100 ≤ anchorHeight ≤ H − 1`; `root` is the root after that block, or the empty root before activation | `_checkSpend` l. 268–272 |
| R3 | nullifiers non-zero, different from each other, never seen; then recorded | l. 273–276, `_commitSpend` l. 289 |
| R4 | output leaves non-zero; room for three leaves | l. 277–279 |
| R5 | `m` is computed by the indexer from the bytes before the proof | l. 280 |
| R6 | `(vPub, tPub)` come from the envelope type: TRANSFER `(0, 0)`, BURN `(vPub, t(ticker))`, LIST `(amount, t(ticker))`, DEPLOY with `D > 0` `(D, t("SH20"))` | l. 227, 395, 410, 353 |
| R7 | turnstile: a spend with `vPub > pool[ticker]` is rejected before its proof is looked at | `_outOfPool` l. 321, called at l. 352, 394, 409 |
| R8 | the verifying key must hash to the pinned digest | `adapters/plonk.js` l. 26–27 |
| R9 | one envelope per transaction; the default verifier rejects every spend | `carrier.js`; `rejectAllVerifier` l. 22 |
| R10 | the lock of a LIST is the output `OP_1 <lockKey>`, for the `lockKey` its body names (PR #20, §6.1) | `_list` l. 407; `codec.js` l. 234 |

### The proof system

PLONK as in ePrint 2019/953 §8 (three wires, selectors `qM qL qR qO qC`, coset shifts `k1 = 2`,
`k2 = 3`, the linearisation trick), KZG over BN254, domain `2^17`.

- **Setup.** The first 131,078 G1 powers and `τ·G2` of Hermez `powersOfTau28_hez_final_18.ptau`,
  pinned by BLAKE2b-512 (`srs.rs` l. 21). Keys are a deterministic function of the gates and these
  powers (`keys.rs` `setup`, l. 160): no circuit ceremony.
- **Verifying key.** 712 bytes; `SHA256("sh20/v0/vk" ‖ key)` =
  `f48b551776188b652259ac42ff3d064ea61e9dd0d4b48addb825085ab1237745`, pinned in `circuit/src/lib.rs`,
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
| the witness | any assignment to the 86,302 variables, not only those the honest synthesis produces; any 480 bytes as a proof |
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
| the relation rejects bad witnesses | `T/spend.rs` `adversarial_witnesses_are_rejected`: the 34 witnesses of `fixture::adversarial` — 28 on a transfer (7 inflation, 2 ticker, 8 membership and nullifiers, 7 authorisation, 2 outputs, 2 points off the curve), 3 on a BURN, 3 on a dummy input | each case alters witness *inputs* and re-runs the honest synthesis; the next two rows are the tests that touch single variables |
| honest spends satisfy it | `valid_spends_satisfy_the_circuit` (transfer, dummies, burn, largest amounts) | — |
| the gates are the same for every witness | `the_gates_do_not_depend_on_the_witness` | — |
| no variable is free, alone | `T/constraints.rs` `every_variable_alone_is_pinned`: each of the 86,301 variables of five honest assignments is moved to up to five other values, everything else left as it is (about 418,000 changes per assignment); a gate must break. Free: only the inverse witness of `v = 0` for a dummy input (0, 1, 0, 2 and 1 variables on the five assignments) | one variable at a time |
| every choice of the prover reaches a check | `T/constraints.rs` `every_choice_of_the_prover_reaches_a_check`: each of the 7,608 variables no gate defines (witness, bits, inverses, quotients) is changed, every variable a later gate defines is recomputed, and a gate must still fail (about 31,000 changes per assignment). Free: for a dummy input, its 32 Merkle siblings and that inverse witness (0, 33, 0, 66, 33), which is what "a dummy skips membership" means. `the_probe_sees_a_missing_check` shows the test catches a forgotten comparison | one choice at a time; advice the prover could adapt together (bits with the value they decompose) is only covered where the next row does it by hand |
| the gadgets at their limits | `T/gadgets.rs`: `on_curve_accepts_the_curve_and_nothing_else`; `ranges_end_where_they_say` (`range`, `scalar_bits` at `l − 1` and `l`, `canonical_bits_254` at `r − 1` and around `r_hi`); `the_second_decomposition_of_a_field_element_is_refused` (a prover writes the bits of `x + r` and adjusts every other choice of the gadget: only the last gate of the comparison refuses it) | five gadget instances, not all; the hand-made assignment is for one gadget |
| a bad witness has no proof; every public input and proof byte is bound | `rejected_witnesses_have_no_proof`, `transfer_burn_and_dummies_prove_and_verify`, `T/plonk.rs` `prove_and_verify` | sampled bytes, real proofs only |
| the model agrees with the indexer's constants | `leaf_tag_matches_the_indexer`, `ticker_ids_match_the_indexer` | — |
| Poseidon is circomlib's | `T/vectors.rs` `poseidon_matches_circomlibjs_for_every_width`; `I/primitives.test.js` | one vector per width, from circomlibjs |
| small-order keys do not sign | `T/gadgets.rs` `keys_of_small_order_do_not_sign`: the circuit's `eddsa_verify` refuses the eight points of order dividing 8 and points off the curve; `T/vectors.rs` `small_order_keys_do_not_verify` on the model | a key `A + T` with `T` of small order is accepted and is simply another key: `a_key_outside_the_prime_subgroup_still_signs_for_its_owner` states it |
| a second verifier agrees | `bench/cross-check.sh`: snarkjs verifies a spend proof made here and rejects a tampered input; this verifier accepts a snarkjs proof and rejects tampered ones (also `a_proof_made_by_snarkjs_is_accepted`) | the snarkjs proof is of a toy circuit (`circom/cubic.circom`), not of the spend relation |
| a second statement of the relation agrees | `bench/cross-check.sh` step 3: circomlib's `spend.circom` accepts a witness built by the Rust model, with the same nine public signals. Step 4 (`bench/circom-cases.mjs`): the five honest witnesses of `fixture::valid` are accepted by both, and the 34 adversarial ones refused by both, at matching places (`--verbose` prints circom's failed assertion next to the part of the relation the Rust circuit names) | altered inputs through an honest computation on both sides; not an equivalence of the two constraint systems |
| the keys are the pinned ones and reproducible | `shipped_key_is_reproducible` (key generation gives `artifacts/spend.pk` byte for byte, the SRS is a consistent sequence of powers), `a_key_file_that_is_not_the_pinned_one_is_refused`; `I/plonk.test.js` `a verifying key other than the pinned one is refused` | that the powers are Hermez' is shown by rebuilding from the pinned file (§5), not by a test |
| real proofs through the indexer | `I/plonk.test.js`: `real TRANSFER and BURN proofs are accepted, and only once`, `a proof does not carry over to an altered envelope`, `a TRANSFER proof cannot be replayed as a BURN` | no real LIST or DEPLOY-burn proof |
| the rules around a proof | `I/indexer.test.js` `TRANSFER: anchor window, nullifiers, proof`; `the default verifier accepts no proof at all`; `I/codec.test.js` `strict parsing rejects malformed envelopes`, `carrier rules: one envelope per transaction` | with a test verifier that accepts a tag |
| the turnstile (PR #16) | `I/indexer.test.js` `turnstile: no spend takes more of a ticker out of the pool than went in, even with a broken circuit` and `turnstile: TAKE, CLAIM and team unlocks bring units back into the pool, and a rollback restores it` | it bounds what leaves in public, not who loses (§6.5) |
| a copied LIST cannot take the lock (PR #20) | `I/indexer.test.js` `a LIST copied into another transaction cannot point its lock at the copier`, `LIST needs a P2TR lock to its lockKey, of at least 330 sats`; `I/codec.test.js` | with the test verifier. That a rewritten `lockKey` changes the body hash is shown for other fields by `a proof does not carry over to an altered envelope`; no real LIST proof exists |
| reorgs | `I/reorg.test.js` (three tests) | — |
| sealing and scanning | `T/notes.rs` (7 tests) and `J/notes.test.js`, on vectors written by the Rust model; each JavaScript test runs on `node:crypto` and on WebCrypto; `scanning refuses anything altered`, `a note whose plaintext lies about its leaf is ignored` | X25519, HKDF and AES-GCM are the platform's; Safari and Firefox not run |
| the wallet's spend values | `J/vectors.test.js`, `J/reference.test.js`; `the_wallet_vectors_are_the_ones_the_model_writes` | — |

Counts: `cargo test --release` 35, `indexer` 61 (those of `plonk.test.js` are skipped without the
verifier module), `circuit/js` 48.

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
$B keygen build/pot18-2p17.srs build/spend.vk   # vk digest f48b5517…b1237745
$B pk build/pot18-2p17.srs build/spend.pk       # sha256 3625deb6…51d4688b
cmp build/spend.vk artifacts/spend.vk && cmp build/spend.pk artifacts/spend.pk
$B info                                      # 86248 gates, and the gates of each part of the relation
```

The three digests are constants of `circuit/src/lib.rs` (`SRS_SHA256`, `VK_DIGEST`, `PK_SHA256`).

**Tests.**

```sh
cd circuit && cargo test --release           # 35 tests
./build-wasm.sh                              # needs the targets wasm32-unknown-unknown and wasm32-wasip1-threads
cd ../indexer && npm test                    # 61 tests; those of plonk.test.js need the module just built
cd ../circuit/js && npm test                 # 48 tests
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
rejected`; `circom accepts the Rust witness; public signals identical`; `5 honest witnesses
accepted by both, 34 adversarial witnesses refused by both`.

**A static analyser on the circom statement.** circomspect 0.9.0 (`cargo install circomspect`):

```sh
circomspect circom/spend.circom circom/templates.circom -L bench/node_modules
```

Result on 2026-11-19: one warning, on `Num2Bits(depth)` in `MerkleRoot` ("may lead to aliasing"),
which does not apply: `depth` is 32. At the `info` level, 18 generic notes on field arithmetic and
loop comparisons. Run on the circomlib templates the relation instantiates, it gives 28 warnings of
circomlib's own (`<--` assignments followed by their constraint, divisions in the point additions).
It analyses the circom file, not the Rust gates (§6.3).

## 6. Where the author would look first

Ranked from the most serious down. These are the author's own doubts, not findings of a review.

### 6.1 The lock of a LIST was not covered by the proof — fixed by PR #20, to be verified

**Status: fixed** by PR #20 (`0287b62`, "LIST binds its lock key in the signed body"). The problem
is kept here in full so that the fix can be checked against it.

**The problem, as it stood at `e8b4450`.** A LIST moves `amount` out of the pool into a listing
controlled by a Bitcoin output, the lock: output `lockVout` of the transaction that carries the
envelope. Whoever spends the lock decides: a TAKE that pays is a sale, a TAKE that does not pay is a
cancellation, and in both cases the tokens go to the opening the TAKE names (`_take`, `indexer.js`
l. 423).

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
`lockVout` (`SPEC-WIRE.md` §4; `codec.js` l. 234 and l. 298), so the body hash the proof signs
covers it. `_list` rejects the envelope unless output `lockVout` is exactly `OP_1 <lockKey>`
(`indexer.js` l. 407), and records the key from the envelope, not from the transaction (l. 416). A
CLAIM is verified against that recorded key (`_claim`, l. 440). A LIST is 32 bytes longer.

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

### 6.2 Under-constrained gadgets: tested one variable at a time, not proved

The gadgets are hand-written PLONK gates in a small constraint system of our own, and no tool
analyses them. What the tests now show (§4, `T/constraints.rs` and `T/gadgets.rs`):

- every variable of five honest assignments, moved alone to other values, breaks a gate;
- every variable the prover chooses, changed with everything computed from it recomputed, still
  runs into a check;
- the exceptions are exactly the ones the relation intends: for a dummy input, its 32 Merkle
  siblings and the inverse witness of the test `v = 0`. Nothing else, on any of the five
  assignments. A dummy's position, keys, nullifier key and signature are not free;
- the second decomposition of a field element into 254 bits, written by hand with every other
  choice of the gadget adjusted to it, is refused by the last gate of the comparison and by no
  earlier one.

What they do not show. A change is one variable at a time; apart from that one hand-made case, no
test changes several of the prover's choices together, and a missing constraint that needs two
coordinated changes to exploit would pass. The five assignments are honest ones: values an honest
synthesis never produces (a point where a denominator vanishes, a bit pattern at a boundary) are
reached only where `T/gadgets.rs` builds them. This is evidence, not a proof of uniqueness.

Where a missing or wrong gate would be most costly, for someone reading the gates:

- `finish_add` (l. 197): `x3` and `y3` are witnesses of two divisions. The argument that they are
  determined is the one in §2; it has not been checked by anyone else.
- `canonical_bits_254` (l. 145): the comparison with `r`, guarded by `is_zero`.
- `scalar_bits` (l. 136) on `nk`: `nk + l` is the same point and another nullifier.
- `add_const_if` (l. 217): the algebra of adding `(bit·cx, 1 + bit·(cy − 1))` in six gates.
- `poseidon` (l. 32): the partial rounds keep lanes as "variable plus constant" and fold constants
  into the next linear layer.
- `spend.rs` l. 77: the gate that waives membership for dummies.

### 6.3 The second implementation agrees on more than before, still not on everything

`spend.circom` now gets the same 39 witnesses as the Rust circuit: the five honest ones are
accepted by both, and the 34 adversarial ones are refused by both, at matching places
(`bench/cross-check.sh`, step 4). The on-curve checks are in both (`BabyCheck` on `Ak` and `R8`).

That is agreement on altered inputs run through an honest computation of the rest, on each side.
It is not an equivalence of the two constraint systems, and the two are built differently:
circomlib multiplies in Montgomery form with windows, the Rust gates use the unified Edwards
addition everywhere.

circomspect finds nothing specific to this statement in the circom files (§5). It cannot say
anything about the Rust gates, which are what the verifying key commits to. Picus was not tried: it
needs Racket, Rosette and an SMT solver, and did not qualify as easy to install.

The snarkjs proof our verifier accepts is still of a toy circuit. And acceptance by snarkjs is not
the consensus rule: the rule is this verifier with the strict decoding of `SPEC-WIRE.md` §4, and an
indexer that used snarkjs' own parsing could accept bytes this one rejects.

### 6.4 `Ak` and `R8` were not checked to be on the curve — now checked; the subgroup is not

**Status: done.** `eddsa_verify` starts with `assert_on_curve` on both points (`gadgets.rs`
l. 262–263; four gates each, sixteen in the circuit), `spend.circom` has `BabyCheck` on both, and
`SPEC-WIRE.md` §4 states it. The verifying key changed with it. Tests: the gadget alone, the
signature gadget with either point off the curve, and two adversarial witnesses (§4).

Before, the additions were determined (§2) but a rational map rather than a group law whenever a
point was off the curve, and the argument that this was harmless had only its author behind it.

What remains: `Ak` is not checked to be in the prime subgroup. The circuit refuses the eight points
of order dividing 8 (`(4·Ak).x ≠ 0`) and accepts `A + T` for `T` of small order. Such a key signs
for whoever holds the scalar of `A`, because `8·(A + T) = 8·A`; it hashes to another `npk`, so it is
another key and not a second way to spend a note (`T/gadgets.rs`,
`a_key_outside_the_prime_subgroup_still_signs_for_its_owner`). Addresses are checked for the
subgroup by payers (`SPEC-NOTES.md` §2), so an honest wallet never has one. Whether to close it in
the circuit (a multiplication by `l`, about 3,400 gates per input) is an open choice.

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

### 6.9 Gates with no test of their own — closed

The small-order check and the ends of the range gadgets were tested on the model only, or through
whole spends. `T/gadgets.rs` now feeds each gadget its boundary values directly (§4). Not covered
the same way: `fixed_mul`, `var_mul` and `merkle_root` have no test of their own; they are
exercised by every spend and by the two tests of §6.2.

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
added 32 bytes to a LIST (PR #20); the on-curve checks of 6.4 changed the key, from
`da847145…a302492d` to `f48b5517…b1237745`. `SPEC-WIRE.md` §7 lists what else is open.

## 8. Vault

A reading of the cryptography of the browser vault, [`vault/src/`](../vault/src/), at `main`
`f0cb20e` on 2026-11-19, by the author of the circuit. It covers what the maintainer listed: the
derivation of the master secret, note keys and lock keys; the use of `circuit/js/webcrypto.js`; the
nullifier and the signature of a spend; the prover's seed; the `sh20offer1` offers; the encryption
of the stored state and the backup. **Nothing was changed in `vault/`**: the findings are for the
vault's own maintainers to fix. It is a reading, with two experiments, and not an audit.

**Where the lines point (updated at `main` `08fec3c`, after #38 and #40).** Since `f0cb20e`,
`app.js` was split into `src/ui/` (#32) and #33 fixed 8.1 to 8.6. The descriptions of 8.1 to 8.6
keep the files and line numbers of `f0cb20e` (`git show f0cb20e:vault/src/app.js`): they describe
code that has changed. Everything else names the code as it is now: the "Fixed" paragraphs, the open
findings 8.7 to 8.10 and the table at the end. Each "Fixed" paragraph is followed by a "Checked"
paragraph by the author of this section, who read the fix against the finding: where the fix is,
which test replays the attack, and what it leaves. The tests are in `vault/test/audit8.test.js`.
Those named "the page …" match the source text of `app.js` and `src/ui/`: they show that a call is
written there, not that the page behaves so. The rules under them (`keys.js`, `market.js`,
`consensus.js`, `match.js`, `sync.js`) are run.

Not looked at: how transactions are funded and laid out for the Bitcoin wallet (`btc.js`,
`mint.js`, `wallets.js`), the parsing of what servers answer (`api.js`), the page's handling of the
DOM, and the release process (`vault/RELEASES.md`).

### Findings, from the most serious down

8.1 to 8.6 are fixed in #33 (each finding names its commits); 8.7 to 8.10 are open.

**8.1 On a path gateway the vault warns and goes on.** High.
[`app.js`](../vault/src/app.js) l. 137. On `…/ipfs/<cid>/` every site of the gateway has the same
origin as the vault. Any of them can read the stored record from `localStorage` (the master secret
and the 12 words in clear when there is no passphrase, §8.4; otherwise a ciphertext to attack
offline), rewrite the saved servers (`sh20.vault.settings`, which are applied without a question),
or open the vault in a window of its own and script it once the user unlocks. The page shows a
warning and still creates, restores and unlocks vaults. `isolation.js` already refuses to register
its service worker there, for the same reason. Closing it: refuse to create, restore or unlock on a
path gateway, and say where to go instead.

Fixed in #33 (commit `4db704c`): the page stops on a path gateway before it reads its settings,
names the same CID on a subdomain gateway and on a local node, and the vault refuses to be created,
restored or opened there.

Checked: `app.js` l. 24 stops before the settings are read, and `refuseSharedOrigin` (`keys.js`
l. 42) is called by `fromWords`, `open` and `restore`. Tests "8.1 no vault is created…" and "8.1 the
page says where…". This closes the finding. Left: a vault stored there by an earlier version stays
readable by the gateway's other sites; the page says so, and to treat its words as exposed.

**8.2 After a restore, an offer signs the terms the servers give, not the vault's own.** High.
`copyOffer` (`app.js` l. 1070) signs the listing returned by `ownListing` (l. 1012). When the vault
still holds the LIST transaction it sent (`pending[].revealHex`, l. 1015), the terms come from its
own bytes. When it does not (a vault restored from its words, or a listing made on another device),
the transaction comes from Esplora and is accepted on its txid (`market.js` l. 123). A txid does not
cover the witness, and the LIST envelope is in the witness: a server can return the same
transaction with another envelope, with another price and another payee. The only other check is
that the primary indexer reports the same terms (l. 139). If both lie, `signOffer` (l. 94) signs
`SIGHASH_SINGLE | ANYONECANPAY` for their price and their payee, with the vault's lock key.

Reproduced: the same transaction with a swapped envelope has the same txid, `listingFromChain`
returns the swapped terms, and the signature verifies under the lock key for them. Whoever holds
that signature spends the lock, pays itself, and names its own opening in the TAKE: the indexers
record a cancellation, and the tokens go to that opening. The seller sees none of the terms it is
signing; "Copy offer" shows the signature only.

Closing it: sign from terms the vault can vouch for. For a listing it made, those in its own record
(`price`, `payScript`), refusing if the chain or the indexer disagree. For a listing found again
after a restore, the envelope can be authenticated without trusting a server: its two nullifiers
must be those of notes of this vault, and its proof must verify for its body, which only the owner
of those notes could have signed. Failing that, show the price and payee and ask before signing.

Fixed in #33 (commits `85ccd6f`, `9f6a058`): `offerTerms` signs the terms of the vault's own record
for a listing it sent and refuses any difference. After a restore it requires a nullifier of this
vault's notes and a proof that verifies for the envelope's body against the local root at its
anchor; with that note and that root, a proof that fails is refused too. It asks, showing price and
payee, only when it cannot check: no nullifier of its notes, a local tree that does not reach the
anchor, or a verifier that cannot run.

Checked: `offerTerms` (`market.js` l. 179), called by `copyOffer` (`ui/market-panel.js` l. 135)
before `signOffer`. Test "8.2 an offer is signed only for terms the vault vouches for" replays the
swap above with a real proof: the same txid with another envelope is refused. Left: when the vault
cannot check, the seller reading the price and the payee is the only check.

**8.3 A buyer is protected by the indexers that know the listing; one is enough, and an indexer
that does not know it is ignored.** High.
`checkedListing` (`app.js` l. 997) asks every configured indexer for the listing and keeps the
answers that hold one. `IndexerApi.listing` returns `null` for a 404, so an indexer that says "no
such listing" is dropped from the comparison instead of counting against it. One indexer that
reports the listing ACTIVE is then enough, whatever the others said, and the page describes the
result as "one indexer: add others in Settings", which is not what happened.

What that allows: someone broadcasts a real Bitcoin transaction that carries a LIST envelope the
honest indexers reject (a bad proof, spent nullifiers, the turnstile), with a lock of its own, and
signs an offer for it. The chain shows a LIST with the right lock key, the signature is valid, and
a lying indexer says ACTIVE. The buyer's TAKE is a valid Bitcoin transaction: it pays the price,
and no honest indexer gives it anything. Unlike a mint, a TAKE pays the seller's asking price.
Closing it: treat "unknown" from a reachable indexer as a disagreement, and require at least two
independent indexers to agree before a TAKE, as `sendClaim` already requires every one to say
CLOSED.

Fixed in #33 (commit `ecfcbb4`): `listingCheck`: an indexer that answers "unknown" refuses the
listing, and a TAKE needs two indexers that agree (`TAKE_QUORUM`).

Checked: `listingCheck` (`consensus.js` l. 155) and `TAKE_QUORUM = 2` (l. 145), used by
`checkedListing` (`ui/market-panel.js` l. 59) and again just before the TAKE is built (l. 181).
Test "8.3 an indexer that answers and does not know the listing refuses it". This closes the
finding as proposed. Left: the quorum counts answers, so two indexers run by one party count as two.

**8.4 Without a passphrase, the master secret and the 12 words are stored and backed up in
clear.** Medium.
[`keys.js`](../vault/src/keys.js) l. 160: the record is `{ v: 0, plain: { …, seed, words } }`.
The passphrase is optional (a `confirm`, `app.js` l. 189). The backup is the stored record
(`exportBackup`, l. 171), so "Download backup" then writes the same clear JSON to the downloads
folder. Three things make it worse than a choice made once:

- no function sets or changes a passphrase afterwards: a vault created without one stays in clear;
- restoring a clear backup ignores the passphrase typed in the "backup passphrase" field (`open`,
  l. 132, takes `rec.plain` and leaves the key null): the user can believe the restored vault is
  protected when it is not;
- "Show recovery words" (`app.js` l. 159) needs no passphrase on an unlocked vault.

Closing it: require a passphrase, or at least refuse to export a clear backup; add a way to set or
change it; refuse a passphrase given for a clear backup, or encrypt with it.

Fixed in #33 (commits `53cf58a`, `3278354`): no backup is written in clear; a passphrase can be set
or changed (`setPassphrase`); a clear backup restored with a passphrase is encrypted with it; the
words of an encrypted vault are shown after the passphrase; a tab holding an older copy cannot write
it back.

Checked: `exportBackup` (`keys.js` l. 247) throws without a key; `setPassphrase` (l. 194),
`restore` (l. 169) and `#checkUnchanged` (l. 226) do the rest; the words of an encrypted vault ask
for the passphrase (`ui/vault-panel.js` l. 21). Tests "8.4 no backup in clear…", "8.4 a clear
backup restored with a passphrase…" and "8.4 a tab that holds the vault…". Left, by choice: the
passphrase stays optional (`ui/vault-panel.js` l. 69). A vault created without one is still stored
in clear on the device, and its words are shown without a question.

**8.5 What the vault shows as received rests on one indexer.** Medium.
`sync.js` rebuilds the tree from the primary indexer's leaves and checks it against that indexer's
own root (l. 106): consistency with itself, not with the chain. Scanning checks a leaf against the
vault's keys, not that the leaf was ever in a block. A lying indexer can show a payment that does
not exist; the digests of several indexers are compared before a mint (`consensus.js`) and at no
other time. A spend built on a wrong root is rejected after paying its fee; nothing is stolen.
Closing it: compare the digest at the synced height across the configured indexers at every sync,
and show how many agree next to a balance.

Fixed in #33 (commits `f242de1`, `1d7766f`): after every sync the other indexers are compared on the
tree's root (against the root rebuilt from the leaves) and on the digest at the synced block, and
the count is shown next to the balance.

Checked: `digestAgreement` (`consensus.js` l. 190), called at every sync (`ui/notes-panel.js`
l. 120). Test "8.5 every sync compares the root and the digest…". Left: this informs and does not
refuse. A balance is still shown when the indexers disagree, with the count marked as an error. What
a disagreement stops is a mint (`crossCheck`), a TAKE (`listingCheck`) and, since #38, giving back
the notes of a spend that looks refused (`refusalAgreed`, `consensus.js` l. 61). #38 also has the
vault start no DEPLOY, spend, TAKE, cancel or CLAIM while an indexer reports another profile than
its own (`requireProfile`, `ui/context.js` l. 78): that compares the profile's constants, not what
the indexers say of the chain.

**8.6 `scanOutput` turns every failure into "not ours".** Low.
[`notekeys.js`](../vault/src/notekeys.js) l. 34 catches whatever `scan` throws. `scan` returns
`null` for a note that is not the vault's and throws only when it could not try (WebCrypto failed,
an input was malformed). The page refuses to start without X25519 (`app.js` l. 34), which covers
the main case; a failure during one sync still drops that note silently. A sync reads a leaf again
only while it is in the last six blocks; after that, only a full rescan finds the note. Closing it:
let anything but a malformed output propagate.

Fixed in #33 (commits `c674e73`, `950f9d0`): `scanOutput` lets a failure propagate (malformed
outputs are still null); a note whose scan fails does not stop the others, and the sync reads again
from the first that failed until the vault has scanned it.

Checked: `scanOutput` (`notekeys.js` l. 36) has no catch left; `matchNotes` (`match.js` l. 15)
goes on past a note that throws, and `Sync.scanned(from)` (`sync.js` l. 138) makes the next sync
read again from the first of them. Tests "8.6 a scan that could not be made throws…" and "8.6 a
note whose scan throws does not stop the others…". One case was left below the vault: `x25519` in
`circuit/js/subtle.js` answered every `OperationError` or `DataError` of WebCrypto as a low-order
point, so a failure of that kind inside `deriveBits` was still read as "not ours". Fixed in #40: a
low-order point is recognised from its bytes before the platform is asked (`isLowOrder`, l. 80),
and `x25519` (l. 93) throws whatever the platform throws; test "X25519: a failure of the platform
is thrown, never read as a point of low order" (`circuit/js/test/webcrypto.test.js`). Left: a
`pk_eph` with bit 255 set, or at or above p, is not of low order and goes to the platform. RFC 7748
has it accept both; a browser that refused one would throw on a `pk_eph` anyone can publish, and
the vault would read again from that note at every sync. Node and Chrome accept them;
`circuit/js/test/subtle.html` checks it in a browser, and Safari and Firefox have not been run.

**8.7 Signatures by secp256k1 keys use the indexer's verification code.** Low.
Lock keys sign offers, cancels and claims, and a one-time key signs each reveal, with
`indexer/src/schnorr.js` `sign` (l. 78) and the point arithmetic of `taproot.js` (l. 44): `BigInt`
double-and-add, whose running time depends on the key and on the nonce. The nonce follows BIP340
with 32 fresh random bytes each time, and a key signs a handful of times in normal use (every
"Copy offer" is a new signature), which leaves little for timing to work on. Two things to add: BIP340's advice to verify a signature before
releasing it (a faulty signature of an offer is published and lasts), and a statement in the code
that this path is not constant-time. The same holds for BabyJubJub in `circuit/js` (§6.11), where
the wallet's two scalars are multiplied again at every unlock.

**8.8 Secrets stay in memory, and the vault never locks itself.** Low.
The witness of a spend holds the nullifier keys in clear. It stays in the object `buildSpend`
returns, and in the prover module's memory until the next proof (`circuit/web/host.js` copies it
into a buffer it keeps). `lock()` (`keys.js` l. 416) zeroes the master secret and can do no more:
the derived scalars are `BigInt`s, the words a string. Nothing locks the vault after a time. None of
this is reachable without code running in the page's origin, which is why §8.1 matters most.

**8.9 An old backup reuses indices.** Low.
A backup taken before some public notes or listings were made restores older counters. The sync
moves them past what it finds on chain, within a gap of 50 notes and 10 lock keys; beyond the gap,
or for an index reserved and not yet mined, a public-note key or a lock key is used twice. That
links two notes or two listings; it loses nothing, since notes are told apart by position and an
offer or a claim is bound to its listing's txid. The one-time keys of spends in flight are missing
from an older backup: their commit outputs (a fee and some dust) cannot be taken back.

**8.10 Things by design that a user should be told.** Note.

- An offer never expires and cannot be withdrawn except by spending the lock on chain; its price is
  the LIST's and cannot change.
- Lock keys are derived by the vault's own rule (`keys.js` l. 327), which `SPEC-NOTES.md` does not
  define: another wallet restoring from the same words finds the notes and not the listings.
- The 12 words are the whole vault. The device passphrase is not a BIP39 passphrase: it protects
  the copy on this device and nothing else.
- The passphrase key is PBKDF2-HMAC-SHA256 with 600,000 rounds and a 16-byte salt; any passphrase is
  accepted, and PBKDF2 is not memory-hard. A weak passphrase on a leaked backup falls to guessing.

### Read and found as intended

| What | Where |
| --- | --- |
| 12 words from 128 random bits; checksum checked before any key is derived; BIP39 seed by WebCrypto PBKDF2; `m` = first 32 bytes of HMAC-SHA512("sh20/v0/seed", seed), as `SPEC-NOTES.md` §1 | `bip39.js` l. 38, l. 41; `keys.js` l. 121 |
| note keys, address, sealing, scanning and the EdDSA nonce go through `circuit/js/webcrypto.js`; the `node:crypto` stand-in implements SHA-256 only and throws for the rest | `sh20.js`; `shim/node-crypto.js` |
| lock keys are separated from note keys: HMAC-SHA512 under the tag "sh20/vault/lock" over `m ‖ index`, reduced into `[1, n − 1]`, then the BIP86 tweak | `keys.js` l. 327; `taproot.js` l. 126 |
| a sealed output is recorded only if it opens, has a value and hashes to its leaf; a note is identified by its position; before spending, each input is checked again against its leaf | `keys.js` l. 307; `spend.js` l. 85 |
| the payer's checks on an address are made by `decodeAddress`; each output is sealed with 32 fresh random bytes; the three outputs are shuffled | `send.js` l. 54, l. 23; `spend.js` l. 99 |
| nullifier = `Poseidon(nsk + τn mod l, leaf, position)`; spent notes are found in the full list of nullifiers, never by asking about one | `notekeys.js` l. 46; `sync.js` |
| an unused input is a note of 0 with fresh random keys and randomness, so its nullifier is new and unlinkable (§6.8) | `spend.js` l. 40 |
| the body signed is every envelope byte before the proof; each signature is verified, and the proof is verified against its public inputs, before anything is sent | `spend.js` l. 113–117; `send.js` l. 85 |
| the prover's seed is 32 bytes from `crypto.getRandomValues` for each proof, drawn in the worker, never stored or derived, with a test (§6.6) | `prover-worker.js` l. 19; `test/prover-seed.test.js` |
| the proving key is checked by the module against its pinned hash, and the verifying key it yields against the pinned digest | `prover.js` l. 69 |
| the BIP341 signature message, read against the specification for the two modes used (default, and `SINGLE \| ANYONECANPAY`), key path and script path | `taproot.js` l. 92 |
| an offer's signature commits to the lock's outpoint, amount, script and sequence, to the version and locktime, and to the output paying the price; a buyer checks it under the key of the lock output, which the txid does cover | `market.js` l. 86–116, l. 136 |
| the BIP340 nonce is derived as specified, with fresh auxiliary randomness at every signature | `indexer/src/schnorr.js` l. 78; `taproot.js` l. 137, l. 196 |
| the state is AES-256-GCM under the passphrase key with a fresh 12-byte nonce at every save; a wrong passphrase fails the tag | `keys.js` l. 27, l. 204 |
| the page refuses to run in a frame and without X25519; servers named in a link need a confirmation and keep a warning on screen; the wallet's signed transaction must be the one that was built | `app.js` l. 16, l. 48; `ui/context.js` l. 30; `ui/spends.js` l. 30 and `ui/tokens-panel.js` l. 175 |
