# sh20-circuit

The spend circuit of **SH-20** (`docs/SPEC-WIRE.md` §4): prover, verifier, and the measurements
behind the choice of proof system.

**Status: draft v0.3. Not audited. Not activated anywhere.**

| | |
| --- | --- |
| Proof system | PLONK over BN254 with KZG commitments (ePrint 2019/953, three wires, no custom gates) |
| Setup | none of ours: the public Hermez `powersOfTau28_hez_final_18.ptau`, 131,078 powers of it |
| Proof | **480 bytes** (9 G1 points, 6 scalars) |
| Circuit | 86,248 gates, domain 2^17, 9 public inputs |
| Verifying key | 712 bytes, digest `f48b551776188b652259ac42ff3d064ea61e9dd0d4b48addb825085ab1237745` |
| Proving key | `artifacts/spend.pk`, 8.4 MB (the verifying key and the SRS powers), SHA-256 `3625deb6e9512e57b530f60abab90e57e2f9648c741e187cb0b9f0fb51d4688b`; loads in 0.2 s, 1.4 s in WebAssembly |
| Proving time, native | 1.8 s on a laptop (10 threads); 9.6 s on one thread |
| Proving time, WebAssembly | 25 s on one thread; 13 s on 2 threads, 7.2 s on 4, 5.6 s on 6, 4.4 s on 10 |
| Proving time, on a phone | iPhone 18 Pro Max, Safari: 5.7 s on 6 threads, 7.4 s on 4, 15.5 s on one |
| Prover memory | 224 MB in WebAssembly (242 MB with 10 threads); 240 MB on the phone |
| Verification | 1.5 ms native, 13 ms in WebAssembly |

Keys are derived from the gates and the SRS and from nothing else, so anyone recomputes the same
keys: there is no ceremony and no secret. The shipped proving key only saves that work, and a test
checks that key generation reproduces it byte for byte.

## Why PLONK: what was measured

The cost budget asks for the smallest proof that needs no project-run ceremony and still proves on a
phone. Every option of the budget was measured before choosing, on one machine (Apple M1 Pro,
10 cores, 16 GB; Rust 1.95, Node 22; 2026-11-18). "Wire" is the size inside an envelope: 32 bytes per
G1 point (x and the sign of y) and 32 bytes per scalar.

| Option | What was proved | Proof on the wire | Prove, 10 threads | Prove, 1 thread | TRANSFER reveal |
| --- | --- | --- | --- | --- | --- |
| Halo2-KZG, Tacit's 12-column layout | Tacit's own relation, as published | 2,080 B | 1.1–1.4 s | 2.7–2.9 s | 743 vB |
| Halo2-KZG, narrow layout (4 advice columns, k = 14) | shape only | ≥ 992 B | 0.5 s | 2.0 s | ≥ 469 vB |
| Halo2-KZG, tightest layout (3 advice columns, k = 17) | shape only | 800 B | 2.5 s | 12.3–12.5 s | 421 vB |
| fflonk, snarkjs | the SH-20 relation in circom | 608 B | 122–146 s | not run | 372 vB |
| PLONK, snarkjs | the SH-20 relation in circom | 480 B | 73–80 s | 102 s | 340 vB |
| **PLONK, this crate** | **the SH-20 relation** | **480 B** | **1.5–1.6 s** | **8.5–8.8 s** (22 s as WebAssembly) | **340 vB** |

The last row is the prover as it was when the choice was made. It has since been reworked for phones
(below): it now takes 1.8 s and 9.6 s natively, in exchange for half the memory and no key generation.

What the numbers say:

- **PLONK is the smallest**, and the only option under the budget's 350 vB for a TRANSFER
  (a P2TR payment with one input and two outputs is 154 vB by the same count).
- **fflonk loses on every axis**: larger proofs, slower, and at this circuit size it needs 2^21
  powers of tau. `pot18` holds 2^18, so fflonk would also break the "Hermez pot18" requirement.
- **A tighter Halo2 circuit cannot catch up.** Halo2 opens every fixed column and has no
  linearisation step, so its proof grows with the layout: 800 bytes is the floor for three advice
  columns, and that layout needs as many rows as PLONK while proving more slowly. The two Halo2
  rows are shape benchmarks (`bench/halo2-shape`): the exact columns, degree and row count of such a
  layout, filled with satisfied gates. They are not implementations of the relation; the narrow row
  is a lower bound, since a real layout needs more rotations and selectors.
- **snarkjs was the bottleneck, not PLONK.** Its prover spends most of its time in single-threaded
  JavaScript and needs a 370 MB key file. The prover here implements the same protocol in Rust:
  about 45 times faster on ten threads and 12 times on one, with a 1.1 MB WebAssembly module and
  an 8.4 MB SRS.

## On a phone

Measured by the maintainer on 2026-11-19 with the page of `web/`, served over https with the
isolation headers. The phone was on its charger, with Low Power Mode off. The iPhone figures come
from the page's thread sweep: one proof per thread count, in a shuffled order, twice over.

| Device | Browser | Threads | Proving time | Key loading | Prover memory |
| --- | --- | --- | --- | --- | --- |
| iPhone 18 Pro Max, iOS 18.7 | Safari | 6 | 5.7 s | under 1 s | 240 MB |
| iPhone 18 Pro Max, iOS 18.7 | Safari | 4 | 7.4 s | | |
| iPhone 18 Pro Max, iOS 18.7 | Safari | 1 | 15.5 s | | |
| MacBook Pro M1 Pro | Chrome | 10 | 4.5 s | | |
| MacBook Pro M1 Pro | Chrome | 1 | 25.5 s | | |

So a recent phone proves a transfer in under 6 s, and the prover fits in its memory. What these
sessions settled:

- **Safari reports fewer cores than the phone has.** `navigator.hardwareConcurrency` is 4 on this
  phone, and 6 threads prove faster than 4. `defaultThreads()` in `web/host.js` therefore takes at
  least 6 on an iPhone and the reported count everywhere else; the page and a wallet should ask it
  rather than the browser.
- **The single-thread build is as fast as the threaded build on one thread.** The page's key-loading
  diagnosis starts each of them cold: the key loads in 0.6 to 1.4 s and a proof takes 15.3 to 17.4 s,
  whichever build runs.
- **Growing the memory costs nothing there.** Taking a memory to 224 MB in 223 steps takes 62 ms on
  the phone, so reserving the prover's heap in one step gains nothing. `sh20_reserve` exists for that
  measurement and nothing calls it by default.
- **A phone can run twice as slow.** A first session the day before, on the same phone, gave 14.5 s
  on 4 threads and 31.9 s on one, with 5.5 s to load the key on one thread. None of it reproduced.
  The files served that day run as fast as today's on the laptop (7.9 s against 7.6 s on 4 threads,
  26.4 s against 26.0 s on one, in Chrome), so the code is not the cause. The state of the phone that
  day was not recorded; Low Power Mode or heat are the likely causes. Note the conditions with every
  phone figure.

The phases of a proof on that phone, from the same sweep (mean of the two passes, in seconds):

| Threads | Proof | Commitments | Transforms | Quotient | Rest |
| --- | --- | --- | --- | --- | --- |
| 1 | 15.5 | 10.5 | 3.9 | 0.74 | 0.33 |
| 2 | 9.8 | 6.5 | 2.4 | 0.47 | 0.33 |
| 3 | 9.1 | 6.1 | 2.2 | 0.41 | 0.34 |
| 4 | 7.4 | 4.8 | 1.8 | 0.37 | 0.35 |
| 5 | 6.5 | 4.1 | 1.6 | 0.34 | 0.35 |
| 6 | 5.7 | 3.7 | 1.4 | 0.30 | 0.33 |

No phase falls behind: from one thread to six the commitments gain 2.9 times, the transforms 2.8
and the quotient 2.5, and the rest runs on one thread. What is short of the thread count is the same
in every phase: two threads are 1.6 times faster than one, and a third adds almost nothing. That is
what a phone with two fast cores and four slow ones would give (the page cannot see the cores, so
this is read from the figures), not something one phase of the prover does.

Not measured yet: a mid-range phone and an Android phone.

### Where the time goes

The threaded build on the laptop, in Node (`bench/wasm-threads-bench.mjs`), best of two proofs, in
seconds. Commitments are multi-scalar multiplications, transforms are FFTs.

| Threads | Proof | Commitments | Transforms | Quotient | Rest |
| --- | --- | --- | --- | --- | --- |
| 1 | 25.3 | 17.7 | 6.2 | 0.9 | 0.3 |
| 2 | 13.5 | 9.1 | 3.3 | 0.5 | 0.3 |
| 4 | 7.3 | 4.8 | 1.8 | 0.3 | 0.3 |
| 6 | 5.7 | 3.7 | 1.4 | 0.2 | 0.3 |
| 8 | 4.9 | 3.0 | 1.3 | 0.2 | 0.3 |
| 10 | 5.3 | 3.0 | 1.6 | 0.3 | 0.4 |

Commitments are 70% of a proof on one thread and keep gaining up to the eight fast cores. The
transforms get slower when the two slow cores join: ten threads lose to eight. `examples/slow_cores.rs` shows
the same thing natively by mixing fast threads with background ones, which run on the slow cores at
a low clock: two fast threads prove in 5.4 to 6.4 s, two fast and one slow in 7.4 to 8.0 s, and
the transforms go from 1.4 s to between 2.4 and 2.7 s. That mix is far more unequal than a phone's (a background
thread alone takes over 100 s), so it shows the direction of the effect and not its size.

The tools: the page's sweep and key-loading diagnosis (`web/README.md`), `sh20_timings` for the
phases of the last proof, `sh20_pool` for a pool of a given size, `bench/jsc-bench.js` for the
single-thread build in Safari's engine outside a browser.

What was done to get there, measured in Node and in headless Chrome on the laptop:

- **No key generation at start-up.** `artifacts/spend.pk` holds the verifying key and the SRS powers;
  the rest of a proving key follows from the gates without any group operation. Loading it takes
  1.4 s in single-thread WebAssembly, against 19.5 s to generate the keys. The file is pinned by its
  SHA-256, and `load_key` refuses anything else.
- **Half the memory.** The quotient is computed on four cosets of the domain instead of one coset four
  times larger, and the key no longer stores evaluations: 224 MB at peak instead of 425 MB, for
  about 13% more proving time.
- **All cores.** A second WebAssembly build runs a thread pool over Web Workers on a shared memory:
  13 s on 2 threads, 7.2 s on 4, 5.6 s on 6, 4.4 s on 10, against 25 s on one. It builds on stable
  Rust (`wasm32-wasip1-threads`); the host side is `web/host.js`, about 250 lines with no dependency.
- **A fallback.** Browsers only give shared memory to cross-origin isolated pages (COOP and COEP
  headers). Where the host cannot send them, a service worker adds them; where that is impossible
  too (plain http), the page proves on one thread with the first build.

`web/README.md` explains how to put the page in front of a phone and what to send back. Tacit publishes
12–15 s for its single-thread Halo2 prover in a browser, with proofs 4.3 times larger.

## Batches and the 150 vB target

The cost budget asks for 150 vB or less per transfer when a relayer publishes several in one
transaction (`docs/SPEC-WIRE.md` §3). A batch of ten costs 222.9 vB each today, because every
TRANSFER carries its own 480-byte proof. This section measures what could bring that down. Nothing
in it is a rule: the envelopes and circuits compared exist only in `bench/batch-vsize.mjs` (sizes)
and `examples/batch_cost.rs` (proofs, on the powers of the pinned Hermez file). Same laptop as
above, 2026-11-21.

**What the target leaves.** A reveal that carries `n` envelopes weighs
`(515 + Σ (envelope + 10)) / 4` vB. At ten, 150 vB each leaves 540 bytes for an envelope: 6 of
header, 480 of proof, and 54 for the spend, whose two nullifiers and three leaves alone are 160. So
nothing done to the body reaches the target while every transfer brings a proof: with no ciphertext
on chain at all, a transfer still costs 177.7 vB. The target takes fewer proofs than transfers, and
at least three transfers under each proof: two give 161.2 vB at ten, three give 148.7.

| Lead | Envelope bytes per transfer, at ten | vB per transfer, at ten | Proving on the phone | Hard requirements | What it costs |
| --- | ---: | ---: | --- | --- | --- |
| **Today**: a proof for each TRANSFER | 830 | 222.9 | 5.7 s on six threads, 15.5 s on one | kept | |
| **Grouped verification**: the indexer checks the proofs of a batch in one pairing equation | 830 | 222.9 | unchanged | kept: nothing on the wire changes | saves indexer time and no byte: ten proofs in 4.0 ms instead of 17.2 |
| **Shared openings**: the senders prove under common challenges, and the batch carries one pair of opening points for all | 772 | 208.3 | unchanged, plus four exchanges with every sender online at once | **4 is not**: snarkjs draws the challenges of a proof from that proof alone, and cannot check these | a sender who stops voids the batch; one bad proof refuses every transfer, where each is judged alone today |
| **One ephemeral key** for the three outputs of a transfer | 766 | 206.7 | unchanged | kept | a change of bytes and of `SPEC-NOTES.md` §3, where each output draws its own key: the derivation must then tell the three outputs apart |
| **The relayer's output as a leaf alone**, without key or ciphertext | 770 | 207.7 | unchanged | kept | the sender gives the relayer the opening, and the relayer must keep it: nothing on chain gives it back |
| The two above together | 738 | 199.7 | unchanged | kept | |
| **Two outputs** instead of three | 738 | 199.7 | unchanged | kept | decided against on 2026-11-18: the third output pays the relayer |
| **Three transfers under one proof**, proved by one wallet | 538 | 148.7 | about 11 s on six threads and 31 s on one, about 500 MB: projected, not run on a phone | kept: the largest circuit `pot18` allows | only for three transfers of one wallet, which the last row serves better |
| **Three transfers under one proof**, proved by the relayer | 538 | 148.7 | none: the phone signs and hands over its witness | kept | the relayer sees each transfer whole, and the amount its payee receives (below) |
| **The ten under one proof**, proved by the relayer | 393 | 111.8 | none | **4 is not**: a domain of 2^20, and `pot18` stops at 2^18 | the same, for ten |
| **Recursion**: the relayer proves that it holds ten valid proofs | 393 | 111.8 | unchanged for each sender | **4 is not**: far beyond `pot18` | not built; an estimate below |
| **A Groth16 proof** for each transfer (128 bytes) | 478 | 134.2 | not measured | **4 is not**: a ceremony for this circuit, run by someone | the setup the project chose not to have |
| **One transfer that pays ten people** (2 inputs, 11 outputs) | 157 for each person paid | 52.4 | unchanged: the same domain | kept | another use, one payer and several payees; a second relation, with its own key and its own audit |

**The proofs.** Each circuit below is the spend relation with other counts, built by
`examples/batch_cost.rs` from the gadgets of `src/`; with two inputs and three outputs it emits
exactly the gates of `src/spend.rs`, and the run checks it. Every proof is 480 bytes and verifies
in about 2 ms. Times are on one thread, the circuits proved in turn and the best pass kept: the
laptop was busy that day, and one thread is what stayed steady (today's circuit: 9.9 s, 9.6 s in
the table at the top). The last two rows are from a second run, compared with today's circuit in
that run (9.7 s). Memory is the peak of the whole process, key generation included, on one thread;
on ten threads for the last two rows.

| Circuit | Gates | Domain | Powers of tau | Proving, one thread | Against today | Peak memory |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| today: one spend, 2 inputs, 3 outputs | 86,248 | 2^17 | 131,078 | 9.9 s | 1 | 247 MB |
| one spend, 2 inputs, 11 outputs | 102,240 | 2^17 | 131,078 | 9.9 s | 1.00 | |
| one spend, 2 inputs, 25 outputs | 130,226 | 2^17 | 131,078 | 9.8 s | 0.99 | 260 MB |
| two spends | 172,496 | 2^18 | 262,150 | 19.3 s | 1.96 | |
| three spends | 258,744 | 2^18 | 262,150 | 19.5 s | 1.98 | 543 MB |
| four spends | 344,992 | 2^19 | 524,294 | 36.8 s | 3.8 | 1.3 GB |
| ten spends | 862,480 | 2^20 | 1,048,582 | 74.3 s | 7.6 | 2.4 GB |

- **The time follows the domain, not the gates.** Eleven or 25 outputs prove as fast as three; a
  26th output, or a sixth beside a third input, goes to the next domain and doubles the time.
- **`pot18` stops at three spends.** The file holds 524,287 powers. A domain of 2^18 needs 262,150
  of them; a domain of 2^19 needs 524,294, seven more than there are. The rows of four and ten
  spends were proved on powers of a throwaway tau, for the time and the memory only: on ten threads
  the ten spends take 15.4 s, which is what a relayer's machine would spend on them. Four spends in
  2^18 would take a spend of 65,536 gates, the limit that item 3 of "Next" expects to miss by about
  a thousand.
- **The phone column is a projection.** It takes the phone's own figures for today's circuit and
  the laptop's ratio: 1.98 for the time, 2.2 for the memory. The test page proves the spend circuit
  only, so no phone has run a domain of 2^18: 500 MB in a browser tab is the first thing to check.
- **Grouped verification.** Each proof's pairing equation is multiplied by a number the verifier
  draws, and the equations are added: ten proofs take 4.0 ms instead of 17.2, a hundred take 18 ms
  instead of 155 (one thread, native; the WebAssembly verifier is about nine times slower either
  way). A batch with one bad proof fails as a whole and is then checked proof by proof, since each
  transfer is accepted or refused alone. So it speeds up honest batches and nothing else, and an
  indexer can do it on its own: no byte and no rule changes.

**Why a shared proof needs someone who sees everything.** A proof covers the witnesses its prover
holds. Three people's transfers under one proof means one party with the three witnesses: for each
input note its amount, its ticker and its position (so which earlier output is being spent), for
each output its amount and its key, the payee's included, and `nsk + τn` for each input, which
`SPEC-NOTES.md` §6 counts as sensitive as `nsk`: together with the sender of that note it gives
`nsk`. That party cannot spend, since the signatures it is handed are over the body, and it does
not learn the payee's address. A relayer is there to hide who pays the fees; one that proves also
learns the token, the amounts and which notes are spent.

Two ways keep the witnesses with the senders, and neither fits requirement 4. Recursion is one:
the relayer proves, in a circuit, that it holds ten proofs that verify. That circuit does
BN254 arithmetic over a field that is not its own, at least nine multiplications of a point by a
scalar for each proof. One published figure gives the scale: a single ECDSA verification on
secp256k1, two such multiplications, is 1,508,136 constraints in circom-ecdsa. Ten proofs would be
on the order of 10^8 gates, a domain near 2^27, five hundred times what `pot18` holds. This is an
estimate, not a measurement. The other is a scheme that folds many PLONK proofs into one of
logarithmic size (aPlonK, ePrint 2022/1352): it comes with a verifier of its own, which snarkjs
does not have. It was not measured.

**Recommendation.**

1. **Keep one proof for each relayed transfer.** The target as written, 150 vB for a transfer in a
   relayer's batch, cannot be met under requirement 4 while senders keep their witnesses. It takes
   a relayer that sees the transfers, a ceremony (Groth16), or a recursion far beyond `pot18`. If
   the maintainer accepts the first for senders who choose it, three transfers under one proof is
   within `pot18` and measured here: 148.7 vB, nothing to prove on the phone, 4 s on the relayer's
   laptop for three.
2. **What a relayed transfer can cost instead is about 200 vB.** One ephemeral key for a transfer
   and a bare leaf for the relayer's output take 92 bytes off each (222.9 to 199.7 vB at ten). Both
   are changes of bytes, for a later version of the wire; the first also changes
   `SPEC-NOTES.md` §3, which has not had its outside review. The line of the budget would then read
   "about 200 vB".
3. **The target is met, with room, where one payer pays several people.** Two inputs and up to 25
   outputs fit the present domain and prove in the same time on the phone: 52.4 vB for each person
   paid at ten, 35.3 at 24. Three inputs and five outputs fit as well (129,995 gates). That is a
   withdrawal run of an exchange, a payroll, an airdrop, or a relayer paying out. It is also a
   second relation: an extension type, its own key from the same powers, its own audit. Worth a
   design after the signet, and not before the first relation is audited.
4. **Not worth building**: shared openings (15 vB, against requirement 4, and one sender can stop
   the batch) and several spends under one proof for a single wallet (item 3 does more in half the
   time and memory).
5. **Grouped verification** is free for an indexer whenever volume asks for it.

## How the result is checked

- `cargo test --release`: 35 tests. Model against the indexer's constants; 34 adversarial witnesses
  (inflation, wrong ticker, double-spend attempts, bad ranges, wrong or swapped signatures, aliased
  keys, points off the curve) rejected by the gates; proofs end to end with every public input and
  proof byte bound; the shipped proving key reproduced by key generation.
- **No free variable** (`tests/constraints.rs`). Every variable of five honest assignments is moved,
  alone, to other values: a gate breaks. Every variable the prover chooses is changed with all that
  follows from it recomputed: a check still fails. The only exceptions are those of a dummy input,
  which skips membership: its 32 Merkle siblings and one inverse witness. `tests/gadgets.rs` takes
  the gadgets to their limits: points off the curve, the ends of each range, keys of small order,
  and the second way to write a field element in 254 bits.
- **A second verifier, both ways** (`bench/cross-check.sh`, required by the handoff). The transcript
  and key fields match snarkjs' PLONK: `snarkjs plonk verify` accepts the proofs made here and
  rejects tampered inputs, and the verifier here accepts a proof made by snarkjs' prover
  (`tests/fixtures/snarkjs/`, checked by `cargo test`) and rejects tampered ones.
- **A second statement of the relation.** `circom/spend.circom` states the relation with circomlib's
  Poseidon, EdDSA and BabyJubJub. A witness built by the Rust model satisfies it and yields the
  same nine public signals (`bench/circom-check.mjs`), and the two agree on every honest and every
  adversarial witness of `src/fixture.rs`: 5 accepted by both, 34 refused by both
  (`bench/circom-cases.mjs`).
- **The reference indexer.** `indexer/test/plonk.test.js` replays a chain with a real TRANSFER and a
  real BURN and verifies them through the WebAssembly module.
- **The wallet side.** `js/` restates in plain JavaScript what a wallet computes for a spend. Its
  vectors are written by the model here (`src/vectors.rs`); `cargo test` fails if the file drifts and
  `npm test` in `js/` fails if the JavaScript disagrees. Poseidon is tied to circomlibjs for every width.
- **The page.** `web/check.mjs` runs it in headless Chrome for each way it can be served.

None of this replaces an audit. The gadgets in `src/gadgets.rs` and the verifier in
`src/plonk/verifier.rs` are the soundness-critical code.

## Use

```sh
cargo test --release                                                  # uses artifacts/spend.pk
cargo run --release --bin sh20-circuit -- bench artifacts/spend.pk    # RAYON_NUM_THREADS=1 for one thread
./build-wasm.sh                                                       # both WebAssembly builds
node bench/wasm-bench.mjs target/wasm32-unknown-unknown/release/sh20_circuit.wasm artifacts/spend.pk
node bench/wasm-threads-bench.mjs target/wasm32-wasip1-threads/release/sh20_circuit.wasm artifacts/spend.pk 4
web/build.sh && node web/serve.mjs                                    # the phone test page, on port 8080
bench/cross-check.sh                                                  # snarkjs, both ways (needs npm ci in bench/)
```

Rebuilding the shipped key from the public setup, to check it rather than trust it:

```sh
curl -L -o pot18.ptau https://circom.info/powersOfTau28_hez_final_18.ptau   # 302 MB; its BLAKE2b is checked
cargo run --release --bin sh20-circuit -- srs pot18.ptau build/hermez-pot18-2p17.srs
cargo run --release --bin sh20-circuit -- pk build/hermez-pot18-2p17.srs build/spend.pk
cmp build/spend.pk artifacts/spend.pk
```

Library entry points: `load_key`, `keygen`, `prove`, `verify` in `src/lib.rs`; the C ABI of the
WebAssembly modules is in `src/ffi.rs`. `artifacts/spend.vk` is the verifying key alone, for verifiers.

Reproducing the measurements (`bench/`, needs `npm ci` there, and circom 2.2.3 for the circom rows):

```sh
circom circom/spend.circom --r1cs --wasm --O1 -l bench/node_modules -o build/o1
npx snarkjs plonk setup build/o1/spend.r1cs pot18.ptau build/o1/spend_plonk.zkey
node bench/prove-snarkjs.mjs plonk build/o1/spend_plonk.zkey build/o1/spend_js/spend.wasm 3 [--single]
node bench/prove-snarkjs.mjs fflonk <zkey made with powersOfTau28_hez_final_21.ptau> build/o1/spend_js/spend.wasm 3
node bench/tx-vsize.mjs
node bench/batch-vsize.mjs                                                # the sizes of "Batches and the 150 vB target"
RAYON_NUM_THREADS=1 cargo run --release --example batch_cost -- pot18.ptau 1x2:3 1x2:11 1x2:25 2x2:3 3x2:3 verify:10
(cd bench/halo2-shape && cargo run --release -- vanilla 17 && cargo run --release -- narrow 14)
```

## Layout

| Path | What |
| --- | --- |
| `src/spend.rs` | the relation, as gates |
| `src/gadgets.rs` | Poseidon, bit decompositions, BabyJubJub, EdDSA-Poseidon, Merkle path |
| `src/model.rs` | the reference model the gates constrain: keys, leaf, nullifier, signature, tree, witness |
| `src/notes.rs` | the wallet model of `docs/SPEC-NOTES.md`: keys, address, sealing, scanning, public notes (not in the WebAssembly builds) |
| `src/poseidon.rs` | Poseidon; constants generated with the Grain LFSR, as in the indexer |
| `src/cs.rs` | constraint system |
| `src/plonk/` | SRS, key generation, prover, verifier, transcript, encodings |
| `src/wire.rs` | envelope bytes a wallet builds |
| `src/ffi.rs` | C ABI for WebAssembly and native callers |
| `artifacts/` | the shipped proving key and the verifying key |
| `web/` | the phone test page and the host side of the threaded build |
| `circom/` | the same relation in circom, for cross-checks only |
| `bench/` | measurement scripts |
| `js/` | what a wallet computes for a spend, in dependency-free JavaScript, with vectors written by `src/vectors.rs` |

## Next

1. **Phone figures**: one recent phone is measured (above). Still missing: a mid-range phone and an
   Android phone. One lead for the next sweep, not built: a parallel region ends when its slowest
   task does, and a commitment is only 20 tasks, one per window, so a slow core that picks up the
   last window keeps the fast ones waiting. On the iPhone the third thread adds 0.12 of one thread's
   speed to the commitments, where the fifth and the sixth add 0.33 each. Committing the polynomials
   of a round in one region (60 tasks instead of three times 20), or cutting a window into smaller
   tasks, would leave the tail to the fast cores. It holds several digit tables at once: measure the
   memory with it.
2. **Memory**: 224 MB at peak. The wire evaluations and the key file are still held longer than
   needed; there is room below 200 MB.
3. **Fewer gates**: the circuit is 86,248 gates and a 2^16 domain, which would halve the proving
   time, holds 65,536. Sparse Poseidon rounds, windowed fixed-base multiplication and cheaper
   comparisons should reach about 66,600 (an estimate, not yet built). That is still above the limit,
   and the three outputs stay (the third pays a relayer in tokens), so the last thousand gates have to
   be found without changing a rule. Each change moves the verifying-key digest. On hold (maintainer,
   2026-11-19).
4. An audit ([`docs/AUDIT.md`](../docs/AUDIT.md) is the dossier for the auditor), then the freeze of the digest.
5. **Batches**: the choice left by "Batches and the 150 vB target" is the maintainer's. A transfer
   with more outputs, if wanted, is a second relation to design, key and audit.

## Licence

MIT. `src/model.rs`, `src/spend.rs`, the EdDSA gadget and `circom/` derive from Tacit's Bitcoin
shielded pool (MIT, Copyright (c) 2026 ross); the notices are in the files. The crate depends on
arkworks, RustCrypto hashes, num-bigint and rayon (MIT or Apache-2.0). circom, circomlib and snarkjs
(GPL-3.0) are used by `bench/` as independent cross-checks and are not part of the crate.
