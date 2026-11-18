# sh20-circuit

The spend circuit of **SH-20** (`docs/SPEC-WIRE.md` §4): prover, verifier, and the measurements
behind the choice of proof system.

**Status: draft v0.3. Not audited. Not activated anywhere.**

| | |
| --- | --- |
| Proof system | PLONK over BN254 with KZG commitments (ePrint 2019/953, three wires, no custom gates) |
| Setup | none of ours: the public Hermez `powersOfTau28_hez_final_18.ptau`, 131,078 powers of it |
| Proof | **480 bytes** (9 G1 points, 6 scalars) |
| Circuit | 86,232 gates, domain 2^17, 9 public inputs |
| Verifying key | 712 bytes, digest `da847145dbc5aa847af92ce5696fbd60bd57e6fbdf0e077cc1b62a0ba302492d` |
| Proving key | `artifacts/spend.pk`, 8.4 MB (the verifying key and the SRS powers), SHA-256 `a376301be345cdeab66a0155714fa81976102d570ee6a3223edaf64a4d9e430a`; loads in 0.2 s, 1.4 s in WebAssembly |
| Proving time, native | 1.8 s on a laptop (10 threads); 9.6 s on one thread |
| Proving time, WebAssembly | 25 s on one thread; 13 s on 2 threads, 7.2 s on 4, 5.6 s on 6, 4.4 s on 10 |
| Proving time, on a phone | iPhone 18 Pro Max, Safari: 14.5 s on 4 threads, 31.9 s on one |
| Prover memory | 224 MB in WebAssembly (242 MB with 10 threads) |
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

Measured by the maintainer on 2026-11-18 with the page of `web/`, served over https with the
isolation headers. Proving times are the median of three proofs, with the three in brackets.

| Device | Browser | Threads | Proving time | Key loading | Prover memory | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| iPhone 18 Pro Max, iOS 18.7 | Safari | 4 | 14.5 s (14.3 / 14.5 / 14.8) | 0.7 s | 232 MB | 15 ms |
| iPhone 18 Pro Max, iOS 18.7 | Safari | 1 | 31.9 s (36.6 / 31.9 / 30.7) | 5.5 s | 224 MB | |
| MacBook Pro M1 Pro | Chrome | 10 | 4.5 s | | | |
| MacBook Pro M1 Pro | Chrome | 1 | 25.5 s | | | |

So a recent phone proves a transfer in about 15 s, and the prover fits in its memory. Two things in
these figures are not explained yet: four threads are only 2.2 times faster than one on the phone,
and in single-thread mode the key takes 5.5 s to load there against 0.7 s with threads. A mid-range
phone has not been measured.

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
  Rust (`wasm32-wasip1-threads`); the host side is `web/host.js`, about 200 lines with no dependency.
- **A fallback.** Browsers only give shared memory to cross-origin isolated pages (COOP and COEP
  headers). Where the host cannot send them, a service worker adds them; where that is impossible
  too (plain http), the page proves on one thread with the first build.

`web/README.md` explains how to put the page in front of a phone and what to send back. Tacit publishes
12–15 s for its single-thread Halo2 prover in a browser, with proofs 4.3 times larger.

## How the result is checked

- `cargo test --release`: 28 tests. Model against the indexer's constants; 26 adversarial witnesses
  (inflation, wrong ticker, double-spend attempts, bad ranges, wrong or swapped signatures, aliased
  keys) rejected by the gates; proofs end to end with every public input and proof byte bound;
  every variable of the assignment pinned by at least one gate; the shipped proving key reproduced
  by key generation.
- **A second verifier, both ways** (`bench/cross-check.sh`, required by the handoff). The transcript
  and key fields match snarkjs' PLONK: `snarkjs plonk verify` accepts the proofs made here and
  rejects tampered inputs, and the verifier here accepts a proof made by snarkjs' prover
  (`tests/fixtures/snarkjs/`, checked by `cargo test`) and rejects tampered ones.
- **A second statement of the relation.** `circom/spend.circom` states the relation with circomlib's
  Poseidon, EdDSA and BabyJubJub. A witness built by the Rust model satisfies it and yields the
  same nine public signals (`bench/circom-check.mjs`).
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

1. **Phone figures**: one recent phone is measured (above). Still missing: a mid-range phone, and why
   four threads only give 2.2 times one on the iPhone.
2. **Memory**: 224 MB at peak. The wire evaluations and the key file are still held longer than
   needed; there is room below 200 MB.
3. **Fewer gates**: the circuit is 86,232 gates and a 2^16 domain, which would halve the proving
   time, holds 65,536. Sparse Poseidon rounds, windowed fixed-base multiplication and cheaper
   comparisons should reach about 66,600 (an estimate, not yet built). That is still above the limit,
   and the three outputs stay (the third pays a relayer in tokens), so the last thousand gates have to
   be found without changing a rule. Each change moves the verifying-key digest.
4. An audit, then the freeze of the digest.

## Licence

MIT. `src/model.rs`, `src/spend.rs`, the EdDSA gadget and `circom/` derive from Tacit's Bitcoin
shielded pool (MIT, Copyright (c) 2026 ross); the notices are in the files. The crate depends on
arkworks, RustCrypto hashes, num-bigint and rayon (MIT or Apache-2.0). circom, circomlib and snarkjs
(GPL-3.0) are used by `bench/` as independent cross-checks and are not part of the crate.
