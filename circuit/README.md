# sh20-circuit

The spend circuit of **SH-20** (`docs/SPEC-WIRE.md` §4): prover, verifier, and the measurements
behind the choice of proof system.

**Status: draft v0.2. Not audited. Not activated anywhere.**

| | |
| --- | --- |
| Proof system | PLONK over BN254 with KZG commitments (ePrint 2019/953, three wires, no custom gates) |
| Setup | none of ours: the public Hermez `powersOfTau28_hez_final_18.ptau`, 131,078 powers of it |
| Proof | **480 bytes** (9 G1 points, 6 scalars) |
| Circuit | 86,232 gates, domain 2^17, 9 public inputs |
| Verifying key | 712 bytes, digest `da847145dbc5aa847af92ce5696fbd60bd57e6fbdf0e077cc1b62a0ba302492d` |
| Proving time | 1.6 s on a laptop (10 threads); 8.6 s on one thread; 22 s in single-thread WebAssembly |
| Key generation | once per device: 1.4 s (10 threads), 7.8 s (1 thread), 19.5 s in single-thread WebAssembly |
| Verification | 1.5 ms native, 14 ms in WebAssembly |

Keys are derived from the gates and the SRS and from nothing else, so anyone recomputes the same
verifying key: there is no ceremony and no secret.

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

Not measured yet: a real phone, a browser, and WebAssembly threads. The 22 s single-thread
WebAssembly figure was taken in Node on the laptop above and is the closest stand-in available here;
Tacit publishes 12–15 s for its Halo2 prover in the same setting. The module's memory peaks at
425 MB, which is too much for some phones (see "Next").

## How the result is checked

- `cargo test --release`: 16 tests. Model against the indexer's constants; 26 adversarial witnesses
  (inflation, wrong ticker, double-spend attempts, bad ranges, wrong or swapped signatures, aliased
  keys) rejected by the gates; proofs end to end with every public input and proof byte bound;
  every variable of the assignment pinned by at least one gate; the pinned key digest.
- **A second verifier.** The transcript and key fields match snarkjs' PLONK, so `snarkjs plonk verify`
  accepts the proofs made here and rejects tampered inputs (`bench/cross-verify.mjs`).
- **A second statement of the relation.** `circom/spend.circom` states the relation with circomlib's
  Poseidon, EdDSA and BabyJubJub. A witness built by the Rust model satisfies it and yields the
  same nine public signals (`bench/circom-check.mjs`).
- **The reference indexer.** `indexer/test/plonk.test.js` replays a chain with a real TRANSFER and a
  real BURN and verifies them through the WebAssembly module.

None of this replaces an audit. The gadgets in `src/gadgets.rs` and the verifier in
`src/plonk/verifier.rs` are the soundness-critical code.

## Use

```sh
# the SRS, from the pinned Hermez file (302 MB; its BLAKE2b is checked)
curl -L -o pot18.ptau https://circom.info/powersOfTau28_hez_final_18.ptau
cargo run --release --bin sh20-circuit -- srs pot18.ptau build/hermez-pot18-2p17.srs

cargo test --release                                                          # uses the SRS above when present
cargo run --release --bin sh20-circuit -- keygen build/hermez-pot18-2p17.srs build/spend.vk
cargo run --release --bin sh20-circuit -- bench build/hermez-pot18-2p17.srs  # RAYON_NUM_THREADS=1 for one thread
./build-wasm.sh                                                               # prover and verifier, no imports
```

`artifacts/spend.vk` is the verifying key those commands reproduce. Library entry points:
`keygen`, `prove`, `verify` in `src/lib.rs`; the C ABI of the WebAssembly module is in `src/ffi.rs`.

Reproducing the measurements (`bench/`, needs `npm ci` there, and circom 2.2.3 for the circom rows):

```sh
circom circom/spend.circom --r1cs --wasm --O1 -l bench/node_modules -o build/o1
npx snarkjs plonk setup build/o1/spend.r1cs pot18.ptau build/o1/spend_plonk.zkey
node bench/prove-snarkjs.mjs plonk build/o1/spend_plonk.zkey build/o1/spend_js/spend.wasm 3 [--single]
node bench/prove-snarkjs.mjs fflonk <zkey made with powersOfTau28_hez_final_21.ptau> build/o1/spend_js/spend.wasm 3
node bench/wasm-bench.mjs target/wasm32-unknown-unknown/release/sh20_circuit.wasm build/hermez-pot18-2p17.srs
node bench/tx-vsize.mjs
(cd bench/halo2-shape && cargo run --release -- vanilla 17 && cargo run --release -- narrow 14)
```

## Layout

| Path | What |
| --- | --- |
| `src/spend.rs` | the relation, as gates |
| `src/gadgets.rs` | Poseidon, bit decompositions, BabyJubJub, EdDSA-Poseidon, Merkle path |
| `src/model.rs` | the reference model the gates constrain: keys, leaf, nullifier, signature, tree, witness |
| `src/poseidon.rs` | Poseidon; constants generated with the Grain LFSR, as in the indexer |
| `src/cs.rs` | constraint system |
| `src/plonk/` | SRS, key generation, prover, verifier, transcript, encodings |
| `src/wire.rs` | envelope bytes a wallet builds |
| `src/ffi.rs` | C ABI for WebAssembly and native callers |
| `circom/` | the same relation in circom, for cross-checks only |
| `bench/` | measurement scripts |
| `js/` | what a wallet computes for a spend, in dependency-free JavaScript, with vectors written by `src/vectors.rs` |

## Next

1. **Phone and browser**: measure on real devices; add a threaded WebAssembly build.
2. **Memory and start-up**: 425 MB at peak. Computing the quotient in four cosets of size n, and the
   selector evaluations on the fly, should bring it near 150 MB. Key generation recomputes the eight
   commitments of the verifying key, which a wallet can take from the pinned key instead.
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
