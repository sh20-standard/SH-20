#!/usr/bin/env bash
# Keeps the PLONK verifier cross-checked against snarkjs (CLAUDE.md, hard requirement 4), both ways:
#
#   1. snarkjs' verifier accepts a spend proof made by this crate and rejects a tampered input;
#   2. this crate's verifier accepts a proof made by snarkjs' prover and rejects tampered ones;
#   3. circomlib's statement of the spend relation accepts a witness built by the Rust model, with
#      the same public signals;
#   4. that statement and the Rust circuit give the same answer on every honest and every
#      adversarial witness of src/fixture.rs: accepted by both, or refused by both.
#
#   bench/cross-check.sh [--write-fixtures]
#
# Needs `npm ci` in bench/. Steps 2 to 4 also need circom (2.1.6 or later) and the pinned Hermez
# file: PTAU=/path/to/powersOfTau28_hez_final_18.ptau. Without them those steps are skipped, and
# `cargo test` still checks step 2 on the proof kept in tests/fixtures/snarkjs/.
# --write-fixtures replaces that proof with the one just made.
set -euo pipefail
cd "$(dirname "$0")/.."
SNARKJS="node bench/node_modules/snarkjs/build/cli.cjs"
BIN=target/release/sh20-circuit
OUT=build/cross-check
mkdir -p "$OUT"
cargo build --release --quiet --bin sh20-circuit

echo "1. snarkjs verifies a spend proof made here"
$BIN prove-sample artifacts/spend.pk "$OUT" > /dev/null
(cd bench && node cross-verify.mjs "../$OUT" spend)

if ! command -v circom > /dev/null || [ -z "${PTAU:-}" ]; then
  echo "2, 3, 4. skipped: need circom on the PATH and PTAU=<Hermez pot18>"
  exit 0
fi

echo "2. this crate verifies a proof made by snarkjs"
circom circom/cubic.circom --r1cs --wasm -o "$OUT" > /dev/null
$SNARKJS plonk setup "$OUT/cubic.r1cs" "$PTAU" "$OUT/cubic.zkey" > /dev/null
$SNARKJS zkey export verificationkey "$OUT/cubic.zkey" "$OUT/cubic.vk.json" > /dev/null
echo '{"x": "3"}' > "$OUT/cubic.input.json"
$SNARKJS plonk fullprove "$OUT/cubic.input.json" "$OUT/cubic_js/cubic.wasm" "$OUT/cubic.zkey" "$OUT/cubic.proof.json" "$OUT/cubic.public.json" > /dev/null
[ "$($BIN verify-snarkjs "$OUT/cubic.vk.json" "$OUT/cubic.proof.json" "$OUT/cubic.public.json")" = valid ] || { echo "FAIL: a snarkjs proof was refused"; exit 1; }
echo '["36"]' > "$OUT/cubic.bad.json"
if $BIN verify-snarkjs "$OUT/cubic.vk.json" "$OUT/cubic.proof.json" "$OUT/cubic.bad.json" > /dev/null; then echo "FAIL: a tampered input was accepted"; exit 1; fi
echo "   accepted; a tampered public input is rejected"
if [ "${1:-}" = "--write-fixtures" ]; then
  mkdir -p tests/fixtures/snarkjs
  for f in vk proof public; do cp "$OUT/cubic.$f.json" "tests/fixtures/snarkjs/cubic.$f.json"; done
  echo "   tests/fixtures/snarkjs/ rewritten"
fi

echo "3. circomlib's statement of the relation accepts the Rust witness"
circom circom/spend.circom --r1cs --wasm --O1 -l bench/node_modules -o "$OUT" > /dev/null
(cd bench && node circom-check.mjs "../$OUT/spend_js/spend.wasm" "../$OUT/spend.input.json" "../$OUT/spend.public.json")

echo "4. circom and the Rust circuit agree on every honest and every adversarial witness"
rm -rf "$OUT/cases"
$BIN cases "$OUT/cases" > /dev/null
(cd bench && node circom-cases.mjs "../$OUT/spend_js/spend.wasm" "../$OUT/cases")
