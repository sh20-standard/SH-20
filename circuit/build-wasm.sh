#!/usr/bin/env bash
# Builds the WebAssembly module of the spend circuit: one thread, no imports, prover and verifier.
#   target/wasm32-unknown-unknown/release/sh20_circuit.wasm
# Needs the wasm32 target once: rustup target add wasm32-unknown-unknown
set -euo pipefail
cd "$(dirname "$0")"
cargo build --lib --release --target wasm32-unknown-unknown --no-default-features
out=target/wasm32-unknown-unknown/release/sh20_circuit.wasm
echo "$out: $(wc -c < "$out" | tr -d ' ') bytes, sha256 $(shasum -a 256 "$out" | cut -d' ' -f1)"
