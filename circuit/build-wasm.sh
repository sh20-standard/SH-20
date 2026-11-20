#!/usr/bin/env bash
# Builds the WebAssembly modules of the spend circuit (prover and verifier in each):
#
#   target/wasm32-unknown-unknown/release/sh20_circuit.wasm    one thread, no imports: runs anywhere,
#                                                              and is what the indexer loads
#   target/wasm32-wasip1-threads/release/sh20_circuit.wasm     a thread pool over Web Workers on a
#                                                              shared memory (host side: web/host.js)
#
# The two targets come with the Rust pinned in rust-toolchain.toml.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --lib --release --target wasm32-unknown-unknown --no-default-features
cargo build --lib --release --target wasm32-wasip1-threads --no-default-features --features parallel
for out in target/wasm32-unknown-unknown/release/sh20_circuit.wasm target/wasm32-wasip1-threads/release/sh20_circuit.wasm; do
  echo "$out: $(wc -c < "$out" | tr -d ' ') bytes, sha256 $(shasum -a 256 "$out" | cut -d' ' -f1)"
done
