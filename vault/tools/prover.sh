#!/usr/bin/env bash
# Builds the spend prover's two WebAssembly modules from circuit/ (unchanged) into vault/prover/,
# the copies the vault ships:
#
#   prover/sh20_circuit.wasm            wasm32-unknown-unknown   one thread, no imports
#   prover/sh20_circuit_threads.wasm    wasm32-wasip1-threads    a thread pool over Web Workers
#
# Same cargo commands as circuit/build-wasm.sh, plus --remap-path-prefix: rustc writes the source
# path of every crate into panic messages, and those paths name this machine (CLAUDE.md, hard
# requirement 5) and differ from one machine to the next. With the prefixes mapped to /sh20 and
# /cargo, the same toolchain gives the same bytes anywhere (test/prover.test.js compares them).
#
#   tools/prover.sh            build and copy
#   tools/prover.sh --check    build and fail if the bytes differ from the committed ones
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
target="$here/prover/.target"
export RUSTFLAGS="--remap-path-prefix=$repo=/sh20 --remap-path-prefix=$cargo_home=/cargo ${RUSTFLAGS:-}"
export CARGO_TARGET_DIR="$target"
cd "$repo/circuit"
cargo build -q --lib --release --locked --target wasm32-unknown-unknown --no-default-features
cargo build -q --lib --release --locked --target wasm32-wasip1-threads --no-default-features --features parallel
single="$target/wasm32-unknown-unknown/release/sh20_circuit.wasm"
threads="$target/wasm32-wasip1-threads/release/sh20_circuit.wasm"
if grep -a -q -e "$HOME" -e "$repo" "$single" "$threads"; then echo "a machine path is still in the modules" >&2; exit 1; fi
if [ "${1:-}" = "--check" ]; then
  cmp "$single" "$here/prover/sh20_circuit.wasm" && cmp "$threads" "$here/prover/sh20_circuit_threads.wasm"
  echo "OK: the committed modules are what this toolchain builds ($(rustc --version))"
else
  cp "$single" "$here/prover/sh20_circuit.wasm"
  cp "$threads" "$here/prover/sh20_circuit_threads.wasm"
fi
shasum -a 256 "$here/prover/sh20_circuit.wasm" "$here/prover/sh20_circuit_threads.wasm" | sed "s#  $here/#  #"
