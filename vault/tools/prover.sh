#!/usr/bin/env bash
# Builds the spend prover's two WebAssembly modules from circuit/ (unchanged) into vault/prover/,
# the copies the vault ships:
#
#   prover/sh20_circuit.wasm            wasm32-unknown-unknown   one thread, no imports
#   prover/sh20_circuit_threads.wasm    wasm32-wasip1-threads    a thread pool over Web Workers
#
# Same cargo commands as circuit/build-wasm.sh, plus --remap-path-prefix: rustc writes the source
# path of every crate into panic messages, and those paths name this machine (CLAUDE.md, hard
# requirement 5) and differ from one machine to the next: the prefixes are mapped to /sh20 and /cargo.
# The flags go through `cargo --config`, which adds them to circuit/.cargo/config.toml (its exports
# for the threaded build); a RUSTFLAGS variable would replace that file's flags.
#
# The machine's host triple changes the bytes too, through the symbol hashes; tools/rustc-host.sh
# says how and builds as from x86_64-unknown-linux-gnu everywhere. With both, the Rust pinned in
# circuit/rust-toolchain.toml gives the same two files on a macOS arm64 laptop and on a Linux x86_64
# CI runner (checked on 2026-11-20), and the CI rebuilds them on every push (--check).
#
#   tools/prover.sh            build and copy
#   tools/prover.sh --check    build and fail if the bytes differ from the committed ones
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
target="$here/prover/.target"
remap="[\"--remap-path-prefix=$repo=/sh20\", \"--remap-path-prefix=$cargo_home=/cargo\"]"
export CARGO_TARGET_DIR="$target"
export RUSTC_WRAPPER="$here/tools/rustc-host.sh"
# each of these would change the flags or the crate ids, hence the bytes
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER __CARGO_DEFAULT_LIB_METADATA
cd "$repo/circuit"
cargo build -q --lib --release --locked --target wasm32-unknown-unknown --no-default-features --config "target.wasm32-unknown-unknown.rustflags = $remap"
cargo build -q --lib --release --locked --target wasm32-wasip1-threads --no-default-features --features parallel --config "target.wasm32-wasip1-threads.rustflags = $remap"
single="$target/wasm32-unknown-unknown/release/sh20_circuit.wasm"
threads="$target/wasm32-wasip1-threads/release/sh20_circuit.wasm"
if grep -a -q -e "$HOME" -e "$repo" "$single" "$threads"; then echo "a machine path is still in the modules" >&2; exit 1; fi
# the exports the host calls (circuit/web/host.js, prover-worker.js)
node -e '
const fs = require("fs");
const need = { [process.argv[1]]: ["sh20_prove", "sh20_load_key"], [process.argv[2]]: ["__wasi_init_tp", "__wasm_call_ctors", "wasi_thread_start", "sh20_threads", "sh20_prove"] };
for (const [f, names] of Object.entries(need)) {
  const have = WebAssembly.Module.exports(new WebAssembly.Module(fs.readFileSync(f))).map((e) => e.name);
  const missing = names.filter((n) => !have.includes(n));
  if (missing.length) { console.error(f + " lacks " + missing.join(", ")); process.exit(1); }
}' "$single" "$threads"
if [ "${1:-}" = "--check" ]; then
  # Each comparison counts by itself. Written `cmp a && cmp b`, a difference in the first module did
  # not stop the script (`set -e` ignores a failure on the left of `&&`) and "OK" was printed anyway.
  same=yes
  cmp "$single" "$here/prover/sh20_circuit.wasm" || same=no
  cmp "$threads" "$here/prover/sh20_circuit_threads.wasm" || same=no
  if [ "$same" != yes ]; then
    {
      echo "FAIL: the committed modules are not what this source builds ($(rustc --version))."
      echo "built:"
      shasum -a 256 "$single" "$threads" | sed "s#  $target/#  #"
      echo "committed:"
      shasum -a 256 "$here/prover/sh20_circuit.wasm" "$here/prover/sh20_circuit_threads.wasm" | sed "s#  $here/#  #"
      echo "A change to circuit/ changes the modules: run tools/prover.sh and commit vault/prover/*.wasm with it."
    } >&2
    exit 1
  fi
  echo "OK: the committed modules are what this toolchain builds ($(rustc --version))"
else
  cp "$single" "$here/prover/sh20_circuit.wasm"
  cp "$threads" "$here/prover/sh20_circuit_threads.wasm"
fi
shasum -a 256 "$here/prover/sh20_circuit.wasm" "$here/prover/sh20_circuit_threads.wasm" | sed "s#  $here/#  #"
