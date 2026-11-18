#!/usr/bin/env bash
# Assembles the phone test page in web/dist/: the page, both WebAssembly builds and the proving key.
# The folder is static and self-contained; serve it with `node serve.mjs` or from any static host.
set -euo pipefail
cd "$(dirname "$0")"
../build-wasm.sh
rm -rf dist
mkdir -p dist
cp index.html app.js host.js prover-worker.js thread-worker.js sw.js dist/
cp ../target/wasm32-unknown-unknown/release/sh20_circuit.wasm dist/sh20_circuit.wasm
cp ../target/wasm32-wasip1-threads/release/sh20_circuit.wasm dist/sh20_circuit_threads.wasm
cp ../artifacts/spend.pk dist/spend.pk
du -sh dist
