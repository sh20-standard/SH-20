#!/bin/sh
# The rustc wrapper of tools/prover.sh: with it the two modules are the same bytes on every machine.
#
# cargo gives every crate an id (`-C metadata`) and rustc mixes it into the hash that ends each
# symbol. For a crate built for the host (a proc-macro, a build script) the id covers the whole output
# of `rustc -vV`, its `host:` line included. For a crate built for WebAssembly cargo leaves that line
# out, but hashes in the ids of the crate's dependencies, proc-macros among them. So ark-ff, through
# ark-ff-macros, and every crate above it get other symbol hashes on macOS than on Linux, and the
# functions land in another order: the same code, other bytes. Measured on 2026-11-20 with rustc and
# cargo 1.95.0: 227 of the 350 named functions of the one-thread module carried another hash, and
# setting the host line alone made a macOS arm64 laptop give the files of a Linux x86_64 runner.
#
# cargo runs `<wrapper> <rustc> -vV` once to learn that output. This file answers it with the host of
# the reference build, x86_64-unknown-linux-gnu. There it changes nothing: a plain build on such a
# machine (a CI runner) gives the committed bytes without this file. Every other call goes to rustc
# untouched, and host crates are still built for the real host: cargo passes them no --target.
rustc="$1"
shift
if [ "$#" -eq 1 ] && [ "$1" = "-vV" ]; then
  "$rustc" -vV | sed 's/^host: .*/host: x86_64-unknown-linux-gnu/'
else
  exec "$rustc" "$@"
fi
