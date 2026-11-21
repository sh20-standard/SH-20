#!/usr/bin/env bash
# Development and CI only: fetches Bitcoin Core, checks it against the SHA-256 pinned below, and
# prints the path of its bitcoind. dev/regtest.js runs it on a regtest chain of its own.
#
#   vault/tools/bitcoind.sh            # prints .../bitcoin-<version>/bin/bitcoind
#
# The archive is kept in $SH20_BITCOIN_CACHE (default: ~/.cache/sh20-bitcoin) and checked on every
# run. The hashes are those of the release's SHA256SUMS (bitcoincore.org/bin/bitcoin-core-<version>/),
# which the Guix builders sign in SHA256SUMS.asc: to change the version, check that signature
# (gpg --verify SHA256SUMS.asc SHA256SUMS) before copying the new hashes here.
set -euo pipefail

VERSION=31.3
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ARCH=x86_64-linux-gnu; SUM=864a06a5106e437a1b87b3c048cd7f14ee6140555262aae9d0e9e3b7bea87568 ;;
  Linux-aarch64) ARCH=aarch64-linux-gnu; SUM=c7ea41ae5d4bd103306ca0d326f017b11bc35686d697c1d1d237a7041dba2021 ;;
  Darwin-arm64) ARCH=arm64-apple-darwin; SUM=f932dcdf49c8ec7620551c297ea273c2a67da696c9a06743905fe0372780b7a0 ;;
  Darwin-x86_64) ARCH=x86_64-apple-darwin; SUM=8b1a32bc5aa1cf37ee12ee5417b367fd34c420aadcf934994aa96396adab6187 ;;
  *) echo "no pinned Bitcoin Core $VERSION for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

CACHE="${SH20_BITCOIN_CACHE:-$HOME/.cache/sh20-bitcoin}"
FILE="bitcoin-$VERSION-$ARCH.tar.gz"
mkdir -p "$CACHE"
if [ ! -f "$CACHE/$FILE" ]; then
  curl -fsSL --proto '=https' -o "$CACHE/$FILE.part" "https://bitcoincore.org/bin/bitcoin-core-$VERSION/$FILE"
  mv "$CACHE/$FILE.part" "$CACHE/$FILE"
fi
if command -v sha256sum > /dev/null; then GOT=$(sha256sum "$CACHE/$FILE" | cut -d' ' -f1); else GOT=$(shasum -a 256 "$CACHE/$FILE" | cut -d' ' -f1); fi
if [ "$GOT" != "$SUM" ]; then
  rm -f "$CACHE/$FILE"
  echo "$FILE: SHA-256 $GOT, expected $SUM (removed)" >&2
  exit 1
fi
if [ ! -x "$CACHE/bitcoin-$VERSION/bin/bitcoind" ]; then
  tar -xzf "$CACHE/$FILE" -C "$CACHE" "bitcoin-$VERSION/bin/bitcoind"
fi
echo "$CACHE/bitcoin-$VERSION/bin/bitcoind"
