# sh20-indexer

Reference indexer for **SH-20**, an open standard for fungible shielded tokens on Bitcoin L1:
anyone deploys a 4-character ticker, anyone mints it for a public price, and transfers hide the
amount, the sender, the recipient and the ticker. All tickers share one note tree.

**Status: draft v0.3, not activated anywhere, not audited.** The default verifier rejects every proof,
so proof-less envelopes (genesis DEPLOY, MINT, TAKE, CLAIM) are fully checked and spends (TRANSFER, BURN,
LIST, later DEPLOYs) are rejected. Pass `plonkVerifier` (`src/adapters/plonk.js`) to check spends with
the pinned verifier of [`circuit/`](../circuit), built as a WebAssembly module with no imports.

- Wire format and rules: [`docs/SPEC-WIRE.md`](../docs/SPEC-WIRE.md)
- Test vectors for a second implementation: [`vectors/v0.3.json`](./vectors/v0.3.json), and [`vectors/plonk-v0.3.json`](./vectors/plonk-v0.3.json) for its PLONK verifier (real proofs)

## Run

Node 20 or newer, no dependencies.

```sh
(cd ../circuit && ./build-wasm.sh)   # optional: the 4 tests of real proofs use this build, else the copy in ../vault/prover/
npm test                  # 83 tests: primitives, codec, carriers, every rule, reorgs, two-indexer agreement, follower, block file, API, real proofs
npm run vectors           # regenerates vectors/v0.3.json and vectors/plonk-v0.3.json (deterministic)
node bin/replay.js <dir> --deploy-burn D   # replays a folder of `bitcoin-cli getblock <hash> 3` JSON files
node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser U --rpcpass P --activation A --deploy-burn D   # live, own node
node bin/follow.js --esplora https://mempool.space/signet/api --activation A --deploy-burn D    # live, Esplora
node bin/follow.js … --data ~/sh20-js        # keeps the blocks read: a restart applies them again from disk
```

The live follower serves a read-only JSON API for wallets: see [`docs/API.md`](../docs/API.md).

## Layout

| Path | What |
| --- | --- |
| `src/poseidon.js` | Poseidon over BN254 for 2 to 5 inputs, circomlib-compatible; constants generated in place with the Grain LFSR |
| `src/schnorr.js` | BIP340 sign and verify (checked against the BIP340 vectors) |
| `src/codec.js` | strict envelope parser and serialiser |
| `src/carrier.js` | finds the envelope in a transaction (OP_RETURN or tapscript witness) |
| `src/tree.js` | the shared note tree (depth 32) with snapshots and paths |
| `src/notes.js` | the note leaf formula |
| `src/indexer.js` | the state machine: tickers, mints, team unlocks, spends, listings, digest, rollback |
| `src/events.js` | the byte encoding of accepted events, hashed into the digest (`SPEC-WIRE.md` §6) |
| `src/adapters/bitcoind.js` | Bitcoin Core `getblock 3` JSON → indexer blocks |
| `src/adapters/plonk.js` | the pinned spend verifier (WebAssembly build of `circuit/`), keyed by the pinned digest |
| `src/follower.js` | live chain follower (Bitcoin Core RPC or Esplora) with reorg handling |
| `src/blockfile.js` | the blocks a follower read, kept on disk so that a restart applies them again (`follow.js --data`) |
| `src/api.js` | read-only HTTP API (`docs/API.md`) |
| `src/mirror.js`, `src/mirror-read.js` | the static mirror of the API (`docs/API.md`, "The static mirror"): building it from a running indexer, and answering each route from its files (no dependency: the explorer inlines it) |
| `bin/` | `follow.js`, `replay.js`, `vectors.js`; `mirror.js` (the mirror of one indexer) and `mirror-site.js` (both, as `pages.yml` runs it); `fuzz.js`, `api-diff.js` and `mirror-check.js` against `indexer-rs`, on chains from `chain-gen.js` served by `esplora-fake.js` |

## What is still missing

1. An audit of the spend circuit and its verifier, then the freeze of the verifying-key digest. Until then `bin/replay.js` and `bin/follow.js` check spends only with `--verifier <wasm>`.
2. The browser vault: keys on the device, proofs in the browser, PSBTs signed by Xverse / UniSat / Leather.
3. A second, independent indexer that matches `vectors/v0.3.json`.
4. Freezing the profile (activation height, D).

## License

MIT, see [`LICENSE`](../LICENSE).
