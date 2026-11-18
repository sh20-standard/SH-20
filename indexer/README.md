# sh20-indexer

Reference indexer for **SH-20**, an open standard for fungible shielded tokens on Bitcoin L1:
anyone deploys a 4-character ticker, anyone mints it for a public price, and transfers hide the
amount, the sender, the recipient and the ticker. All tickers share one note tree.

**Status: draft v0.2, not activated anywhere, not audited.** The default verifier rejects every proof,
so proof-less envelopes (genesis DEPLOY, MINT, TAKE, CLAIM) are fully checked and spends (TRANSFER, BURN,
LIST, later DEPLOYs) are rejected. Pass `plonkVerifier` (`src/adapters/plonk.js`) to check spends with
the pinned verifier of [`circuit/`](../circuit), built as a WebAssembly module with no imports.

- Wire format and rules: [`docs/SPEC-WIRE.md`](../docs/SPEC-WIRE.md)
- Test vectors for a second implementation: [`vectors/v0.2.json`](./vectors/v0.2.json)

## Run

Node 20 or newer, no dependencies.

```sh
(cd ../circuit && ./build-wasm.sh)   # optional: the spend verifier; the 4 tests that need it are skipped without it
npm test                  # 47 tests: primitives, codec, carriers, every rule, reorgs, two-indexer agreement, follower, API, real proofs
npm run vectors           # regenerates vectors/v0.2.json (deterministic)
node bin/replay.js <dir>  # replays a folder of `bitcoin-cli getblock <hash> 2` JSON files
node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser U --rpcpass P --activation H   # live, own node
node bin/follow.js --esplora https://mempool.space/signet/api --activation H             # live, Esplora
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
| `src/adapters/bitcoind.js` | Bitcoin Core `getblock 2` JSON → indexer blocks |
| `src/adapters/plonk.js` | the pinned spend verifier (WebAssembly build of `circuit/`), keyed by the pinned digest |
| `src/follower.js` | live chain follower (Bitcoin Core RPC or Esplora) with reorg handling |
| `src/api.js` | read-only HTTP API (`docs/API.md`) |
| `bin/` | `follow.js`, `replay.js`, `vectors.js` |

## What is still missing

1. An audit of the spend circuit and its verifier, then the freeze of the verifying-key digest. Until then `bin/replay.js` and `bin/follow.js` check spends only with `--verifier <wasm>`.
2. The browser vault: keys on the device, proofs in the browser, PSBTs signed by Xverse / UniSat / Leather.
3. A second, independent indexer that matches `vectors/v0.2.json`.
4. Freezing the profile (activation height, D) and the event encoding of the digest.

## License

MIT, see [`LICENSE`](../LICENSE).
