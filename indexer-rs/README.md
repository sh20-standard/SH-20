# indexer-rs — a second SH-20 indexer, written blind

A Rust indexer for SH-20 draft v0.3, written from [`docs/SPEC-WIRE.md`](../docs/SPEC-WIRE.md) alone, to check that
the spec is enough to reach the reference indexer's results.

**Clean room.** Read: `docs/SPEC-WIRE.md`, `docs/DESIGN.md`, `indexer/vectors/v0.3.json`, the root `CLAUDE.md`, and
`docs/SPEC-GAPS.md` (written here; its resolution table is the maintainer's).
Never opened: `indexer/` apart from the vectors file, `explorer/`, `vault/`, `circuit/`, `docs/AUDIT.md`. No code is shared
with the reference: Poseidon is [`light-poseidon`](https://crates.io/crates/light-poseidon) (circom parameters, over
`ark-bn254`), BIP340 is the [`secp256k1`](https://crates.io/crates/secp256k1) crate (libsecp256k1), SHA-256 is `sha2`.

**Result.** It reproduces every value of `indexer/vectors/v0.3.json`: the 13 blocks of the scenario, the `bodyHash`
of every spend envelope, the nine inputs of every verifier call, the 23 carrier cases and the CLAIM.
[`docs/SPEC-GAPS.md`](../docs/SPEC-GAPS.md) lists the 28 points the first draft of the spec left open and the six a
recheck still found, all settled in the spec since, and what the vectors still do not pin.

```sh
cd indexer-rs
cargo test --release      # 64 tests
cargo run --release -- replay <folder of `bitcoin-cli getblock <hash> 3` JSON files> [options]
```

## replay

```
sh20-indexer-rs replay <folder> [--activation <A>] [--deploy-burn <D>] [--window <W>] [--min-depth <K_min>]
                                [--maturity <N>] [--verifier reject|test] [--json]
```

Reads every `.json` file of the folder (one block each, bare or inside a JSON-RPC `result`), orders them by the
height they contain, and prints one line per block from the activation block on:

```
<height> <digest>
```

`--json` prints one object per block instead, with the field names of the vectors (`height`, `root`, `events`,
`eventsH`, `digest`) and the refused envelopes (`rejected`). The profile used goes to standard error. Defaults:
`A` = the lowest height in the folder, `D = 0`, `W = 100`, `K_min = 1`, `N = 6`. Heights must be consecutive from
`A`; blocks below `A` are not read.

**Use `getblock <hash> 3`.** A DEPLOY must reveal a commit confirmed at least `N` blocks earlier (SPEC-WIRE §5), so
the indexer needs the height of the block that confirmed the output spent by input 0 of the reveal. Verbosity 3
gives it as `vin[].prevout.height`; verbosity 2 does not. Files of verbosity 2 replay until the first DEPLOY
revealed in a witness: there the replay stops with an error that names the block and the transaction, and prints
no digest for that block. It never guesses, and never refuses the DEPLOY for lack of a height. Esplora gives the
same height as the spent transaction's `status.block_height`; this command reads `getblock` files only.

`--verifier reject` (default) refuses every spend. `--verifier test` accepts the one proof the vectors use
(`"valid-proof"` padded with zeros to 480 bytes). The PLONK verifier of `circuit/` is not wired in: it implements
the `SpendVerifier` trait when someone adds it.

To compare two indexers on a chain, run both over the same folder with the same profile and verifier, and compare
the digests. The first block where they differ holds the event to look at; `--json` shows its `eventsH`.

## Layout

| File | What |
| --- | --- |
| `src/field.rs` | `Fr`, Poseidon `H`, `TAG_LEAF`, the note leaf, `bodyHash` (§1, §2) |
| `src/tree.rs` | the shared tree of depth 32, kept as a frontier (§2) |
| `src/chain.rs` | transactions, script parsing, the OP_RETURN and witness carriers (§3) |
| `src/envelope.rs` | strict codec of the 7 envelopes and the spend section (§4) |
| `src/verifier.rs` | `SpendVerifier`: the nine public inputs and a proof; `RejectAll`, `TestVerifier` |
| `src/state.rs` | acceptance rules, turnstile, listings, block processing, digest, undo log (§5, §6) |
| `src/events.rs` | byte encoding of the events inside the digest (§6) |
| `src/json.rs` | blocks from `getblock <hash> 3` (or 2) and from the vectors |
| `src/main.rs` | the `replay` command |

## Tests

| File | What |
| --- | --- |
| `tests/vectors.rs` | replays `v0.3.json`: primitives; per block the root, the events, `eventsH`, the digest; the refusals; every verifier call and its nine inputs; the final state; every `bodyHash`; the 23 carrier cases, alone and through the rules; the CLAIM message and signature; `digest_{A−1}` |
| `tests/codec.rs` | every envelope of the vectors and of the §4 table, byte for byte; the note leaf; what the decoder refuses |
| `tests/rules.rs` | what the vectors do not cover: carriers at their edges, mint window and payment, DEPLOY conditions, anchors, nullifiers, CANCELLED, CLOSED, CLAIM, team unlocks, reorgs |
| `tests/replay_cli.rs` | the `replay` command over the scenario written as `getblock` files |

`tests/rules.rs` states this implementation's reading of the spec. It is not evidence of agreement with the
reference: only the vectors and a run of both indexers over the same chain are.

## Limits

- No PLONK verification here (interface only).
- No chain follower and no HTTP API: this indexer replays blocks it is given. Reorgs are handled by
  `Indexer::rollback_to`, with 288 blocks of undo by default.
- The state lives in memory.
