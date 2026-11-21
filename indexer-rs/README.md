# indexer-rs — a second SH-20 indexer, written blind

A Rust indexer for SH-20 draft v0.3, written from [`docs/SPEC-WIRE.md`](../docs/SPEC-WIRE.md) alone, to check that
the spec is enough to reach the reference indexer's results.

**Clean room.** Read: `docs/SPEC-WIRE.md`, `docs/DESIGN.md`, `indexer/vectors/v0.3.json`, the root `CLAUDE.md`,
`docs/API.md` (for `follow`), and `docs/SPEC-GAPS.md` (written here; its resolution table is the maintainer's).
Never opened: `indexer/` apart from the vectors file, `explorer/`, `vault/`, `circuit/`, `docs/AUDIT.md`. No code is shared
with the reference: Poseidon is [`light-poseidon`](https://crates.io/crates/light-poseidon) (circom parameters, over
`ark-bn254`), BIP340 is the [`secp256k1`](https://crates.io/crates/secp256k1) crate (libsecp256k1), SHA-256 is `sha2`.

**Result.** It reproduces every value of `indexer/vectors/v0.3.json`: the 17 blocks of the scenario and its reorg, the `bodyHash`
of every spend envelope, the nine inputs of every verifier call, the 32 carrier cases and the CLAIM.
[`docs/SPEC-GAPS.md`](../docs/SPEC-GAPS.md) lists the 28 points the first draft of the spec left open and the six a
recheck still found, all settled in the spec since, and what the vectors still do not pin.

It also follows a chain and serves the read-only HTTP API of [`docs/API.md`](../docs/API.md), so that it can run
beside the reference indexer and be compared with it block by block (`follow`, below).

```sh
cd indexer-rs
cargo test --release      # 101 tests
cargo run --release -- replay <folder of `bitcoin-cli getblock <hash> 3` JSON files> [options]
cargo run --release -- follow --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A --deploy-burn D
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
`eventsH`, `digest`) and the refused envelopes (`rejected`, with `envelope`, the index of the envelope, when the
transaction is a batch). The profile used goes to standard error. Defaults:
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

## follow

```
sh20-indexer-rs follow (--rpc <url> [--rpcuser <user> --rpcpass <password> | --rpccookie <file>] | --esplora <url>)
                       --activation <A> --deploy-burn <D> [--window <W>] [--min-depth <K_min>] [--maturity <N>]
                       [--verifier reject|test] [--listen <address>] [--data <folder>] [--poll <seconds>]
                       [--network <name>]
```

Follows the best chain from the activation block and serves the API of `docs/API.md` on `--listen`
(`127.0.0.1:8621` by default: local only; give `0.0.0.0:<port>` to open it).

- **Sources.** Bitcoin Core's RPC (`getblockhash`, `getblock <hash> 3`; the node must keep its blocks and their undo
  data, so not a pruned one), or an Esplora API (`https://mempool.space/signet/api`, or one's own). Esplora gives a
  block in pages of 25 transactions, and the height of the commit a DEPLOY reveals as the status of the transaction
  it spends: one more request for each DEPLOY, none for anything else. A public Esplora limits requests: the first
  run is slow there, and `--data` keeps it from happening twice.
- **Reorgs.** When the best chain no longer goes through the indexer's tip, it undoes its blocks one by one down to
  the last one the source still has (one hash asked for each), then applies the new ones. 288 blocks can be undone.
  A deeper reorg stops the command with an error, as `docs/API.md` says: it does not serve a state it cannot stand
  behind. Start it again to index from `A` (after deleting the block file, if there is one).
- **A source that fails** (node down or still starting, HTTP 429 or 5xx, a timeout) is asked again after 1 second,
  then 2, up to a minute, for as long as it takes. The state is kept and the API goes on answering from it.
  Wrong RPC credentials and a pruned block end the command instead: asking again would not help.
- **A restart.** The state lives in memory. With `--data <folder>`, the indexer appends what it read of each block to
  `<folder>/blocks.jsonl` (the transactions that carry an envelope or spend an output of one; a rollback is a line
  too) and applies that file again when it starts: no request to the source for a block it had, and a reorg that
  happened meanwhile is undone as any other. The file holds chain data only, no state, and belongs to one activation
  height. Without `--data`, a restart reads the chain again from `A`.
- **A missing commit height** (a node that gives no `prevout.height`) stops the command at the first DEPLOY
  revealed, with the block and the transaction named (SPEC-WIRE §5: stop, do not guess).
- **Proofs.** As for `replay`: `--verifier reject` refuses every spend and `test` is the vectors' rule. There is no
  PLONK verifier here yet. See "Beside the reference indexer" for what that means on a chain with real spends.

Standard error gets the profile, `listening on http://<address>`, a line per block (`block <height> <digest>`; one
every few seconds while catching up), `reorg: block <height> undone`, and `source: …; trying again`.
The password is never printed. `--rpccookie` reads the node's `.cookie` file, which keeps it off the command line.

### The API

Every route of `docs/API.md`, GET only, JSON, `Access-Control-Allow-Origin: *`, one request per connection:

`/status` `/tokens` `/token/:ticker` `/notes?from=0&limit=1000` `/path/:pos` `/roots?from=H` `/nullifier/:hex`
`/nullifiers?from=H` `/listings?state=ACTIVE` `/listing/:txid` `/digest/:height` `/blocks?before=H&limit=20`
`/tx/:txid`, and `/block/:height`, which `docs/API.md` does not list (one block, as an entry of `/blocks`).

Encodings are those of `docs/API.md`: amounts as decimal strings; field elements, hashes and nullifiers as
64-character big-endian hex; txids in display order. Where it does not say what a field holds (an event or a
listing as JSON, `genesis` and `network` in `/status`, a block's `events`), this indexer had to choose:
`docs/SPEC-GAPS.md` ("The HTTP API") lists the sixteen choices. Until the reference is checked against that list,
compare the two indexers on the values that are normative, which both must give alike:

| Route | Compare |
| --- | --- |
| `/status` | `height`, `digest`, `root`, `leaves` |
| `/digest/:height` | `digest`: once two indexers differ at a height, they differ at every height after |
| `/block/:height` | `digest`, `root`, `leaves`; here also `eventsH`, the bytes of SPEC-WIRE §6 behind the digest |
| `/roots`, `/nullifiers`, `/notes` | every `root`, every `nullifier`, every `leaf` with its `pos` |
| `/listings`, `/tokens` | the state of every listing; `mints`, `burned` and `pool` of every token |

Refusal reasons are informative and worded differently by each indexer: compare which transactions are refused,
never the text.

### Beside the reference indexer

Both read the same node (or the same Esplora), each on its own port, with the same profile:

```sh
# the reference, as docs/API.md gives it
cd indexer && node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A

# this one
cd indexer-rs && cargo run --release -- follow --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS \
    --activation A --deploy-burn D --listen 127.0.0.1:8621 --data ./data
```

1. **The same profile.** Read the reference's `/status` (`activationHeight`, `deployBurn`, `anchorWindow`,
   `deployMaturity`) and give this one the same `--activation`, `--deploy-burn`, `--window` and `--maturity`
   (and `--min-depth` if the reference does not use `K_min = 1`). `D`, `W`, `K_min` and `N` are in the GENESIS
   record: with a different one, the digests differ from block `A` on. `A` is in no digest: check it by eye.
2. **The same verifier.** This indexer refuses every spend. It agrees with a reference started without
   `--verifier <wasm>`, and with one started with it up to the first valid proof on the chain (a TRANSFER, a BURN,
   a LIST, or a DEPLOY, which burns `D`): from that block on the reference accepts what this one refuses and the
   digests part for good. Mints and proof-less envelopes (MINT, TAKE, CLAIM) are compared in full either way.
   A PLONK verifier behind the `SpendVerifier` trait is what a signet with real spends needs.
3. **Compare.** With `REF` and `RS` the two addresses:

   ```sh
   H=$(curl -s $RS/status | jq .height)                  # wait until both are at the tip
   curl -s $REF/digest/$H | jq -r .digest
   curl -s $RS/digest/$H  | jq -r .digest                # the same line twice, or not
   ```

   If they differ, the first height where `/digest/:height` differs holds the cause (digests chain, so a bisection
   between `A` and `H` finds it in a few requests). There, `/block/:height` gives `root`, `leaves` and `eventsH` on
   this side, and `/tx/:txid` what each transaction of the block did.

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
| `src/follow.rs` | the follower: one block forward, one back in a reorg, over any `Source` |
| `src/sources.rs` | the two sources: Bitcoin Core's JSON-RPC and Esplora (HTTP client: `ureq`, with `rustls`) |
| `src/blocks.rs` | the block file of `--data` |
| `src/api.rs` | what the API serves: every leaf, nullifier, root and digest by block, and the routes |
| `src/server.rs` | the HTTP server (standard library only): GET, JSON, CORS, read-only, with a deadline for each connection |
| `src/main.rs` | the `replay` and `follow` commands |

## Tests

| File | What |
| --- | --- |
| `tests/vectors.rs` | replays `v0.3.json`: primitives; per block the root, the events, `eventsH`, the digest; the refusals (with the index of the envelope in a batch); every verifier call and its nine inputs; the final state; the `reorg` part (roll back, apply, compare); every `bodyHash`; the carrier cases, alone and through the rules; the CLAIM message and signature; `digest_{A−1}` |
| `tests/codec.rs` | every envelope of the vectors and of the §4 table, byte for byte; the note leaf; what the decoder refuses |
| `tests/rules.rs` | what the vectors do not cover: carriers at their edges, batches at their edges, mint window and payment, DEPLOY conditions and maturity, the `payScript` rule, anchors, nullifiers, CANCELLED, CLOSED, CLAIM, team unlocks, reorgs |
| `tests/replay_cli.rs` | the `replay` command over the scenario written as `getblock` files |
| `tests/follow.rs` | the follower over a chain in memory: the scenario block after block, among transactions that carry nothing; the vectors' reorg and back; a shorter chain; a reorg of the activation block; one deeper than the undo history; a failure at every call to the source; a missing commit height; restarts from the block file, and a damaged file |
| `tests/api.rs` | every route over the scenario: roots, digests, `eventsH`, refusals, nullifiers, listings and token counters against the vectors; public leaves recomputed from their openings; Merkle paths folded up to the root; batches in `/tx`; pages, bad parameters, 404s |
| `tests/sources.rs` | over real sockets on local ports: the scenario served as Bitcoin Core's RPC (credentials, a busy node, no `prevout.height`) and as an Esplora API (pages, commit heights, 429), and the `follow` command from its first block through a reorg, a stop and a restart with the node down |

`tests/rules.rs` states this implementation's reading of the spec. It is not evidence of agreement with the
reference: only the vectors and a run of both indexers over the same chain are.

In `tests/follow.rs`, `tests/api.rs` and `tests/sources.rs` the vectors say what the digests, roots and leaves must
be; the Core and Esplora answers are written here from those services' documented formats, and `follow --esplora`
was run once against a public signet API (2026-11-21, five blocks to the tip). No test runs against the reference
indexer's API: where `docs/API.md` is silent, the shape of an answer is this indexer's choice.

## Limits

- No PLONK verification here (interface only): on a chain with valid spends, `follow` and the reference part at
  the first one.
- The state lives in memory; `--data` keeps the blocks, not the state, so a restart applies them again.
- `/nullifiers`, `/roots` and `/listings` return everything at once, as `docs/API.md` describes them.
- One request per connection, 64 at a time and 8 for one remote address; a connection has 10 seconds in all to
  send its request and 60 to take the answer. Put a reverse proxy in front for a public address or for TLS.
