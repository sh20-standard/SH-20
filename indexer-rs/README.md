# indexer-rs — a second SH-20 indexer, written blind

A Rust indexer for SH-20 draft v0.3, written from [`docs/SPEC-WIRE.md`](../docs/SPEC-WIRE.md) alone, to check that
the spec is enough to reach the reference indexer's results.

**Clean room.** Read: `docs/SPEC-WIRE.md`, `docs/DESIGN.md`, the two vectors files of `indexer/vectors/`, the root
`CLAUDE.md`, `docs/API.md` (for `follow`), `docs/PLAN.md`, and `docs/SPEC-GAPS.md` (written here; its resolution table is
the maintainer's). Never opened: `indexer/` apart from the vectors, `explorer/`, `vault/`, `circuit/src`, `docs/AUDIT.md`.
No code is shared with the reference indexer: Poseidon is [`light-poseidon`](https://crates.io/crates/light-poseidon)
(circom parameters, over `ark-bn254`), BIP340 is the [`secp256k1`](https://crates.io/crates/secp256k1) crate
(libsecp256k1), SHA-256 is `sha2`.

**One exception, on purpose: the proof verifier.** A second PLONK verifier written here would be new
soundness-critical code that no audit covers. So `--verifier plonk-bn254-hermez` calls the verifier of `circuit/`, the
one the reference runs as WebAssembly, as a library (`sh20-circuit`, a path dependency without its default features),
through the interface its README gives ("The verifier as a library") and no other reading of that crate. What stays
independent is everything around it: the nine public inputs come from this indexer's own reading of the chain, and
the key is checked against the digest `docs/SPEC-WIRE.md` §4 pins. A bug in the verifier itself is common to both
indexers and no comparison of the two will show it.

**Result.** It reproduces every value of `indexer/vectors/v0.3.json`: the 17 blocks of the scenario and its reorg, the `bodyHash`
of every spend envelope, the nine inputs of every verifier call, the 32 carrier cases and the CLAIM. And every value of
`indexer/vectors/plonk-v0.3.json`, a chain with real proofs: the seven calls to the verifier with their inputs and
answers (a TRANSFER, a BURN, a LIST and a DEPLOY that burns accepted; a TRANSFER, a LIST and a DEPLOY with one bit of
the proof flipped refused), and the root, `eventsH` and digest of its seven blocks.
[`docs/SPEC-GAPS.md`](../docs/SPEC-GAPS.md) lists the 28 points the first draft of the spec left open and the six a
recheck still found, all settled in the spec since, and what the vectors still do not pin.

It also follows a chain and serves the read-only HTTP API of [`docs/API.md`](../docs/API.md), so that it can run
beside the reference indexer and be compared with it block by block (`follow`, below).

```sh
cd indexer-rs
cargo test --release      # 115 tests
cargo run --release -- replay <folder of `bitcoin-cli getblock <hash> 3` JSON files> --deploy-burn D [options]
cargo run --release -- follow --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A --deploy-burn D
```

## replay

```
sh20-indexer-rs replay <folder> --deploy-burn <D> [--activation <A>] [--window <W>] [--min-depth <K_min>]
                                [--maturity <N>] [--verifier <name>] [--json]
```

Reads every `.json` file of the folder (one block each, bare or inside a JSON-RPC `result`), orders them by the
height they contain, and prints one line per block from the activation block on:

```
<height> <digest>
```

`--json` prints one object per block instead, with the field names of the vectors (`height`, `root`, `events`,
`eventsH`, `digest`) and the refused envelopes (`rejected`, with `envelope`, the index of the envelope, when the
transaction is a batch). The profile used goes to standard error. Defaults:
`A` = the lowest height in the folder, `W = 100`, `K_min = 1`, `N = 6`. `D` has none, here as for `follow`: the spec
gives it no value, and a replay under another `D` gives other digests from block `A` on. Heights must be consecutive
from `A`; blocks below `A` are not read, and a folder that starts after `A` is refused.

The command line is read the way the reference's `replay.js` and `follow.js` read theirs, so that one line gives two
replays or none: a number is decimal digits and nothing else, in its range (`A`, `W`, `K_min` and `N` below 2^32, `D`
below 2^64; no sign, space, point or exponent), an option given twice or without its value is refused, and so is a
second folder. The same holds for `follow`.

**Use `getblock <hash> 3`.** A DEPLOY must reveal a commit confirmed at least `N` blocks earlier (SPEC-WIRE §5), so
the indexer needs the height of the block that confirmed the output spent by input 0 of the reveal. Verbosity 3
gives it as `vin[].prevout.height`; verbosity 2 does not. Files of verbosity 2 replay until the first DEPLOY
revealed in a witness: there the replay stops with an error that names the block and the transaction, and prints
no digest for that block. It never guesses, and never refuses the DEPLOY for lack of a height. Esplora gives the
same height as the spent transaction's `status.block_height`; this command reads `getblock` files only.

`--verifier` names what checks the proof of a spend:

| Name | What it accepts |
| --- | --- |
| `plonk-bn254-hermez` | a valid PLONK proof under the pinned verifying key (SPEC-WIRE §4): the verifier of `circuit/`, with `circuit/artifacts/spend.vk` built into the binary and refused unless its digest is the spec's. The one for a real network |
| `reject-all` (default; `reject` is the same) | nothing: every spend is refused |
| `test` | the one proof `v0.3.json` uses (`"valid-proof"` padded with zeros to 480 bytes), whatever the inputs. For the vectors and the fuzzer only: `follow` takes it with `--network regtest` and stops with any other network, or with none named (whoever sends those bytes spends notes that do not exist) |

The default stays `reject-all`, as in the reference, whose default it is too: two indexers started without the option
agree. Give both the real verifier on a network (`--verifier <wasm>` for the reference).

To compare two indexers on a chain, run both over the same folder with the same profile and verifier, and compare
the digests. The first block where they differ holds the event to look at; `--json` shows its `eventsH`.

## follow

```
sh20-indexer-rs follow (--rpc <url> [--rpcuser <user> --rpcpass <password> | --rpccookie <file>] | --esplora <url>)
                       --activation <A> --deploy-burn <D> [--window <W>] [--min-depth <K_min>] [--maturity <N>]
                       [--verifier <name>] [--listen <address>] [--data <folder>] [--poll <seconds>]
                       [--network <name>]
```

Follows the best chain from the activation block and serves the API of `docs/API.md` on `--listen`
(`127.0.0.1:8621` by default: local only; give `0.0.0.0:<port>` to open it).

- **Sources.** Bitcoin Core's RPC (`getblockhash`, `getblock <hash> 3`; the node must keep its blocks and their undo
  data, so not a pruned one), or an Esplora API (`https://mempool.space/signet/api`, or one's own). Esplora gives a
  block in pages of 25 transactions, and the height of the commit a DEPLOY reveals as the status of the transaction
  it spends: one more request for each DEPLOY, none for anything else. A block of more than one page is read from
  `GET /block/:hash/raw` instead, Bitcoin's serialized block in one request: a mainnet block holds thousands of
  transactions, 160 pages for 4,000. The bytes are checked against themselves (the header hashes to the hash asked
  for, the txids to its merkle root, the witnesses to the commitment in the coinbase, BIP 141), which no page of JSON
  allows; bytes that fail are asked for again, never replaced by pages. A server without the route (404) still
  serves the pages. A public Esplora limits requests: the first
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
- **Proofs.** As for `replay`: `--verifier plonk-bn254-hermez` on a network; the default refuses every spend.
  `/status` gives the name (`verifier`), the same one the reference gives for the same verifier.

Standard error gets the profile, `listening on http://<address>`, a line per block (`block <height> <digest>`; one
every few seconds while catching up), `reorg: block <height> undone`, and `source: …; trying again`.
The password is never printed. `--rpccookie` reads the node's `.cookie` file, which keeps it off the command line.

### The API

Every route of `docs/API.md`, GET only, JSON, `Access-Control-Allow-Origin: *`, one request per connection:

`/status` `/tokens` `/token/:ticker` `/notes?from=0&limit=1000` `/path/:pos` `/roots?from=H` `/nullifier/:hex`
`/nullifiers?from=H` `/listings?state=ACTIVE` `/listing/:txid` `/digest/:height` `/blocks?before=H&limit=20`
`/tx/:txid`, and `/block/:height`, which `docs/API.md` does not list (one block, as an entry of `/blocks`).

Encodings and shapes are those of `docs/API.md`: amounts as decimal strings; field elements, hashes and nullifiers
as 64-character big-endian hex; txids in display order; an event under the names of SPEC-WIRE §6; a listing as
`{ listTxid, ticker, amount, price, payScript, lock, lockKey, state, height }` with `lock` as `txid:vout`, `takeTxid`
once sold or cancelled and `closedBy` once closed. The document first left sixteen of these open (`docs/SPEC-GAPS.md`,
"The HTTP API"); they are settled there now, and `indexer/bin/api-diff.js` has both indexers follow one random chain,
through a reorg, and compares every route field by field:

```sh
cargo build --release
node ../indexer/bin/api-diff.js --rs target/release/sh20-indexer-rs --reorg 3,2
```

Only `implementation` and the free text of errors and refusal reasons may differ. On a live network, these are the
values to watch, which two indexers must give alike:

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
cd indexer && node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A --deploy-burn D \
    --verifier ../vault/prover/sh20_circuit.wasm

# this one
cd indexer-rs && cargo run --release -- follow --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS \
    --activation A --deploy-burn D --verifier plonk-bn254-hermez --listen 127.0.0.1:8621 --data ./data
```

1. **The same profile.** Read the reference's `/status` (`activationHeight`, `deployBurn`, `anchorWindow`,
   `deployMaturity`) and give this one the same `--activation`, `--deploy-burn`, `--window` and `--maturity`
   (and `--min-depth` if the reference does not use `K_min = 1`). `D`, `W`, `K_min` and `N` are in the GENESIS
   record: with a different one, the digests differ from block `A` on. `A` is in no digest: check it by eye.
2. **The same verifier.** Both `/status` must name the same one: `plonk-bn254-hermez` on a network (`--verifier
   plonk-bn254-hermez` here, `--verifier <wasm>` for the reference), or `reject-all` on both. An indexer that refuses
   every spend agrees with one that checks proofs up to the first valid proof on the chain (a TRANSFER, a BURN, a
   LIST, or a DEPLOY, which burns `D`): from that block on the digests part for good.
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
| `src/verifier.rs` | `SpendVerifier`: the nine public inputs and a proof; `PlonkVerifier` (the verifier of `circuit/` under the pinned key), `RejectAll`, `TestVerifier` |
| `src/state.rs` | acceptance rules, turnstile, listings, block processing, digest, undo log (§5, §6) |
| `src/events.rs` | byte encoding of the events inside the digest (§6) |
| `src/json.rs` | blocks from `getblock <hash> 3` (or 2) and from the vectors |
| `src/raw.rs` | a block from Bitcoin's serialization (`/block/:hash/raw`): header, transactions in both forms (BIP 144), merkle root, witness commitment. Written from Bitcoin's formats, not from `indexer/` |
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
| `tests/plonk.rs` | replays `plonk-v0.3.json` under the real verifier: the key and its digest; the envelopes and each `bodyHash`; every verifier call with its nine inputs and its answer; per block the root, the events, `eventsH`, the digest; the refusals; the final state. The same chain with every spend refused. And one valid proof made wrong thirty-odd ways (each public input moved, each part of the proof, a scalar that is `r`, bytes that are no point, other lengths): all refused |
| `tests/codec.rs` | every envelope of the vectors and of the §4 table, byte for byte; the note leaf; what the decoder refuses |
| `tests/rules.rs` | what the vectors do not cover: carriers at their edges, batches at their edges, mint window and payment, DEPLOY conditions and maturity, the `payScript` rule, anchors, nullifiers, CANCELLED, CLOSED, CLAIM, team unlocks, reorgs |
| `tests/replay_cli.rs` | the `replay` command over the scenario written as `getblock` files, and over the chain of `plonk-v0.3.json` with the real verifier and without |
| `tests/follow.rs` | the follower over a chain in memory: the scenario block after block, among transactions that carry nothing; the vectors' reorg and back; a shorter chain; the scenario undone block by block; a reorg of the activation block; one deeper than the undo history; a failure at every call to the source; a missing commit height; restarts from the block file, and a damaged file |
| `tests/api.rs` | every route over the scenario: roots, digests, `eventsH`, refusals, nullifiers, listings and token counters against the vectors; public leaves recomputed from their openings; Merkle paths folded up to the root; batches in `/tx`; pages, bad parameters, 404s |
| `tests/sources.rs` | over real sockets on local ports: the scenario served as Bitcoin Core's RPC (credentials, a busy node, no `prevout.height`) and as an Esplora API (pages, commit heights, 429; blocks of more than one page read raw, from a server that has the route and from one that has not, and eight kinds of bytes that are not the block), and the `follow` command from its first block through a reorg, a stop and a restart with the node down; `follow` with the real verifier over the chain of `plonk-v0.3.json` |

`tests/rules.rs` states this implementation's reading of the spec. It is not evidence of agreement with the
reference: only the vectors and a run of both indexers over the same chain are.

In `tests/follow.rs`, `tests/api.rs` and `tests/sources.rs` the vectors say what the digests, roots and leaves must
be; the Core and Esplora answers are written here from those services' documented formats, and `follow --esplora`
was run once against a public signet API (2026-11-21, five blocks to the tip). No test runs against the reference
indexer's API: where `docs/API.md` is silent, the shape of an answer is this indexer's choice.

## Limits

- The PLONK verifier is the reference's own code (`circuit/`), on purpose: the two indexers check each other's rules,
  not each other's proof check. Only two proofs made by the prover are replayed here (a TRANSFER and a BURN); a LIST
  and a DEPLOY that burns go through the same call, with inputs built by the same code, but with no real proof in
  any vector.
- The state lives in memory; `--data` keeps the blocks, not the state, so a restart applies them again.
- `/nullifiers`, `/roots` and `/listings` return everything at once, as `docs/API.md` describes them.
- One request per connection, 64 at a time and 8 for one remote address (an IPv6 /64 counts as one). A connection
  has 10 seconds in all to send its request and 60 to take the answer. Put a reverse proxy in front for a public
  address or for TLS.
