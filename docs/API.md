# SH-20 indexer API — draft v0.3

Read-only JSON over HTTP, served by `indexer/bin/follow.js` and by `indexer-rs follow`. GET only (`405` otherwise),
CORS open (`*`, and `204` to a browser's preflight), no authentication: it reports what the chain implies and can change
nothing. Anyone can run it; a wallet should use its own or several, and can check them against each other with `digest`.
Two indexers given the same profile answer every route below with the same JSON, field for field, apart from the free
text of `error` and of refusal reasons and the `implementation` field: `indexer/bin/api-diff.js` checks it, route by
route, on a random chain both follow.

Encoding: big integers (amounts, supply) are decimal strings; heights, positions, counts, `payMode`, `start`, `end`,
`unlock` and `lockVout`-like indices are JSON numbers; field elements, hashes and nullifiers are 64-character lowercase
hex (big-endian, for readability); other byte strings (`payScript`, `pkEph`, `ct`, `lockKey`) are lowercase hex as on the
wire; txids are in display order.

```sh
node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation A --deploy-burn D --network signet
node bin/follow.js --esplora https://mempool.space/signet/api --activation A --deploy-burn D --network signet
sh20-indexer-rs follow --esplora https://mempool.space/signet/api --activation A --deploy-burn D --network signet
```

Every indexer of a network takes the same profile (`--activation`, `--deploy-burn`, `--window`, `--min-depth`,
`--maturity`): `D`, `W`, `K_min` and `N` are in the GENESIS record, so a difference shows in the digest of block `A`;
`A` is not, so two indexers started at different heights agree on nothing and no digest says why. Give `--network`
too: it is what `/status` reports, and the vault refuses an indexer whose network or profile is not its own.

| Route | Returns |
| --- | --- |
| `GET /status` | `{ network, implementation, activationHeight, height, hash, digest, root, leaves, nullifiers, tokens, genesis, deployBurn, deployMaturity, anchorWindow, anchorMinDepth, verifier }` (below) |
| `GET /tokens` | every token, genesis `SH20` first (`genesis: true`, `deployTxid: null`), then in DEPLOY order: `{ ticker, t, max, lim, pre, start, end, unlock, price, payMode, payScript, mints, burned, pool, deployTxid, deployHeight }` (`pool`: the turnstile of SPEC-WIRE §5, what the shielded pool holds of the ticker) |
| `GET /token/:ticker` | one token (`[A-Z0-9]{4}`), 404 if none, 400 for another string |
| `GET /notes?from=0&limit=1000` | `{ from, total, notes }`, one entry per tree leaf in tree order; a `limit` above 5000 is brought down to 5000; a `from` past the last leaf gives an empty list |
| `GET /path/:pos` | `{ pos, height, root, siblings[32] }`: the siblings from the leaf's level up to the root's children, against the root at `height`, the tip; 404 for a position with no leaf |
| `GET /roots?from=H` | `[{ height, root }]` from `max(H, A)` to the tip; default `H` is `height − W` (the anchor window of the profile) |
| `GET /nullifier/:hex` | `{ nullifier, spent }` |
| `GET /nullifiers?from=H` | `{ from, height, nullifiers: [{ height, nullifier }] }`: every nullifier spent from block `H` on (default `A`), in the order spent (block by block, events in order, `nf0` before `nf1`); `height` is the tip |
| `GET /listings?state=ACTIVE` | listings in LIST order (below), optionally filtered by state: `ACTIVE`, `SOLD`, `CANCELLED`, `CLOSED`, `CLAIMED`; another state is 400 |
| `GET /listing/:txid` | one listing, or 404 |
| `GET /digest/:height` | `{ height, digest }` after that block: two honest indexers give the same value at the same height; 404 outside `A` to the tip (`/status` gives `digest_{A−1}` before the first block) |
| `GET /blocks?before=H&limit=20` | blocks with SH-20 activity (an event or a refusal), newest first, below `H` (`H` excluded: the last height of a page is the `before` of the next); a `limit` above 200 is brought down to 200 |
| `GET /block/:height` | one block from `A` to the tip, with activity or not; 404 otherwise |
| `GET /tx/:txid` | one SH-20 transaction (below); 404 if it has no event and no refusal |

A route parameter that does not parse (`/tx/xyz`, `limit=x`) is `400`, what does not exist `404`, both with
`{ "error": "…" }`; a query parameter a route does not know is ignored.

**Status.** `network`: what the indexer was started for (`--network`; else, from Bitcoin Core, the node's chain name; else
`unknown`). `implementation`: which indexer answers, free text. `height` and `hash`: the tip, `null` before the first
block, when `digest` is `digest_{A−1}` and `root` the empty root. `genesis`: the genesis ticker, `"SH20"`.
`tokens`, `leaves`, `nullifiers`: counts. `deployBurn` is a decimal string; `deployMaturity`, `anchorWindow` and
`anchorMinDepth` are numbers. `verifier`: `plonk-bn254-hermez` (the PLONK verifier of `circuit/`, keyed by `VK_DIGEST`),
`test` (the vectors' rule, for differential runs) or `reject-all` (every spend refused; the vault says so beside the
balance).

**Blocks.** `{ height, hash, digest, root, leaves, events, rejected, eventsH }`: `events` in API shape (below), `rejected`
as `[{ txid, reason }]` with `envelope` in a batch, and `eventsH` the byte string of SPEC-WIRE §6 in hex, the one form of
the events that two indexers must agree on byte for byte.

**Events.** An event is `{ type, txid, … }` with the fields of its record in SPEC-WIRE §6, under the spec's names;
GENESIS and TEAM_UNLOCK have no `txid`, and in a batch an event carries its `envelope` index. `pos` is a number for one
note and three numbers for a spend's outputs; `nullifiers` are the spend's two.

| type | fields beside `type` and `txid` |
| --- | --- |
| `GENESIS` | `ticker`, `max`, `lim`, `deployBurn`, `anchorWindow`, `anchorMinDepth`, `deployMaturity` |
| `DEPLOY` | `ticker`; with `D > 0`, the burn's `nullifiers` and `pos` |
| `MINT` | `ticker`, `v`, `pos` |
| `TEAM_UNLOCK` | `ticker`, `pre`, `pos` |
| `TRANSFER` | `nullifiers`, `pos` |
| `BURN` | `ticker`, `vPub`, `nullifiers`, `pos` |
| `LIST` | `ticker`, `amount`, `price`, `nullifiers`, `pos` (the listing is the LIST's own `txid`) |
| `TAKE` | `listTxid`, `outcome` (`SOLD` or `CANCELLED`), `pos` |
| `CLAIM` | `listTxid`, `pos` |
| `CLOSED` | `listTxid` |

**Listings.** `{ listTxid, ticker, amount, price, payScript, lock, lockKey, state, height }`: `lock` is the lock output as
`txid:vout`, `height` the LIST's block; `takeTxid` once SOLD or CANCELLED, `closedBy` (the transaction that spent the lock
without a TAKE) once CLOSED, kept when CLAIMED.

**Transactions.** `{ txid, height, event, rejected, events, rejections, notes }`. `event` and `rejected` are the verdict
on the transaction's one envelope: its event, or the reason it was refused (free text). CLOSED is never a verdict: it is
in `events` only, so a transaction that spends a lock and carries no envelope has `event: null`, `rejected: null` and one
event, and a refused one that spends a lock has a reason and one event. A batch of TRANSFERs has a verdict per envelope
and none for the whole: `event` and `rejected` are `null`, and `events` and `rejections` (`[{ reason }]`) list them all,
each with its `envelope` index; the notes of a batch carry their `envelope` too.

**Tokens.** `t` is the ticker's id inside notes and proofs (`tickerT`, SPEC-WIRE §2), as a decimal string;
a wallet can recompute it from the ticker. Before paying for a mint, a wallet should check the token's
conditions against the DEPLOY transaction itself (`deployTxid`), which any Bitcoin source returns, and compare
`digest` and the token across several independent indexers: only the full history proves which DEPLOY of a
ticker came first. The genesis token's `deployHeight` is `A`.

**Notes.** Every note has `pos`, `height`, `txid`, `leaf` and `kind`; a TEAM note has `txid: null` (no transaction
creates it):

| kind | extra fields | created by |
| --- | --- | --- |
| `MINT`, `TEAM`, `TAKE`, `CLAIM` | `ticker`, `v`, `npk` (public opening; `rho` is 0) | proof-less envelopes and team unlocks |
| `OUT` | `j` (output index), `pkEph`, `ct` | the three outputs of every spend |

A wallet scans `OUT` notes with its viewing key (decrypting `ct` with the ECDH secret from `pkEph`, `docs/SPEC-NOTES.md`),
recognises its public notes by `npk`, and checks on the device whether a note it owns is spent.

**Privacy for wallets.** Every request tells the indexer what you are interested in. Never ask `/path/:pos`
or `/nullifier/:hex` for your own notes: that tells the indexer which notes are yours. Download `/notes`
(every leaf) and `/nullifiers`, rebuild the tree and check spends on the device; ask for everything, not for what you own.

**Reorgs.** The follower keeps 288 blocks of undo history, rolls back to the common block and replays.
A deeper reorg stops the follower with an error instead of serving a wrong state. While it rolls back, the API serves
each tip on the way: a client that pages through `/notes` reads `/status` before and after, and starts again if `hash` or
`digest` moved.
