# SH-20 indexer API — draft v0.2

Read-only JSON over HTTP, served by `indexer/bin/follow.js`. GET only, CORS open (`*`), no
authentication: it reports what the chain implies and can change nothing. Anyone can run it;
a wallet should use its own or several, and can check them against each other with `digest`.

Encoding: big integers (amounts, supply) are decimal strings; field elements, hashes and
nullifiers are 64-character lowercase hex (big-endian, for readability); txids are in display order.

```sh
node bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser USER --rpcpass PASS --activation H
node bin/follow.js --esplora https://mempool.space/signet/api --activation H
```

| Route | Returns |
| --- | --- |
| `GET /status` | `{ network, activationHeight, height, digest, root, leaves, nullifiers, tokens, genesis, deployBurn, anchorWindow, verifier }` |
| `GET /tokens` | every token, genesis `SH20` first (`genesis: true`, `deployTxid: null`), then in DEPLOY order: `{ ticker, t, max, lim, pre, start, end, unlock, price, payMode, payScript, mints, burned, deployTxid, deployHeight }` |
| `GET /token/:ticker` | one token (`[A-Z0-9]{4}`), or 404 |
| `GET /notes?from=0&limit=1000` | `{ from, total, notes }`, one entry per tree leaf in tree order; `limit` ≤ 5000 |
| `GET /path/:pos` | `{ pos, height, root, siblings[32] }` for the leaf at `pos`, against the current root |
| `GET /roots?from=H` | `[{ height, root }]`, default from `height − 100` (the anchor window) |
| `GET /nullifier/:hex` | `{ nullifier, spent }` |
| `GET /nullifiers?from=H` | `{ from, height, nullifiers: [{ height, nullifier }] }`: every nullifier spent from block `H` on |
| `GET /listings?state=ACTIVE` | listings, optionally filtered by state (ACTIVE, SOLD, CANCELLED, CLOSED, CLAIMED) |
| `GET /listing/:txid` | one listing, or 404 |
| `GET /digest/:height` | `{ height, digest }` after that block: two honest indexers give the same value at the same height |
| `GET /blocks?before=H&limit=20` | blocks with SH-20 activity, newest first: `[{ height, hash, digest, root, leaves, events, rejected }]`; `limit` ≤ 200 |
| `GET /tx/:txid` | one SH-20 transaction: `{ txid, height, event, rejected, notes }` (the accepted event or the rejection reason, and the notes it created) |

**Tokens.** `t` is the ticker's id inside notes and proofs (`tickerT`, SPEC-WIRE §2), as a decimal string;
a wallet can recompute it from the ticker. Before paying for a mint, a wallet should check the token's
conditions against the DEPLOY transaction itself (`deployTxid`), which any Bitcoin source returns, and compare
`digest` and the token across several independent indexers: only the full history proves which DEPLOY of a
ticker came first.

**Notes.** Every note has `pos`, `height`, `txid`, `leaf` and `kind`:

| kind | extra fields | created by |
| --- | --- | --- |
| `MINT`, `TEAM`, `TAKE`, `CLAIM` | `ticker`, `v`, `npk`, `rho` (public opening) | proof-less envelopes and team unlocks |
| `OUT` | `j` (output index), `pkEph`, `ct` | the three outputs of every spend |

A wallet scans `OUT` notes with its viewing key (decrypting `ct` with the ECDH secret from `pkEph`),
recognises its public notes by `npk`, and asks `/nullifier` whether a note it owns is spent.
The `ct` sealing format is not final yet.

**Privacy for wallets.** Every request tells the indexer what you are interested in. Never ask `/path/:pos`
or `/nullifier/:hex` for your own notes: that tells the indexer which notes are yours. Download `/notes`
(every leaf) and `/nullifiers`, rebuild the tree and check spends on the device; ask for everything, not for what you own.

**Reorgs.** The follower keeps 288 blocks of undo history, rolls back to the common block and replays.
A deeper reorg stops the follower with an error instead of serving a wrong state.
