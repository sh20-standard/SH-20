# SH-20 indexer API — draft v0.1

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
| `GET /status` | `{ network, activationHeight, height, digest, root, leaves, nullifiers, tokens, verifier }` |
| `GET /tokens` | every deployed token: `{ tokenNum, ticker, max, lim, pre, start, end, unlock, price, payMode, payScript, mints, burned, deployTxid, deployHeight }` |
| `GET /token/:ticker` | one token (`[A-Z0-9]{4}`), or 404 |
| `GET /notes?from=0&limit=1000` | `{ from, total, notes }`, one entry per tree leaf in tree order; `limit` ≤ 5000 |
| `GET /path/:pos` | `{ pos, height, root, siblings[32] }` for the leaf at `pos`, against the current root |
| `GET /roots?from=H` | `[{ height, root }]`, default from `height − 100` (the anchor window) |
| `GET /nullifier/:hex` | `{ nullifier, spent }` |
| `GET /listings?state=ACTIVE` | listings, optionally filtered by state (ACTIVE, SOLD, CANCELLED, CLOSED, CLAIMED) |
| `GET /listing/:txid` | one listing, or 404 |

**Notes.** Every note has `pos`, `height`, `txid`, `leaf` and `kind`:

| kind | extra fields | created by |
| --- | --- | --- |
| `MINT`, `TEAM`, `TAKE`, `CLAIM` | `t`, `v`, `npk`, `rho` (public opening) | proof-less envelopes and team unlocks |
| `OUT` | `j` (output index), `pkEph`, `ct` | the three outputs of every spend |

A wallet scans `OUT` notes with its viewing key (decrypting `ct` with the ECDH secret from `pkEph`),
recognises its public notes by `npk`, and asks `/nullifier` whether a note it owns is spent.
The `ct` sealing format is not final yet.

**Reorgs.** The follower keeps 288 blocks of undo history, rolls back to the common block and replays.
A deeper reorg stops the follower with an error instead of serving a wrong state.
