# SH-20 Explorer

A block explorer for SH-20, in one static file (`index.html`): no dependency, no CDN, no script or
font from another domain (the Content-Security-Policy is pinned to the page script's SHA-256).

- **Dashboard**: block height, notes in the pool, spent notes, tokens, indexer agreement; the latest
  blocks with SH-20 activity (share of private and public transactions); latest transactions; tokens.
- **Blocks**, **Transactions**, **Tokens**, and a page for each block, transaction, token and nullifier.
  Sealed fields (token, amount, sender and recipient of a transfer, balances) show as *Hidden*.
- **Search**: txid, block height, ticker or nullifier.
- **Supply check** per token: units leaving the pool in public (burned or in open listings) never exceed
  units issued.
- **Indexers**: read from any SH-20 indexer and compare several at the same block (`/digest/:height`).

It reads the read-only indexer API ([`../docs/API.md`](../docs/API.md)) and keeps its settings in the browser.

## Use it

Open `index.html` from disk or any static host (GitHub Pages, IPFS, your own server). With no indexer
configured it shows its built-in **demo data**, labelled as such. Add indexer URLs under *Indexers*, or
pass them in the link: `index.html?indexer=https://…` (used for that tab only, never saved).

```sh
cd indexer
node bin/follow.js --esplora https://mempool.space/signet/api --activation A --deploy-burn 1000 --host 0.0.0.0
```

## Demo data

`build-demo.mjs` replays a scripted test chain through the reference indexer (`../indexer/src`) and
captures every API route the page reads; only the proofs are fake (a demo verifier accepts any
480-byte proof). It also writes the page script's hash into the CSP. Run it after any change to the page:

```sh
node explorer/build-demo.mjs   # deterministic: two runs give the same index.html
```
