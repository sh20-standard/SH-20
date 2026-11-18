# SH-20 explorer

One self-contained page (`index.html`) that shows what SH-20 makes public and what it keeps sealed:

- **The transfer demo**: the same kind of transfer on BRC-20 or Runes, on Tacit and on SH-20, next to what
  the latest SH-20 transfer on the chain actually puts on Bitcoin.
- **Activity**: every SH-20 transaction, newest first, with rejected envelopes and their reason.
- **Supply**: per ticker, what was minted, the team allocation and its unlock block, what was burned and
  what sits in open offers, with the one check anyone can run on a sealed pool: public outflows never
  exceed issued supply.
- **Indexers**: read from any SH-20 indexer and compare several of them at the same block (`/digest/:height`).

No dependency, no CDN, no font or script from another domain, no server of ours. It reads the
read-only indexer API ([`../docs/API.md`](../docs/API.md)) and keeps its settings in the browser.
English and French.

## Use it

Open `index.html` from disk or from any static host (GitHub Pages, IPFS, your own server). With no
indexer address it shows its built-in **demo sample**, clearly labelled as such. Add one or more
indexer addresses under *Indexers*, or pass them in the link: `index.html?indexer=https://…`
(link addresses are used for that tab only and never saved).

To read a live chain, run an indexer:

```sh
cd indexer
node bin/follow.js --esplora https://mempool.space/signet/api --activation H --host 0.0.0.0
```

## Demo data

The demo sample is real indexer output: `build-demo.mjs` replays a scripted test chain through the
reference indexer (`../indexer/src`) and captures every API route the page reads. Only the proofs are
fake (a demo verifier accepts any 480-byte proof), which is why the page says so. The script also
writes the SHA-256 of the page script into the page's Content-Security-Policy, so the page runs no
other script. Run it after any change to the page:

```sh
node explorer/build-demo.mjs   # deterministic: two runs give the same index.html
```
