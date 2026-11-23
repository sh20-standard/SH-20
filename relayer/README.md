# relayer — SH-20 reference relayer

Publishes other people's proved TRANSFERs, in batches, from its own Bitcoin; each pays it in tokens
by one of its three outputs. What a sender hands over, what the relayer checks, how it batches, what
it sees and what a sender does when it drops a transfer: [`docs/RELAYER.md`](../docs/RELAYER.md).

Node ≥ 20, zero dependencies. It reuses the code checked elsewhere in the repository: the indexer's
codec and PLONK verifier (`indexer/src/`), the scanning of `circuit/js` and the vault's Bitcoin and
taproot code (`vault/src/`).

```sh
npm test                 # 6 tests, against the reference indexer and its API, with a mock verifier
node bin/relayer.js --indexer http://127.0.0.1:8020 --esplora http://127.0.0.1:8020/esplora --fee SH20=25
```

The regtest flow, with real proofs and Bitcoin Core's relay policy (from the repository root):

```sh
node vault/dev/regtest.js &      # Bitcoin Core regtest, two indexers, an Esplora at :8020/esplora
node relayer/dev/regtest.js      # two senders, one batch, everyone's notes checked
```

| Path | What |
| --- | --- |
| `src/check.js` | the checks of `docs/RELAYER.md` §2 that need no chain: the bytes, the spend's rules, the anchor, the fee, the verifier's inputs |
| `src/relayer.js` | the queue, the checks against its indexer, when a batch is due, publishing |
| `src/batch.js` | the batch's tapscript, its commit and its reveal |
| `src/keys.js` | the relayer's words (its sh20 address, as a vault derives it) and its Bitcoin key |
| `src/http.js` | `GET /info`, `POST /transfer`, `GET /transfer/:nf` |
| `bin/relayer.js` | the command line |
| `dev/regtest.js` | the flow on Bitcoin Core regtest |
