# The public signet

How SH-20 goes live on Bitcoin's signet, so that anyone can mint, send, deploy and sell with
coins that are worth nothing, and so that phones and real wallets get tried before mainnet.
Every step names the file or command it uses. Nothing here needs a server run by the SH-20
contributors: the standard needs none (hard requirement 2), and a default of ours would make us one.

## What must be true first

| | Condition | State (2026-11-22) |
| --- | --- | --- |
| 1 | The clean redeploy: the repository on the project's own anonymous account `SH-20`, public, history rewritten (`docs/PLAN.md` §2) | waits on that account; the rewritten history is ready |
| 2 | The CI runs. On a public repository GitHub's runners cost nothing; on a private one a run costs about 27 runner minutes | the account's minutes ran out on 2026-11-22 (no job starts since 11:41 UTC) |
| 3 | `indexer-rs` verifies PLONK proofs. Without `--verifier plonk-bn254-hermez` it refuses every spend, and parts with the reference at the first TRANSFER | done (2026-11-23): the verifier of `circuit/` as a library; it replays `indexer/vectors/plonk-v0.3.json` |
| 4 | An indexer that a phone can reach (below, "Phones") | the site's own mirror (`docs/PLAN.md`, decision 3): built by `pages.yml` and read by the explorer (2026-11-24); the vault to read it |
| 5 | The activation height `A` | fixed at launch (step 1) |

## Launch, in order

1. **Fix `A`.** For the soft launch, the signet tip + 6, about an hour (signet mines about 144 blocks a
   day): signet coins are worth nothing, so mints before the announcement harm nobody (`docs/PLAN.md`,
   decision 4). On mainnet, a block not yet mined when the launch is announced. Set `SIGNET_ACTIVATION_HEIGHT = A` in `vault/src/profile.js`: the one
   value a launch adds. The rest of the profile is in the code and is never passed on signet: `D =
   1000`, `N = 6`, `W = 100`, `K_min = 1`, genesis `SH20` (`indexer/src/constants.js`). The vault
   names any indexer whose `/status` reports another profile, and acts on nothing it says.
2. **A signet node.** Bitcoin Core with `-signet -server`, not pruned: both indexers read every block
   from `A` on with `getblock <hash> 3` (each input's spent output and its height). With `--data`, a
   restart applies the blocks kept on disk again instead of asking the node for them. No `-txindex`.
   The RPC port is 38332.
3. **Two indexers on that node**, the reference and the clean room, with the same `A`:

   ```sh
   node indexer/bin/follow.js --rpc http://127.0.0.1:38332 --rpcuser U --rpcpass P \
     --activation A --deploy-burn 1000 --verifier vault/prover/sh20_circuit.wasm --data ~/sh20-js   # API on 127.0.0.1:8020
   indexer-rs/target/release/sh20-indexer-rs follow --rpc http://127.0.0.1:38332 \
     --rpccookie ~/.bitcoin/signet/.cookie --activation A --deploy-burn 1000 \
     --verifier plonk-bn254-hermez --data ~/sh20-rs                      # API on 127.0.0.1:8621
   ```

   `indexer-rs` has no default for `D`: `--deploy-burn 1000` is required. `vault/prover/sh20_circuit.wasm`
   is the build of `circuit/` the CI checks byte for byte (`vault/tools/prover.sh --check`).
   Open the explorer with both (`explorer/index.html?indexer=http://127.0.0.1:8020&indexer=http://127.0.0.1:8621`):
   it compares their digests at the height both have reached. A difference stops the run (below).
4. **The site.** Settings → Pages → Source: GitHub Actions; Settings → Secrets and variables →
   Actions → Variables: `PAGES` = `on`. `.github/workflows/pages.yml` then publishes, from `main`,
   the vault on the signet profile at `/vault/`, the explorer at `/explorer/`, the phone test page
   at `/phone/`, and the mirror of both indexers at `/api/js/` and `/api/rs/`, rebuilt every 10
   minutes from a public signet Esplora (the variable `SIGNET_ESPLORA`, else mempool.space). It
   publishes nothing while `A` is unset, so nothing goes out before step 1. The first run after the
   launch reads the chain from `A`; each later run starts from the block files the last one cached.
   The explorer on the site reads both mirrors by itself and compares their digests.
5. **The release.** `vault/RELEASES.md`, steps 3 to 6: version, CI green on the commit (the regtest
   job included), `npm run release`, and the `release` workflow's rebuild. Step 7, the CID pinned on
   IPFS, waits for mainnet (`docs/PLAN.md`, decision 5).
6. **A real wallet signs** a MINT, a transfer and a sale on signet, with each of Xverse, UniSat and
   Leather that can be set to signet. Note which ones cannot: the vault's README says what each returns.
7. **Announce**: `A`, the site's address, the release's SHA-256 and CID, and the explorer link with
   the indexers testers may compare.

## What a tester does

- **On a computer.** Run an indexer of one's own: the vault's signet defaults already point at
  `http://127.0.0.1:8020` (`vault/src/servers.js`): Chrome and Firefox let an https page read this
  machine's own address over plain http (Safari is to be tried). Without
  a node: `node indexer/bin/follow.js --esplora https://mempool.space/signet/api --activation A
  --deploy-burn 1000 --verifier vault/prover/sh20_circuit.wasm` (the Esplora server is then trusted to name the best
  chain; every envelope is still checked here). The browser may ask before a public page reads this
  machine's own address: allow it for the site.
- **Coins.** Signet coins come from a signet faucet; a MINT of SH20 costs network fees only.
- **What to try**, each one once: mint SH20, send some to another tester and receive some, DEPLOY a
  ticker (it burns 1,000 SH20: one mint), mint it, list some for sale, buy another tester's listing,
  cancel one, CLAIM a sale's BTC, restore the vault from its backup on another browser.
- **What to send back**: for anything that failed, the txid and the vault's message; the `/status` of
  the indexer used; from the phone page, the JSON of both runs with the phone's model and state (on
  its charger or not, Low Power Mode, hot or cool: `circuit/web/README.md`).

## Phones

The phone test page needs nothing but the site: it proves on the phone and reports the time. The
vault on a phone needs an indexer the phone can reach, which means https on a public address: an
https page cannot read a plain http address other than the device's own.

Decided (`docs/PLAN.md`, decision 3) and built (2026-11-24): the site serves a mirror of both indexers
itself, at `/api/js/` and `/api/rs/`, rebuilt every 10 minutes by `pages.yml` from the public code; it
lags the chain by about 10 to 30 minutes (`docs/API.md`, "The static mirror"). The explorer reads it;
until the vault does, phones measure the prover and the whole flow is tried on computers. Operators who run `follow.js` behind https can still offer it as a link
(`/vault/?indexer=https://…`): the vault asks before it uses servers from a link, and a default needs
its operator's agreement and its host in `vault/test/signet.test.js` (`vault/RELEASES.md`, step 2).

## When the run stops

The two indexers give different digests at the same height; the explorer's supply check fails; an
indexer accepts a spend it should refuse, or refuses one it should accept. Keep both indexers'
logs and the height, dump the blocks from `A` (`bitcoin-cli -signet getblock <hash> 3`), and replay
them in both with the profile of step 1 (`node indexer/bin/replay.js <folder> --activation A --deploy-burn 1000 --verifier
vault/prover/sh20_circuit.wasm`, `sh20-indexer-rs replay <folder> --activation A --deploy-burn 1000
--verifier plonk-bn254-hermez --json`): the first block whose events differ says which rule. On signet the
simplest restart is a new release with a new `A`; the old chain's tokens do not carry over.
