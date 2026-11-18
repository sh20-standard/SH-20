# SH-20 design — draft v0.3

SH-20 is an open standard for fungible shielded tokens on Bitcoin L1: anyone deploys a ticker, the
mint is public and paid in BTC, and transfers are private. Bitcoin only publishes and orders data;
every indexer recomputes the same state. Nothing is activated on any network.

## What is public, what is private

| Data | Visibility |
| --- | --- |
| Ticker, max supply, team allocation, mint price and window | Public |
| Each mint: ticker, amount, receiving key | Public |
| Circulating supply (minted minus burned) | Public |
| Listing: ticker, amount, price | Public |
| Transfer: ticker, amount, sender, recipient | Private |
| A holder's balance | Private |

Tokens enter and leave in public (mint, team unlock, purchase; burn, listing) and move in private
inside one pool shared by every ticker. Each new ticker enlarges everyone's anonymity set.

## Principles

- **Open:** anyone deploys a ticker without permission.
- **Unique tickers:** 4 characters `[A-Z0-9]`; the first valid DEPLOY keeps the name forever.
- **Honest supply:** max supply, team allocation and its unlock block are public at DEPLOY.
- **Real cost:** each mint costs a price in BTC set by the deployer, burned or paid to a public script.
- **Public mint is mandatory:** a DEPLOY must leave something to mint (`pre < max`).
- **Private transfers:** amount, ticker, sender and recipient are hidden.
- **No third party:** no admin key, blacklist, co-signer or platform signature.

Non-goals for v0: private BTC (no peg), DeFi, NFTs.

## Launch and walk away

After activation nothing depends on the team.

| Piece | Who runs it after launch | Ready before activation |
| --- | --- | --- |
| Rules | Nobody: frozen, version `0x00` | Frozen spec and test vectors |
| Activation | A block height written in the spec | Height fixed in advance |
| Proof parameters | Nobody: public Hermez setup, key hash in the spec | PLONK-KZG: keys derived from the circuit and the setup, so no ceremony |
| Indexer | Anyone, with their own node | Free code, two implementations with the same digest |
| Wallet | The user, on their device | Static page on IPFS and a CLI; proofs computed locally |
| Relayers | Anyone, paid inside the pool; optional | Relayer code; self-publishing always works |
| Sale offers | Any marketplace or Nostr relay | A published offer format (partially signed transaction) |
| Mint price | Nobody in the middle: BTC burn or direct payment | — |

A fix after activation is a new version byte that each indexer chooses to adopt, as with Runes, so
audits and public signet tests happen before activation.

## Lifecycle

- **Genesis token: SH20.** Fixed in the activation profile rather than deployed, so nobody can race for it
  and nobody owns its deployment, the team included. Like ORDI: 21,000,000 units, 1,000 per mint (21,000 mints),
  free to mint (network fees only), no team allocation.
- **DEPLOY** reserves a ticker and fixes its rules.
  A token is named by its ticker everywhere, on the wire and inside notes (`t` = its 4 bytes as a number),
  so a wallet can check on chain which token a mint or a listing is for. The team allocation, if any, enters the tree automatically at its public unlock block.
- **Proposed rule:** every DEPLOY burns `D` SH20, so the whole meta consumes SH20 supply after its
  mint-out (`D = 0` turns the burn off). The trade-off: deployers must buy genesis first, which
  slows spam but also adoption. The alternative is the plain BRC-20 model with no burn.
- **MINT** creates a public note of exactly `lim` units, with no proof, in one OP_RETURN transaction.
  All mints of a ticker are identical. A rejected mint is not refunded.
- **TRANSFER** spends two notes and creates three, inside the pool; only nullifiers and new leaves are published.
- **BURN** spends notes and publishes the amount and ticker that leave.
- **Trading:** LIST moves an amount into a public escrow and creates a P2TR lock output. The seller
  signs a spend of the lock with `SIGHASH_SINGLE | ANYONECANPAY` that pays the price to them, and
  shares it anywhere. Anyone completes it with a TAKE: the tokens move only if the lock is spent, and a
  lock is spent once, so a sale can be neither doubled nor unpaid. A TAKE without payment is the
  seller cancelling; a lock spent with no TAKE closes the listing, and the seller CLAIMs with a signature.

## Proof engine

PLONK with KZG commitments over BN254, on the public Hermez `pot18` powers of tau. Proofs are 480 bytes
and the keys are a deterministic function of the circuit and that setup: no ceremony, no secret.

An open standard without an admin should not rest on a ceremony run by its own authors, which rules
out Groth16 (192-byte proofs, but a new ceremony for every change to the circuit). Among the systems
that reuse a universal public setup, each option was measured on the SH-20 relation before choosing
(method and reproduction: [`circuit/README.md`](../circuit/README.md); one laptop, 10 threads):

| Option | Proof | Proving time | TRANSFER reveal |
| --- | --- | --- | --- |
| Halo2-KZG, Tacit's layout | 2,080 bytes | 1.1–1.4 s | 743 vB |
| Halo2-KZG, tightest layouts | 800 to about 1,000 bytes | 0.5–2.5 s | 421–469 vB |
| fflonk (snarkjs) | 608 bytes | 122–146 s; needs more powers than `pot18` holds | 372 vB |
| PLONK (snarkjs) | 480 bytes | 73–80 s | 340 vB |
| **PLONK, native prover (chosen)** | **480 bytes** | **1.5–1.6 s** | **340 vB** |

PLONK's linearisation keeps the proof at 9 group elements and 6 scalars whatever the circuit; Halo2
opens every column, so its proof cannot go below about 800 bytes here. snarkjs' prover was the
obstacle, not the protocol: `circuit/` implements the same protocol in Rust, and snarkjs' verifier
accepts its proofs, which gives the standard two independent verifiers.

The price is proving work: 9.6 s on one thread against 2.8 s for Tacit's Halo2 circuit. In a browser the
prover takes 25 s on one thread and 7 s on four (WebAssembly threads, measured on a laptop), with a
proving key that is shipped rather than generated on the device. Proving time only affects transfers, burns
and listings, never the mint. On a recent phone (iPhone 18 Pro Max, Safari) a proof takes 14.5 s on four threads
and 32 s on one; a mid-range phone has not been measured.

The relation follows Tacit's shielded pool (MIT) with the ticker made private, SH-20's note leaf and no
transparent boundary. Notes per proof: 2 in, 3 out (the recipient, the change, and a relayer's fee in tokens).
The verifier stays cross-checked against snarkjs' PLONK verifier.

## Security, privacy, limits

- **Main risk:** a bug in the circuit or in the verifier that accepts a bad proof would allow counterfeiting.
  Counterfeits are invisible in transfers and would only show if a ticker's public outflows exceeded its
  minted supply. The circuit and its PLONK verifier are new code: hence an audit, a public signet run and a
  bug bounty before activation.
- **Still visible:** mints, listings, burns and purchases; the BTC inputs paying fees (mitigated by
  relayers, fresh addresses, delayed publication); timing.
- **Anonymity at launch** is small and grows with every mint, purchase and ticker.
- **Relay policy:** witness envelopes are standard everywhere since Taproot; OP_RETURN above 83 bytes is
  relayed by default since Bitcoin Core 30 but still filtered by some nodes and pools.
- **Legal:** privacy tools are under regulatory pressure in several jurisdictions; get legal advice before mainnet.

## Prior art and competitors

- [Tacit](https://github.com/z0r0z/tacit) — confidential amounts on Bitcoin since May 2026, fair mint,
  shielded pool; the asset id is public in each spend.
- [zkCoins / Shielded CSV](https://zkcoins-docs.pages.dev/specification) — client-side validation,
  hides the asset; only an asset's creator mints.
- [Shielded Ordinals](https://github.com/Fl1ntstowned/shielded-ordinals) — private NFTs; the platform signs mints and buys.
- [Shielded Bitcoin](https://eprint.iacr.org/2026/2749) ([alloc] init, September 2026) and
  [77ph/shielded-bitcoin](https://github.com/77ph/shielded-bitcoin) — private BTC transfers, no tokens;
  the paper leaves BTC entry and exit out of scope and nothing is deployed yet.
- [pERC20](https://github.com/PLabs4/pERC20_) — private tokens on EVM chains, issuer-only mint.

## Reserved for later

- `t = 0` is reserved for native BTC in the shared tree, and envelope types `0x08`–`0x0f` for extensions:
  aggregated batches (one proof for many transfers, built by anyone) and a BTC entry and exit once Bitcoin
  can enforce one without a federation. Both arrive as new rules that indexers opt into; existing tokens keep working.

## Open decisions

1. Final name and 4-byte magic.
2. Value of `D`, or no genesis burn at all.
3. Tickers of 4 characters only, or also 5 to 12 (then `t` = the ticker's bytes as a big-endian number,
   still unique and below the field size, and ticker fields get a length byte).
4. Several envelopes per transaction, so relayers can publish in batches.
5. Exact event encoding inside the digest, frozen before activation.
