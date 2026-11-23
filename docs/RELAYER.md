# SH-20 relayers — draft v0.3

A TRANSFER hides its amount, its ticker, its sender and its recipient, but the Bitcoin transaction that
carries it does not: the inputs that pay its network fee belong to someone, and on chain they say who
sent something. A **relayer** pays those fees from its own coins and is paid in tokens by one of the
transfer's three outputs. It is never trusted with a note: it cannot change, redirect or keep a
transfer, only publish it, late, or not at all. Anyone can run one. Nobody has to use one.

A relayer also shares bytes: it puts the transfers of several people in one transaction (a batch,
`SPEC-WIRE.md` §3), which costs each of them less than a transaction of their own.

This document is for wallet and relayer authors. It describes wire v0.3, which the signet runs. The
reference relayer is [`relayer/`](../relayer/), with its tests. The rules it relies on are in
`docs/SPEC-WIRE.md` (§3 carriers and batches, §4 the spend section, §5 acceptance) and
`docs/SPEC-NOTES.md` (§2 addresses, §3 sealing, §4 scanning).

## 1. What the sender hands over

The bytes of one TRANSFER envelope, 830 of them, proved, and nothing else: no Bitcoin transaction, no
key, no address of the sender.

The sender builds it as for any transfer, with three outputs in random order:

| Output | To | Amount |
| --- | --- | --- |
| the payment | the recipient's sh20 address | what is sent |
| the relayer's fee | the relayer's sh20 address | the relayer's fee for the ticker |
| the change | the sender's own address | the rest (0 if nothing is left) |

Every output is sealed as `SPEC-NOTES.md` §3 says, the relayer's too: on chain the three look alike.
A spend has one ticker for its five notes (`SPEC-WIRE.md` §4), so the fee is paid in the ticker of the
transfer. A relayer that does not price that ticker cannot be paid by that transfer.

The anchor (`anchorHeight`) should be recent: the relayer refuses a transfer whose anchor leaves too
few blocks before `anchorHeight + W` (§2), since it needs time to batch and confirm it.

The sender keeps a copy of the envelope until its nullifiers are on chain (§5).

**Interface of the reference relayer** (HTTP, JSON answers, `access-control-allow-origin: *`):

| Route | Answer |
| --- | --- |
| `GET /info` | `{ version, network, address, fees, maxBatch, maxWaitSeconds, minBlocksLeft, height, queued }`: `address` is the relayer's sh20 address (`tsh20…` on signet), `fees` maps each ticker it takes to its fee (an amount, as a decimal string), `minBlocksLeft` the blocks a transfer's anchor must leave (§2) |
| `POST /transfer` | the body is the envelope, in hex. `202 { state: "queued", nullifiers, fee: { ticker, v }, deadline }` when it takes it; the same transfer again gives its current status (`200`). Refusals: `400` not a TRANSFER of this version; `402` no output pays the fee; `409` a nullifier already spent or queued; `422` an anchor outside the window, or a proof that does not verify; `503` the relayer cannot check it now (its indexer is down or behind) |
| `GET /transfer/:nf` | the status of the transfer whose first or second nullifier is `nf` (64 hex): `{ state, nullifiers, txid?, reason? }`, `state` being `queued`, `published` or `dropped`; `404` if the relayer does not know it |

`/transfer/:nf` is a convenience. A sender follows a transfer by its nullifiers on its own indexers,
as for any spend: the relayer's word about a txid proves nothing (`SPEC-WIRE.md` §3: a TRANSFER is not
bound to its transaction).

## 2. What the relayer checks before it publishes

Its BTC pays for every envelope it publishes, accepted or refused. It publishes only what its indexer
would accept, checked in this order, the cheapest first, the proof last:

1. **The bytes.** 830 bytes; `"SH20"`, version `0x00`, type `0x03`; the codec of `indexer/` parses
   them and gives the same bytes back.
2. **The spend's own rules** (`SPEC-WIRE.md` §5). The two nullifiers are non-zero and distinct; the
   three leaves are non-zero.
3. **The anchor.** With `next` the block the batch can confirm in (the indexer's height + 1), `W` and
   `K_min` of the profile: `anchorHeight ≤ next − K_min`, and the transfer's deadline
   `anchorHeight + W` leaves at least `minBlocksLeft` blocks after `next`. The root `R[anchorHeight]`
   comes from the relayer's indexer (`/roots`).
4. **Nothing spent twice.** Neither nullifier is in the indexer's full list (`/nullifiers`, read whole,
   at most a few seconds old), nor in a transfer the relayer has queued or published. The same transfer submitted twice
   is the same transfer; another one that shares a nullifier with a queued one is refused.
5. **Its fee.** The relayer tries to open each output with its incoming viewing key (`SPEC-NOTES.md`
   §4). An output pays it when it opens, names a ticker, and hashes to its own leaf with the opening
   it gives; the ticker must be one the relayer prices, and the amount at least its fee.
6. **The proof**, last: the pinned PLONK verifier (`indexer/src/adapters/plonk.js`) over the nine
   public inputs of `SPEC-WIRE.md` §4: `R[anchorHeight]`, the nullifiers, the three leaves, the
   `bodyHash` of the envelope's bytes before the proof, and `vPub = tPub = 0`.

Why that is enough for its fee: the fee note's leaf is a public input of the proof and is appended to
the tree when the transfer is accepted; the opening hashes to that leaf, so the note exists and the
relayer's keys spend it. The envelope cannot be changed: `bodyHash` covers every byte before the proof
and the proof covers `bodyHash`.

What it cannot check, and what it costs (§4): a spend of the same notes that is in the mempool but
not yet in a block, or one handed to another relayer. Just before publishing, it reads the indexer's
nullifiers and the tip again, and leaves out what was spent or ran out of time meanwhile.

## 3. How it batches

A batch is one transaction whose input 0 carries every envelope (`SPEC-WIRE.md` §3), in two
transactions as for a single spend:

- **commit**: the relayer's coins pay one taproot output whose single leaf is the tapscript below,
  worth the reveal's fee and a dust output, and the change goes back to the relayer;
- **reveal**: spends that output by the script path. Its witness is `[sig, tapscript, control]`,

  ```
  <E> OP_CHECKSIG
  OP_0 OP_IF "SH20" <pushes of at most 520 bytes> OP_ENDIF      the first transfer
  OP_0 OP_IF "SH20" <pushes of at most 520 bytes> OP_ENDIF      the second
  …
  ```

  with a fresh one-time key `E`, and its one output returns what the fee leaves to the relayer.

The envelopes apply in the order of the tapscript, each accepted or refused alone, against the state
the ones before it left. The reference relayer puts them in the order they reached it.

**When.** The queue is published when it holds `maxBatch` transfers (10 by default), when its oldest
has waited `maxWaitSeconds` (600), or when one of its transfers has fewer than `minBlocksLeft` blocks
before its deadline. A transfer still queued at its deadline is dropped.

**Sizes** (`circuit/README.md`, "Batches and the 150 vB target"): the reveal of `n` transfers is
`(515 + 840 n) / 4` vB, 339 vB for one and 2,229 vB for ten; the commit, one key-path input and two
outputs, is 154 vB more, shared by the batch. Each transfer of a batch of ten costs the relayer
about 238 vB of fees. The reference relayer's regtest run (`relayer/dev/regtest.js`) prints the sizes
Bitcoin Core accepted: for a batch of two, a reveal of 549 vB (`(515 + 1,680) / 4`) and a commit of
154 vB, 351.5 vB a transfer.

**Its price.** A relayer sets one fee per ticker it takes, in that ticker, and publishes it at
`/info`. What the fee must be worth is its BTC cost above at the fee rate of the day; how a token is
priced in BTC is the relayer's business (the market's listings give one price).

## 4. What a relayer sees, and what it does not

It sees:

- the envelope, which everyone sees once it is published;
- when it was handed over, and from which network address, unless the sender uses Tor or another
  relay: this is the link a relayer could keep, and the one a sender should cut;
- the ticker of the transfer and the fee: its own output opens to it, and the five notes of a spend
  share their ticker;
- which of its own batches each transfer went into.

It does not see the amount of the two other outputs, the recipient, the sender's sh20 address, the
change, or which notes were spent: a nullifier says nothing about the leaf it spends, to the relayer
as to anyone. Two transfers from the same sender look like two transfers from two senders, except by
their timing and their network address.

It cannot take anything: the outputs are fixed by the signed body and the proof. It can delay a
transfer, drop it, publish it in any order among others, or refuse a ticker. Whoever watches the
chain learns that a relayer published these transfers (its coins pay the commits), not who handed
them over.

Wire v0.4 (`circuit/README.md`, "The transfer body of wire v0.4, on paper") would make the relayer's
output a bare leaf, its opening handed to the relayer with the envelope: the relayer would learn the
same things, and checking its fee would mean checking that opening against the leaf instead of
opening a ciphertext.

## 5. When a relayer drops or delays a transfer

A TRANSFER is not bound to its transaction (`SPEC-WIRE.md` §3): whoever holds its bytes can publish it,
alone or in any batch, until block `anchorHeight + W` or until one of its nullifiers is spent. So a
sender whose relayer is slow or silent can:

1. **Publish it itself**, with its own Bitcoin wallet, as an ordinary transfer (the vault's commit and
   reveal). It is the same transfer: the recipient is paid, and so is the relayer's fee output, which
   is in the envelope. The sender's coins then show again who sent it.
2. **Make a new transfer of the same notes** (to another relayer, with a fee to that one, or alone).
   This does not cancel the first one: whichever is mined first applies, the other is refused
   (its nullifiers are spent). If the first relayer publishes late and its batch is mined first, the
   first transfer is the one that counts, with its recipient and its fee. A sender who wants the
   second to win publishes it at once.
3. **Wait.** Past block `anchorHeight + W` no indexer accepts it, and the notes it spends are the
   sender's again. A wallet counts them back only once that block is a few blocks deep and its
   indexers agree that none of their nullifiers was recorded. The vault does this today for the
   spends it published itself (`vault/src/send.js`, `refusedSpend`), not yet for one handed to a
   relayer.

Another relayer does not take the same envelope: its fee output pays the first relayer, not it.

A transfer is sent once its nullifiers are recorded by the indexers, never before, whatever a relayer
answers.

## 6. What a relayer risks

- **Spends it could not see.** A sender can hand the same notes to two relayers, or spend them
  itself, after the relayer checked them: one of the two envelopes is refused and its bytes are paid
  for anyway. Each attempt costs the sender a proof and a real spend; a relayer publishes soon and
  can limit what it takes from one address.
- **A copy of its reveal.** Anyone who sees the reveal in the mempool can copy its envelopes into a
  transaction of their own. Whichever is mined first applies the transfers; the relayer's fee notes
  are in the envelopes either way, and only its BTC fee is lost if the copy wins.
- **Its keys.** The reference relayer holds two secrets on its machine: twelve words for its sh20
  address, whose notes the vault spends once restored from them, and a Bitcoin key for its coins.

## 7. The reference relayer

`relayer/` (Node ≥ 20, zero dependencies) does what §1 to §3 say, against one indexer of the profile
it runs on (`indexer/bin/follow.js`, its own: the relayer trusts it for roots, nullifiers, the tip and
the profile's `W` and `K_min`) and one Esplora. Its queue lives in memory: a restart drops what was
queued, and the senders fall back on §5. It reuses the code that is checked elsewhere: the indexer's
codec and PLONK verifier, the scanning of `circuit/js`, and the vault's Bitcoin and taproot code (BIP340
signatures by the constant-time code of `vault/src/secp256k1.js`).

Not done yet: the vault sending through a relayer; a view of the mempool; limits per address; a queue
that survives a restart; Tor.
