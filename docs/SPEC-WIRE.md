# SH-20 wire format and acceptance rules — draft v0.2

Status: draft. Nothing here is activated on any network. This file is normative for
`indexer/src/`; the design rationale lives in [`DESIGN.md`](DESIGN.md).

Changes from v0.1: tokens are named by their ticker everywhere. MINT, BURN and LIST carry `ticker(4)`
instead of an indexer-assigned `tokenNum(4)` (same size), and the asset id inside notes and proofs is
`t = tickerT(ticker)`. A wallet can therefore check on chain which token a mint or a listing is for.

## 1. Primitives

| Item | Definition |
| --- | --- |
| Field `Fr` | BN254 scalar field, `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| `H(a, b)` | Poseidon with 2 inputs, circomlib parameters (t = 3, R_F = 8, R_P = 57, x^5). `H(1, 2) = 7853200120776062878684798364095072458815029376092732009249414926327459813530` |
| `SHA256` | SHA-256 |
| Signatures | BIP340 Schnorr over secp256k1 |
| Integers on the wire | little-endian |
| Field elements on the wire | 32 bytes, little-endian, value `< r` (anything else is rejected) |

## 2. Notes and the shared tree

```
TAG_LEAF = SHA256("sh20/v0/leaf") mod r
leaf     = H( H( H(TAG_LEAF, t), v ), H(npk, rho) )
```

- `t` = `tickerT(ticker)` = the ticker's 4 ASCII bytes read as a big-endian u32 (`"GENE"` = `0x47454e45`),
  `v` = amount (u64), `npk` = note public key, `rho` = random field element.
- `t = 0` is reserved for native BTC; no valid ticker maps to it (the smallest is `"0000"` = `0x30303030`).
- One append-only tree for every ticker: depth 32, nodes `H(left, right)`, empty leaf `0`,
  `Z[0] = 0`, `Z[i+1] = H(Z[i], Z[i])`. `R[h]` = root after block `h`.
- A **public opening** is `npk (32) ‖ rho (32)` = 64 bytes. For public notes the indexer computes the leaf.

## 3. Carriers

A transaction carries **at most one** envelope. Two envelopes of any kind reject the transaction.

- **OP_RETURN**: an output `OP_RETURN <push>` with exactly one minimal push whose data starts with `SH20`.
- **Witness**: the tapscript of input 0 (script-path spend; annex ignored) contains
  `OP_0 OP_IF <push "SH20"> <push>... OP_ENDIF`; each push is minimal and at most 520 bytes;
  the envelope is `"SH20" ‖ concat(pushes)`.

Proof-carrying envelopes (~2.4 KB with the pinned Halo2 proof) use the witness carrier.

## 4. Envelopes

Header (6 bytes): `"SH20" (4) ‖ version 0x00 (1) ‖ type (1)`. Unknown version: ignored. Unknown type: rejected.
Types `0x08`–`0x0f` are reserved for extensions (aggregated batches; a BTC entry and exit once Bitcoin can enforce one).
After parsing, re-serialising must give the same bytes; trailing bytes are rejected.

| Type | Code | Body after the header | Bytes |
| --- | --- | --- | --- |
| DEPLOY | 0x01 | `ticker(4) max(8) lim(8) pre(8) start(4) end(4) unlock(4) price(8) payMode(1) psLen(1) payScript(psLen) [team opening(64) if pre > 0] [spend if bytes remain]` | 120 genesis with team; + spend |
| MINT | 0x02 | `ticker(4) opening(64)` | 74 |
| TRANSFER | 0x03 | `spend` | 2,435 with a 2,080-byte proof |
| BURN | 0x04 | `ticker(4) vPub(8) spend` | 2,447 |
| LIST | 0x05 | `ticker(4) amount(8) price(8) lockVout(1) psLen(1) payScript(psLen) spend` | 2,457 + payScript |
| TAKE | 0x06 | `opening(64)` | 70 |
| CLAIM | 0x07 | `listTxid(32) opening(64) sig(64)` | 166 |

- `ticker`: 4 ASCII characters `[A-Z0-9]`, in every type that carries one; anything else is rejected. `payMode`: 0 none, 1 burn, 2 pay to `payScript`.
  `payScript` (≤ 34 bytes) is present only with payMode 2. `listTxid`: txid in display (RPC) byte order.

**Spend section**

```
anchorHeight(4) ‖ nf0(32) ‖ nf1(32) ‖ 3 × [ leaf(32) ‖ pk_eph(33) ‖ ct(28) ] ‖ proofLen(2) ‖ proof(proofLen)
```

- `pk_eph`: compressed secp256k1 point (prefix 02/03). `ct`: amount u64 ‖ ticker (4) ‖ 16-byte tag, sealed to the recipient.
- `1 ≤ proofLen ≤ 4096`.
- `body` = every envelope byte before `proofLen`; `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r`.

**Verifier inputs** (public inputs of the spend circuit): `R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`.

The circuit must prove: both inputs are notes in the tree under the root (an input with `v = 0` is a dummy and skips
membership); the nullifiers are derived from the owner's secret key, the leaf and its position; all five notes share one
private `t`; every `v` and `vPub` fits in 64 bits; `v_in0 + v_in1 = v_out0 + v_out1 + v_out2 + vPub`;
`vPub × (t − tPub) = 0`; each output leaf follows §2; the inputs are authorised by the owner over `bodyHash`.

## 5. Acceptance rules

Block `H`, profile constants `W = 100`, `K_min = 1`, `D` (deploy burn), activation height `A`. Nothing before `A` is read.

**Every spend**: `H − W ≤ anchorHeight ≤ H − K_min`; root known (`anchorHeight < A` uses the empty root); nullifiers
non-zero, distinct, never seen; output leaves non-zero; room in the tree; proof valid. Effect: record nullifiers, append the 3 leaves.

| Type | Accepted when | Effect |
| --- | --- | --- |
| DEPLOY | ticker never deployed; `max > 0`, `lim > 0`, `pre < max`, `(max − pre) mod lim = 0`; `start > H`; `end = 0` or `end ≥ start`; `unlock ≥ start`; payMode 0 ⇔ `price = 0`. First accepted DEPLOY = genesis and has no spend; every later one has a spend with `vPub = D`, `tPub = t(genesis)` | token recorded under its ticker; `burned[genesis] += D`; team note scheduled for block `unlock` |
| MINT | `ticker` deployed; `start ≤ H`; `end = 0` or `H ≤ end`; mints `< (max − pre) / lim`; paid in the same tx: payMode 1 = OP_RETURN outputs carry ≥ `price` sats, payMode 2 = outputs to `payScript` total ≥ `price` | leaf `(t, lim, npk, rho)`; mints + 1 |
| TRANSFER | spend with `vPub = tPub = 0` | — |
| BURN | `ticker` deployed; `vPub > 0`; spend with `tPub = t(ticker)` | `burned[ticker] += vPub` |
| LIST | `ticker` deployed; `amount > 0`, `price > 0`; output `lockVout` is P2TR with ≥ 330 sats; spend with `vPub = amount`, `tPub = t(ticker)` | listing ACTIVE, lock = `(txid, lockVout)` |
| TAKE | the tx spends the lock of an ACTIVE listing (first in input order) | leaf `(t, amount, npk, rho)`; SOLD if outputs to `payScript` total ≥ `price`, else CANCELLED |
| CLAIM | listing is CLOSED; BIP340 signature by the lock's output key over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk ‖ rho)` | leaf `(t, amount, npk, rho)`; CLAIMED |

A rejected envelope changes nothing; sats it paid are not returned.

## 6. Block processing and digest

1. If `H ≥ A`: append team notes whose `unlock = H` (by ticker, in byte order), then for each transaction in block order:
   note the ACTIVE listings whose lock it spends; apply its envelope; set any of those still ACTIVE to CLOSED.
2. Record `R[H]`.
3. `digest_H = SHA256(digest_{H−1} ‖ u32le(H) ‖ R[H] (32, LE) ‖ SHA256(events_H))`, `digest_start = SHA256("sh20-v0")`,
   `events_H` = the JSON list of accepted events in order (see `src/indexer.js`; to be frozen as a byte format before activation).

Reorgs: roll back to the fork point (per-block undo log) and replay.

## 7. Not final

The spend circuit and its pinned verifying key; the `ct` sealing; the profile constants (`A`, `D`, network);
the canonical event encoding inside the digest.
