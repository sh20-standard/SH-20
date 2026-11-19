# SH-20 wire format and acceptance rules — draft v0.3

Status: draft. Nothing here is activated on any network. This file is normative for every SH-20 indexer (the
reference in `indexer/`, and `indexer-rs/`, written from this text alone); the design rationale lives in [`DESIGN.md`](DESIGN.md).

Changes from v0.2: `pk_eph` is a 32-byte X25519 public key (was a 33-byte secp256k1 point), so wallets can scan with
the native X25519 of WebCrypto; the spend section loses `proofLen`, since the proof always has 480 bytes. A TRANSFER is
830 bytes. A public opening is `npk` alone and public notes use `rho = 0` (a fresh `npk` already makes each one unique,
and nothing in a public note is hidden): a MINT is 42 bytes instead of 74, about 32 vB less per mint. Sealing and scanning are specified for wallets in [`SPEC-NOTES.md`](SPEC-NOTES.md).
The events inside the digest have an exact byte encoding (§6) instead of JSON, and the GENESIS record commits to the
profile's rules, so a second implementation in any language can reproduce every digest.
A MINT may carry a count `k` (2 to 10) as one more byte: one note of `k × lim` for `k × price` (§5).
Each ticker has a turnstile, `pool[ticker]`: no BURN, LIST or DEPLOY burn may take out more than went in (§5).
A LIST carries the x-only key of its lock output (`lockKey`, 32 bytes) in its signed body: a copy of the envelope in
another transaction can no longer point its lock at a key the copier controls (§5).
Every point a clean-room second indexer found open (`SPEC-GAPS.md`) is now settled here: what a carrier is and which
envelopes count (§3), which fields are field elements and where `body` starts (§4), blocks below `A` (§6), and the edge
cases of §5 ("Details"). The vectors give `bodyHash` for every spend, the nine verifier inputs of every spend in the
scenario, carrier cases, a CLAIM with its signature, and a listing CLOSED then claimed and one CANCELLED.

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
| Field elements on the wire | 32 bytes, little-endian, value `< r` (anything else is rejected). §4 lists which fields are field elements |
| `SHA256(…) mod r` | the 32 bytes of the digest read as a big-endian integer, reduced mod `r` |

## 2. Notes and the shared tree

```
TAG_LEAF = SHA256("sh20/v0/leaf") mod r
leaf     = H( H( H(TAG_LEAF, t), v ), H(npk, rho) )
```

- `t` = `tickerT(ticker)` = the ticker's 4 ASCII bytes read as a big-endian u32 (`"GENE"` = `0x47454e45`),
  `v` = amount (u64), `npk` = note public key, `rho` = a field element (derived for sealed notes, `SPEC-NOTES.md` §3;
  `0` for public notes).
- `t = 0` is reserved for native BTC; no valid ticker maps to it (the smallest is `"0000"` = `0x30303030`).
- One append-only tree for every ticker: depth 32, nodes `H(left, right)`, empty leaf `0`,
  `Z[0] = 0`, `Z[i+1] = H(Z[i], Z[i])`. `R[h]` = root after block `h`.
- A **public opening** is `npk` (32 bytes). For public notes the indexer computes the leaf with `rho = 0`.

## 3. Carriers

A **minimal push** is a push in Bitcoin's minimal form (`CheckMinimalPush`): no data is `OP_0`; the single byte
`0x01`…`0x10` is `OP_1`…`OP_16` and `0x81` is `OP_1NEGATE`; any other data of `n` bytes is the opcode `n` for `n ≤ 75`,
`OP_PUSHDATA1` for `n ≤ 255`, `OP_PUSHDATA2` for `n ≤ 65,535`, and `OP_PUSHDATA4` above. Any other way of pushing the same
data is not minimal. (A witness push of more than 520 bytes is invalid in Bitcoin; an OP_RETURN script can be longer.)
A script is read as opcodes from its first byte; a script with a push that runs past its end carries no envelope.

- **OP_RETURN**: an output whose script is exactly `OP_RETURN` followed by one minimal push, whose data starts with
  `SH20`. The envelope is that data. Every output is looked at.
- **Witness**: the witness of input 0, read alone (the spent output is not looked at): if it has at least two elements
  and the last starts with `0x50`, that last one (the annex) is removed; at least two must remain; the last is a control
  block of `33 + 32m` bytes, `m ≤ 128`, whose first byte is `0xc0` or `0xc1`; the element before it is the tapscript.
  An envelope starts at any opcode `OP_0` followed by `OP_IF`, then the push `04 53 48 32 30` (`"SH20"`, nothing else),
  then zero or more minimal pushes of at most 520 bytes each, then `OP_ENDIF`. The envelope is `"SH20"` followed by the
  data of those pushes. If anything else comes before `OP_ENDIF` (another opcode, a push that is not minimal or longer
  than 520 bytes, the end of the script), no envelope starts at that `OP_0`, and the search goes on from the next opcode.
  After an envelope, it goes on after its `OP_ENDIF`. Whether the branch would run is not looked at.

Anything that does not match a carrier exactly carries no envelope. Every envelope found counts, except one whose fifth
byte (the version) exists and is not `0x00`: it belongs to another version, is not counted and has no effect.
A transaction with **one** counted envelope applies it (§5). With **two or more**, none is applied: the transaction is
refused (the listings whose locks it spends still close, §6). Any type may use either carrier; a proof-carrying envelope
(830 bytes for a TRANSFER) costs four times more in an OP_RETURN than in a witness. A coinbase transaction is read like
any other for its OP_RETURN outputs; the witness of its input is not looked at.

## 4. Envelopes

Header (6 bytes): `"SH20" (4) ‖ version 0x00 (1) ‖ type (1)`. Another version is not counted (§3). Unknown type, or an
envelope too short for its header (`"SH20"` alone, `"SH20" 00`): counted and rejected.
Types `0x08`–`0x0f` are reserved for extensions (aggregated batches; a BTC entry and exit once Bitcoin can enforce one).
After parsing, re-serialising must give the same bytes; trailing bytes are rejected. (With fixed sizes, `k` never 0 or
1, and optional parts that depend on `pre` and on the bytes left, no byte string has two parses: this restates canonicity.)

| Type | Code | Body after the header | Bytes |
| --- | --- | --- | --- |
| DEPLOY | 0x01 | `ticker(4) max(8) lim(8) pre(8) start(4) end(4) unlock(4) price(8) payMode(1) psLen(1) payScript(psLen) [team opening(32) if pre > 0] [spend if bytes remain]` | 88 with a team opening; + 824 with a spend |
| MINT | 0x02 | `ticker(4) opening(32) [k(1)]` | 42, or 43 with `k` |
| TRANSFER | 0x03 | `spend` | 830 |
| BURN | 0x04 | `ticker(4) vPub(8) spend` | 842 |
| LIST | 0x05 | `ticker(4) amount(8) price(8) lockVout(1) lockKey(32) psLen(1) payScript(psLen) spend` | 884 + payScript |
| TAKE | 0x06 | `opening(32)` | 38 |
| CLAIM | 0x07 | `listTxid(32) opening(32) sig(64)` | 134 |

- `ticker`: 4 ASCII characters `[A-Z0-9]`, in every type that carries one; anything else is rejected. `payMode`: 0 none, 1 burn,
  2 pay to `payScript`; any other value is rejected.
- `payScript`: 1 to 34 bytes, required with payMode 2 and in a LIST; with payMode 0 or 1, `psLen` is 0. An empty
  `payScript` with payMode 2 or in a LIST, and a longer one, are rejected. `listTxid`: txid in display (RPC) byte order.
- **Field elements** (32 bytes, little-endian, `< r`, else rejected): every opening (`npk` of MINT, TAKE, CLAIM and the
  DEPLOY team opening), `nf0`, `nf1` and the three output leaves. Opaque bytes: `pk_eph`, `ct`, `lockKey`, `listTxid`,
  `sig`, `proof`.
- `lockKey`: the x-only output key of the lock. It is part of `body`, so the proof's signature covers it; `lockVout` alone
  would let anyone copy the envelope into a transaction whose output `lockVout` they control, and cancel the listing to themselves.
- `k`: the number of mints in one MINT, 2 to 10 (`MINT_BATCH_MAX`); a single mint is written without the byte, so `k = 0`,
  `k = 1` and `k > 10` are rejected.

**Spend section**

```
anchorHeight(4) ‖ nf0(32) ‖ nf1(32) ‖ 3 × [ leaf(32) ‖ pk_eph(32) ‖ ct(28) ] ‖ proof(480)
```

- `pk_eph`: X25519 public key (RFC 7748), 32 bytes; indexers accept any 32 bytes. `ct`: AES-256-GCM of amount u64 ‖ ticker (4),
  with its 16-byte tag, sealed to the recipient (`SPEC-NOTES.md` §3). Indexers never open it.
- `proof`: exactly 480 bytes (the pinned PLONK proof, below), so a spend section is 824 bytes. There is no length field.
- `body` = the envelope from its first byte (`"SH20"`, so the header and type are signed too) up to the proof, excluded;
  `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r` (350 bytes of `body` for a TRANSFER).

**Verifier inputs** (public inputs of the spend circuit, in this order): `R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`.

**The relation.** A proof shows knowledge of an asset id `t` (§2) and, for each of the two inputs, of `v, rho, nk, Ak, index`, a sibling
path and a signature, and for each of the three outputs of `v, npk, rho`, such that:

- input note: `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)` with `NK = nk·B8` and `0 ≤ nk < l`; `leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))`;
- membership: unless `v = 0`, `leaf` is at position `index < 2^32` of the tree with root `R[anchorHeight]`. An input with `v = 0`
  is a dummy: it skips membership only, and still has a nullifier and a signature;
- nullifier: `nf = Poseidon(nk, leaf, index)`;
- authorisation: an EdDSA-Poseidon signature `(R8, S)` under `Ak` over `bodyHash`: `Ak` and `R8` are points of the curve,
  `S·B8 = R8 + h·8·Ak`, `h = Poseidon(R8.x, R8.y, Ak.x, Ak.y, bodyHash)` as its integer below `r`, `0 ≤ S < l`, and `4·Ak` has a non-zero x;
- output note: `leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))` with the same `t`;
- every `v` and `vPub` is below `2^64`, and `v_in0 + v_in1 = v_out0 + v_out1 + v_out2 + vPub`;
- `vPub × (t − tPub) = 0`.

`Poseidon(n inputs)` is circomlib's (width n + 1, R_F = 8, R_P = 57, 56, 60, 60 for n = 2, 3, 4, 5). BabyJubJub is
`168700·x² + y² = 1 + 168696·x²·y²` over `Fr`; `l = 2736030358979909402780800718157159386076813972158567259200215660948447373041`
is the order of its prime subgroup and `B8 = (5299619240641551281634865583518297030282874472190772894086521144482721001553,
16950150798460657717958625567821834550301663161624707787222815936182638968203)` its generator.

**The proof.** PLONK (ePrint 2019/953, section 8: three wires, selectors `qM qL qR qO qC`, coset shifts `k1 = 2`, `k2 = 3`) over
BN254 with KZG commitments, on a domain of 2^17 rows. The reference circuit and verifier are in `circuit/`.

- SRS: the first 131,078 G1 powers and `τ·G2` of Hermez `powersOfTau28_hez_final_18.ptau`
  (BLAKE2b-512
  `7e6a9c2e5f05179ddfc923f38f917c9e6831d16922a902b0b4758b8e79c2ab8a81bb5f29952e16ee6c5067ed044d7857b5de120a90704c1d3b637fd94b95b13e`,
  as listed by snarkjs). No other setup exists: the keys are a deterministic function of the
  circuit and this SRS.
- Verifying key: 712 bytes, `power(4) nPublic(4) k1(32) k2(32) Qm Ql Qr Qo Qc S1 S2 S3 (64 each: x ‖ y) X2(128)`.
  Its digest `SHA256("sh20/v0/vk" ‖ key)` is pinned:
  `f48b551776188b652259ac42ff3d064ea61e9dd0d4b48addb825085ab1237745` (draft: it changes with any change to the circuit until frozen).
- Proof, 480 bytes: `A B C Z T1 T2 T3 Wxi Wxiw` (G1, 32 bytes each) then `a b c s1 s2 zω` (scalars, 32 bytes each).
  A G1 point is its x coordinate, little-endian, with bit 255 set when `y > q − y`; x must be below the base-field modulus `q`
  and on the curve, and the point at infinity has no encoding. A scalar is little-endian and below `r`. Anything else is invalid.
- Challenges: Keccak-256 over big-endian encodings (a point is `x ‖ y`, 32 bytes each), read as a big-endian integer mod `r`:
  `β = K(Qm Ql Qr Qo Qc S1 S2 S3 ‖ public inputs ‖ A B C)`, `γ = K(β)`, `α = K(β γ Z)`, `ξ = K(α T1 T2 T3)`,
  `v = K(ξ a b c s1 s2 zω)`, `u = K(Wxi Wxiw)`. This is the transcript of snarkjs' PLONK, whose verifier accepts these proofs.

## 5. Acceptance rules

Block `H`, profile constants `W = 100`, `K_min = 1`, `D` (deploy burn), activation height `A`. No envelope below `A` is
read, and blocks below `A` have no root and no digest (§6).

**Genesis token** (part of the profile, not a DEPLOY, so nobody can race for it): ticker `SH20`, `max = 21,000,000`,
`lim = 1,000`, `pre = 0` (no team allocation), payMode 0 and `price = 0` (free mint, network fees only),
`start = A`, `end = 0`. It exists from block `A` on; a DEPLOY of `SH20` is rejected like any taken ticker.

**Every spend**: `max(0, H − W) ≤ anchorHeight ≤ H − K_min`; root known (`anchorHeight < A` uses the empty root); nullifiers
non-zero, distinct, never seen; output leaves non-zero (they may repeat, within the spend or a leaf already in the tree);
room for 3 leaves in the tree; proof valid, with the nine inputs of §4. Effect: record nullifiers, append the 3 leaves.
The proof is checked **last**, once every other condition of the envelope holds (those of its type in the table below,
the turnstile, and the ones above): a refusal has no effect either way, but this fixes which spends reach the verifier,
and the vectors list exactly those (`scenario.verifierCalls`).

**Turnstile.** Each ticker has a counter `pool[ticker]`, 0 when the token is created: what entered the shielded pool in
public minus what left it in public. MINT adds `m × lim`, a team unlock adds `pre`, TAKE and CLAIM add the listing's
`amount`; BURN subtracts `vPub`, LIST its `amount`, and a DEPLOY with `D > 0` subtracts `D` from `pool[SH20]`. A spend whose
`vPub` is larger than `pool[tPub's ticker]` is rejected, before its proof is checked. Every term is public already, so the
counter reveals nothing. It bounds what a soundness bug in the circuit could do: hidden notes might be forged, but no more
of a ticker can ever come back into the open than was issued. At every block, for every ticker,
`pool + Σ amount of ACTIVE and CLOSED listings + burned = m·lim over all mints + pre if unlocked`.

| Type | Accepted when | Effect |
| --- | --- | --- |
| DEPLOY | ticker never deployed; `max > 0`, `lim > 0`, `pre < max`, `(max − pre) mod lim = 0`; `start > H`; `end = 0` or `end ≥ start`; `unlock ≥ start`; payMode 0 ⇔ `price = 0`. If `D > 0`: `D ≤ pool[SH20]` and a spend with `vPub = D`, `tPub = t("SH20")`; if `D = 0`: no spend | token recorded under its ticker, `pool = 0`; `burned[SH20] += D`, `pool[SH20] −= D`; team note scheduled for block `unlock` |
| MINT | `ticker` deployed; `start ≤ H`; `end = 0` or `H ≤ end`; `left = (max − pre) / lim − mints > 0`; with `m = min(k, left)` (`k = 1` without the byte), paid in the same tx: payMode 1 = OP_RETURN outputs carry ≥ `m × price` sats, payMode 2 = outputs to `payScript` total ≥ `m × price` | one leaf `(t, m × lim, npk, 0)`; mints + `m`; `pool += m × lim` |
| TRANSFER | spend with `vPub = tPub = 0` | — |
| BURN | `ticker` deployed; `0 < vPub ≤ pool[ticker]`; spend with `tPub = t(ticker)` | `burned[ticker] += vPub`, `pool −= vPub` |
| LIST | `ticker` deployed; `0 < amount ≤ pool[ticker]`, `price > 0`; output `lockVout` is `OP_1 <lockKey>` (P2TR to `lockKey`) with ≥ 330 sats; spend with `vPub = amount`, `tPub = t(ticker)` | listing ACTIVE, lock = `(txid, lockVout)`; `pool −= amount` |
| TAKE | the tx spends the lock of an ACTIVE listing (first in input order) | leaf `(t, amount, npk, 0)`; `pool += amount`; SOLD if outputs to `payScript` total ≥ `price`, else CANCELLED |
| CLAIM | listing is CLOSED; BIP340 signature by `lockKey` over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)` | leaf `(t, amount, npk, 0)`; `pool += amount`; CLAIMED |

A rejected envelope changes nothing; sats it paid are not returned.

**Details.**

- **Payment.** payMode 1 counts the value of every output whose script starts with `OP_RETURN` (`0x6a`), the envelope's
  own included; payMode 2 and TAKE count every output whose script equals `payScript`. Products and sums are exact
  integers (128 bits are enough): a price nobody can pay makes a mint impossible, never free.
- **DEPLOY.** `unlock ≥ start` holds even when `pre = 0` (write `unlock = start`). With `pre = 0` there is no team note and
  no TEAM_UNLOCK event. With `D = 0` a DEPLOY that carries a spend is rejected; with `D > 0` one without a spend is.
- **Room in the tree.** MINT, TAKE and CLAIM need one free leaf, a spend three; without it they are rejected. A team note
  that does not fit is dropped: no event, `pool` unchanged. (2^32 leaves: out of reach, but settled.)
- **Locks.** A lock is the output `lockVout` of the LIST transaction; its script is exactly `51 20 <lockKey>` (34 bytes)
  with at least 330 sats. Whether `lockKey` is a valid x-only key is not checked at LIST; if it is not, no CLAIM can
  succeed. A transaction that spends several locks: a TAKE takes the listing of the first such input, in input order; every
  other ACTIVE listing whose lock it spends is CLOSED, in input order, after the envelope's event. Closing does not depend
  on the envelope: a transaction with no envelope, a refused one or two of them still closes the locks it spends. A CLAIM
  in the transaction that spends the lock is refused, since the listing is still ACTIVE when the envelope applies.
- **CLAIM message.** `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)`, with `listTxid` and `npk` as their 32 bytes in the envelope
  (display order, and little-endian); this 32-byte hash is the BIP340 message, checked against `lockKey`.
- **Listings** are named by the txid of their LIST transaction, which is unique on a chain with BIP30 and BIP34. A LIST
  whose txid already names a listing (a chain built by hand) is refused.

## 6. Block processing and digest

Blocks below `A` are not processed: they have no root and no digest, and `digest_{A−1} = SHA256("sh20-v0")` whatever an
indexer read before `A`. For `H ≥ A`:

1. In block `A`, create the genesis token (event `GENESIS`). Append team notes whose `unlock = H` (by ticker, ascending
   byte order; `pool += pre`), then for each transaction in block order: note the ACTIVE listings whose lock it spends,
   in input order; apply its envelope (§3, §5); set any of those still ACTIVE to CLOSED.
2. Record `R[H]`.
3. `digest_H = SHA256(digest_{H−1} ‖ u32le(H) ‖ R[H] (32, LE) ‖ SHA256(events_H))`,
   `events_H` = the records of the block's accepted events, in the order they happen (genesis, team unlocks, then each
   transaction's envelope followed by the listings it closes), concatenated. A block with no event has an empty `events_H`.
   Rejected envelopes are not events.

Every record is `code(1) ‖ txid(32) ‖ payload`. `txid` is the transaction's id in display (RPC) byte order, and 32 zero bytes
for the two block events (GENESIS, TEAM_UNLOCK). Integers are little-endian, field elements 32 bytes little-endian,
tickers their 4 ASCII bytes, `pos` a u32 leaf position. `spent` = `nf0 ‖ nf1 ‖ pos0 ‖ pos1 ‖ pos2`: the two nullifiers and the
positions of the three output leaves (76 bytes). Each payload has one size for its code (DEPLOY: one per flag), so the
concatenation parses one way only.

| Event | Code | Payload | Record |
| --- | --- | --- | ---: |
| DEPLOY | 0x01 | `ticker` ‖ `0x00`, or `ticker` ‖ `0x01` ‖ `spent` (the burn of `D` when `D > 0`) | 38 / 114 |
| MINT | 0x02 | `ticker` ‖ `v`(u64, = `m × lim`) ‖ `pos` | 49 |
| TRANSFER | 0x03 | `spent` | 109 |
| BURN | 0x04 | `ticker` ‖ `vPub`(u64) ‖ `spent` | 121 |
| LIST | 0x05 | `ticker` ‖ `amount`(u64) ‖ `price`(u64) ‖ `spent` | 129 |
| TAKE | 0x06 | `listTxid`(32) ‖ outcome(1: SOLD = 1, CANCELLED = 2) ‖ `pos` | 70 |
| CLAIM | 0x07 | `listTxid`(32) ‖ `pos` | 69 |
| GENESIS | 0x80 | `ticker` ‖ `max`(u64) ‖ `lim`(u64) ‖ `D`(u64) ‖ `W`(u32) ‖ `K_min`(u32) | 69 |
| TEAM_UNLOCK | 0x81 | `ticker` ‖ `pre`(u64) ‖ `pos` | 49 |
| CLOSED | 0x82 | `listTxid`(32); `txid` is the transaction that spent the lock | 65 |

Envelope events reuse the envelope's type code. GENESIS carries the profile's rule constants, so two indexers run with
different profiles have different digests from the activation block on. `indexer/vectors/v0.3.json` gives `events_H`
for every block of its scenario.

Reorgs: roll back to the fork point (per-block undo log) and replay.

## 7. Not final

The verifying-key digest of §4 until the circuit is audited and frozen; the `ct` sealing; the profile constants
(`A`, `D`, network).
