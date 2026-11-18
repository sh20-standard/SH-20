# SH-20 wire format and acceptance rules — draft v0.3

Status: draft. Nothing here is activated on any network. This file is normative for
`indexer/src/`; the design rationale lives in [`DESIGN.md`](DESIGN.md).

Changes from v0.2: `pk_eph` is a 32-byte X25519 public key (was a 33-byte secp256k1 point), so wallets can scan with
the native X25519 of WebCrypto; the spend section loses `proofLen`, since the proof always has 480 bytes. A TRANSFER is
830 bytes. A public opening is `npk` alone and public notes use `rho = 0` (a fresh `npk` already makes each one unique,
and nothing in a public note is hidden): a MINT is 42 bytes instead of 74, about 32 vB less per mint. Sealing and scanning are specified for wallets in [`SPEC-NOTES.md`](SPEC-NOTES.md).
The events inside the digest have an exact byte encoding (§6) instead of JSON, and the GENESIS record commits to the
profile's rules, so a second implementation in any language can reproduce every digest.

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
  `v` = amount (u64), `npk` = note public key, `rho` = a field element (derived for sealed notes, `SPEC-NOTES.md` §3;
  `0` for public notes).
- `t = 0` is reserved for native BTC; no valid ticker maps to it (the smallest is `"0000"` = `0x30303030`).
- One append-only tree for every ticker: depth 32, nodes `H(left, right)`, empty leaf `0`,
  `Z[0] = 0`, `Z[i+1] = H(Z[i], Z[i])`. `R[h]` = root after block `h`.
- A **public opening** is `npk` (32 bytes). For public notes the indexer computes the leaf with `rho = 0`.

## 3. Carriers

A transaction carries **at most one** envelope. Two envelopes of any kind reject the transaction.

- **OP_RETURN**: an output `OP_RETURN <push>` with exactly one minimal push whose data starts with `SH20`.
- **Witness**: the tapscript of input 0 (script-path spend; annex ignored) contains
  `OP_0 OP_IF <push "SH20"> <push>... OP_ENDIF`; each push is minimal and at most 520 bytes;
  the envelope is `"SH20" ‖ concat(pushes)`.

Proof-carrying envelopes (830 bytes for a TRANSFER, with the pinned 480-byte proof) use the witness carrier.

## 4. Envelopes

Header (6 bytes): `"SH20" (4) ‖ version 0x00 (1) ‖ type (1)`. Unknown version: ignored. Unknown type: rejected.
Types `0x08`–`0x0f` are reserved for extensions (aggregated batches; a BTC entry and exit once Bitcoin can enforce one).
After parsing, re-serialising must give the same bytes; trailing bytes are rejected.

| Type | Code | Body after the header | Bytes |
| --- | --- | --- | --- |
| DEPLOY | 0x01 | `ticker(4) max(8) lim(8) pre(8) start(4) end(4) unlock(4) price(8) payMode(1) psLen(1) payScript(psLen) [team opening(32) if pre > 0] [spend if bytes remain]` | 88 with a team opening; + 824 with a spend |
| MINT | 0x02 | `ticker(4) opening(32)` | 42 |
| TRANSFER | 0x03 | `spend` | 830 |
| BURN | 0x04 | `ticker(4) vPub(8) spend` | 842 |
| LIST | 0x05 | `ticker(4) amount(8) price(8) lockVout(1) psLen(1) payScript(psLen) spend` | 852 + payScript |
| TAKE | 0x06 | `opening(32)` | 38 |
| CLAIM | 0x07 | `listTxid(32) opening(32) sig(64)` | 134 |

- `ticker`: 4 ASCII characters `[A-Z0-9]`, in every type that carries one; anything else is rejected. `payMode`: 0 none, 1 burn, 2 pay to `payScript`.
  `payScript` (≤ 34 bytes) is present only with payMode 2. `listTxid`: txid in display (RPC) byte order.

**Spend section**

```
anchorHeight(4) ‖ nf0(32) ‖ nf1(32) ‖ 3 × [ leaf(32) ‖ pk_eph(32) ‖ ct(28) ] ‖ proof(480)
```

- `pk_eph`: X25519 public key (RFC 7748), 32 bytes; indexers accept any 32 bytes. `ct`: AES-256-GCM of amount u64 ‖ ticker (4),
  with its 16-byte tag, sealed to the recipient (`SPEC-NOTES.md` §3). Indexers never open it.
- `proof`: exactly 480 bytes (the pinned PLONK proof, below), so a spend section is 824 bytes. There is no length field.
- `body` = every envelope byte before the proof; `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r`.

**Verifier inputs** (public inputs of the spend circuit, in this order): `R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`.

**The relation.** A proof shows knowledge of an asset id `t` (§2) and, for each of the two inputs, of `v, rho, nk, Ak, index`, a sibling
path and a signature, and for each of the three outputs of `v, npk, rho`, such that:

- input note: `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)` with `NK = nk·B8` and `0 ≤ nk < l`; `leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))`;
- membership: unless `v = 0`, `leaf` is at position `index < 2^32` of the tree with root `R[anchorHeight]`. An input with `v = 0`
  is a dummy: it skips membership only, and still has a nullifier and a signature;
- nullifier: `nf = Poseidon(nk, leaf, index)`;
- authorisation: an EdDSA-Poseidon signature `(R8, S)` under `Ak` over `bodyHash`: `S·B8 = R8 + h·8·Ak`,
  `h = Poseidon(R8.x, R8.y, Ak.x, Ak.y, bodyHash)` as its integer below `r`, `0 ≤ S < l`, and `4·Ak` has a non-zero x;
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
  `da847145dbc5aa847af92ce5696fbd60bd57e6fbdf0e077cc1b62a0ba302492d` (draft: it changes with any change to the circuit until frozen).
- Proof, 480 bytes: `A B C Z T1 T2 T3 Wxi Wxiw` (G1, 32 bytes each) then `a b c s1 s2 zω` (scalars, 32 bytes each).
  A G1 point is its x coordinate, little-endian, with bit 255 set when `y > q − y`; x must be below the base-field modulus `q`
  and on the curve, and the point at infinity has no encoding. A scalar is little-endian and below `r`. Anything else is invalid.
- Challenges: Keccak-256 over big-endian encodings (a point is `x ‖ y`, 32 bytes each), read as a big-endian integer mod `r`:
  `β = K(Qm Ql Qr Qo Qc S1 S2 S3 ‖ public inputs ‖ A B C)`, `γ = K(β)`, `α = K(β γ Z)`, `ξ = K(α T1 T2 T3)`,
  `v = K(ξ a b c s1 s2 zω)`, `u = K(Wxi Wxiw)`. This is the transcript of snarkjs' PLONK, whose verifier accepts these proofs.

## 5. Acceptance rules

Block `H`, profile constants `W = 100`, `K_min = 1`, `D` (deploy burn), activation height `A`. Nothing before `A` is read.

**Genesis token** (part of the profile, not a DEPLOY, so nobody can race for it): ticker `SH20`, `max = 21,000,000`,
`lim = 1,000`, `pre = 0` (no team allocation), payMode 0 and `price = 0` (free mint, network fees only),
`start = A`, `end = 0`. It exists from block `A` on; a DEPLOY of `SH20` is rejected like any taken ticker.

**Every spend**: `H − W ≤ anchorHeight ≤ H − K_min`; root known (`anchorHeight < A` uses the empty root); nullifiers
non-zero, distinct, never seen; output leaves non-zero; room in the tree; proof valid. Effect: record nullifiers, append the 3 leaves.

| Type | Accepted when | Effect |
| --- | --- | --- |
| DEPLOY | ticker never deployed; `max > 0`, `lim > 0`, `pre < max`, `(max − pre) mod lim = 0`; `start > H`; `end = 0` or `end ≥ start`; `unlock ≥ start`; payMode 0 ⇔ `price = 0`. If `D > 0`: a spend with `vPub = D`, `tPub = t("SH20")`; if `D = 0`: no spend | token recorded under its ticker; `burned[SH20] += D`; team note scheduled for block `unlock` |
| MINT | `ticker` deployed; `start ≤ H`; `end = 0` or `H ≤ end`; mints `< (max − pre) / lim`; paid in the same tx: payMode 1 = OP_RETURN outputs carry ≥ `price` sats, payMode 2 = outputs to `payScript` total ≥ `price` | leaf `(t, lim, npk, 0)`; mints + 1 |
| TRANSFER | spend with `vPub = tPub = 0` | — |
| BURN | `ticker` deployed; `vPub > 0`; spend with `tPub = t(ticker)` | `burned[ticker] += vPub` |
| LIST | `ticker` deployed; `amount > 0`, `price > 0`; output `lockVout` is P2TR with ≥ 330 sats; spend with `vPub = amount`, `tPub = t(ticker)` | listing ACTIVE, lock = `(txid, lockVout)` |
| TAKE | the tx spends the lock of an ACTIVE listing (first in input order) | leaf `(t, amount, npk, 0)`; SOLD if outputs to `payScript` total ≥ `price`, else CANCELLED |
| CLAIM | listing is CLOSED; BIP340 signature by the lock's output key over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)` | leaf `(t, amount, npk, 0)`; CLAIMED |

A rejected envelope changes nothing; sats it paid are not returned.

## 6. Block processing and digest

1. If `H ≥ A`: in the first block read (`H = A`), create the genesis token (event `GENESIS`); append team notes whose `unlock = H` (by ticker, in byte order), then for each transaction in block order:
   note the ACTIVE listings whose lock it spends; apply its envelope; set any of those still ACTIVE to CLOSED.
2. Record `R[H]`.
3. `digest_H = SHA256(digest_{H−1} ‖ u32le(H) ‖ R[H] (32, LE) ‖ SHA256(events_H))`, `digest_start = SHA256("sh20-v0")`,
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
| MINT | 0x02 | `ticker` ‖ `v`(u64) ‖ `pos` | 49 |
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
