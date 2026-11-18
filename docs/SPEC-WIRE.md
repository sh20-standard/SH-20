# SH-20 wire format and acceptance rules — draft v0.1

Status: draft. Nothing here is activated on any network. This file is normative for
`src/`; the design rationale lives in the SH-20 spec document.

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

- `t` = tokenNum (u32), `v` = amount (u64), `npk` = note public key, `rho` = random field element.
- One append-only tree for every ticker: depth 32, nodes `H(left, right)`, empty leaf `0`,
  `Z[0] = 0`, `Z[i+1] = H(Z[i], Z[i])`. `R[h]` = root after block `h`.
- A **public opening** is `npk (32) ‖ rho (32)` = 64 bytes. For public notes the indexer computes the leaf.

## 3. Carriers

A transaction carries **at most one** envelope. Two envelopes of any kind reject the transaction.

- **OP_RETURN**: an output `OP_RETURN <push>` with exactly one minimal push whose data starts with `SH20`.
- **Witness**: the tapscript of input 0 (script-path spend; annex ignored) contains
  `OP_0 OP_IF <push "SH20"> <push>... OP_ENDIF`; each push is minimal and at most 520 bytes;
  the envelope is `"SH20" ‖ concat(pushes)`.

Proof-carrying envelopes (835 bytes for a TRANSFER, with the pinned 480-byte proof) use the witness carrier.

## 4. Envelopes

Header (6 bytes): `"SH20" (4) ‖ version 0x00 (1) ‖ type (1)`. Unknown version: ignored. Unknown type: rejected.
After parsing, re-serialising must give the same bytes; trailing bytes are rejected.

| Type | Code | Body after the header | Bytes |
| --- | --- | --- | --- |
| DEPLOY | 0x01 | `ticker(4) max(8) lim(8) pre(8) start(4) end(4) unlock(4) price(8) payMode(1) psLen(1) payScript(psLen) [team opening(64) if pre > 0] [spend if bytes remain]` | 120 genesis with team; + 829 with a spend |
| MINT | 0x02 | `tokenNum(4) opening(64)` | 74 |
| TRANSFER | 0x03 | `spend` | 835 |
| BURN | 0x04 | `tokenNum(4) vPub(8) spend` | 847 |
| LIST | 0x05 | `tokenNum(4) amount(8) price(8) lockVout(1) psLen(1) payScript(psLen) spend` | 857 + payScript |
| TAKE | 0x06 | `opening(64)` | 70 |
| CLAIM | 0x07 | `listTxid(32) opening(64) sig(64)` | 166 |

- `ticker`: 4 ASCII characters `[A-Z0-9]`. `payMode`: 0 none, 1 burn, 2 pay to `payScript`.
  `payScript` (≤ 34 bytes) is present only with payMode 2. `listTxid`: txid in display (RPC) byte order.

**Spend section**

```
anchorHeight(4) ‖ nf0(32) ‖ nf1(32) ‖ 3 × [ leaf(32) ‖ pk_eph(33) ‖ ct(28) ] ‖ proofLen(2) ‖ proof(proofLen)
```

- `pk_eph`: compressed secp256k1 point (prefix 02/03). `ct`: amount u64 ‖ tokenNum u32 ‖ 16-byte tag, sealed to the recipient.
- `1 ≤ proofLen ≤ 4096`. The pinned verifier accepts only `proofLen = 480` (below), so a spend section is 829 bytes.
- `body` = every envelope byte before `proofLen`; `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r`.

**Verifier inputs** (public inputs of the spend circuit, in this order): `R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub`.

**The relation.** A proof shows knowledge of a ticker `t` and, for each of the two inputs, of `v, rho, nk, Ak, index`, a sibling
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

**Every spend**: `H − W ≤ anchorHeight ≤ H − K_min`; root known (`anchorHeight < A` uses the empty root); nullifiers
non-zero, distinct, never seen; output leaves non-zero; room in the tree; proof valid. Effect: record nullifiers, append the 3 leaves.

| Type | Accepted when | Effect |
| --- | --- | --- |
| DEPLOY | ticker never deployed; `max > 0`, `lim > 0`, `pre < max`, `(max − pre) mod lim = 0`; `start > H`; `end = 0` or `end ≥ start`; `unlock ≥ start`; payMode 0 ⇔ `price = 0`. First accepted DEPLOY = genesis (tokenNum 1) and has no spend; every later one has a spend with `vPub = D`, `tPub = 1` | next tokenNum; `burned[1] += D`; team note scheduled for block `unlock` |
| MINT | token exists; `start ≤ H`; `end = 0` or `H ≤ end`; mints `< (max − pre) / lim`; paid in the same tx: payMode 1 = OP_RETURN outputs carry ≥ `price` sats, payMode 2 = outputs to `payScript` total ≥ `price` | leaf `(t, lim, npk, rho)`; mints + 1 |
| TRANSFER | spend with `vPub = tPub = 0` | — |
| BURN | token exists; `vPub > 0`; spend with `tPub = tokenNum` | `burned[t] += vPub` |
| LIST | token exists; `amount > 0`, `price > 0`; output `lockVout` is P2TR with ≥ 330 sats; spend with `vPub = amount`, `tPub = tokenNum` | listing ACTIVE, lock = `(txid, lockVout)` |
| TAKE | the tx spends the lock of an ACTIVE listing (first in input order) | leaf `(t, amount, npk, rho)`; SOLD if outputs to `payScript` total ≥ `price`, else CANCELLED |
| CLAIM | listing is CLOSED; BIP340 signature by the lock's output key over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk ‖ rho)` | leaf `(t, amount, npk, rho)`; CLAIMED |

A rejected envelope changes nothing; sats it paid are not returned.

## 6. Block processing and digest

1. If `H ≥ A`: append team notes whose `unlock = H` (by tokenNum), then for each transaction in block order:
   note the ACTIVE listings whose lock it spends; apply its envelope; set any of those still ACTIVE to CLOSED.
2. Record `R[H]`.
3. `digest_H = SHA256(digest_{H−1} ‖ u32le(H) ‖ R[H] (32, LE) ‖ SHA256(events_H))`, `digest_start = SHA256("sh20-v0")`,
   `events_H` = the JSON list of accepted events in order (see `src/indexer.js`; to be frozen as a byte format before activation).

Reorgs: roll back to the fork point (per-block undo log) and replay.

## 7. Not final

The verifying-key digest of §4 until the circuit is audited and frozen; the `ct` sealing; the profile constants
(`A`, `D`, network); the canonical event encoding inside the digest.
