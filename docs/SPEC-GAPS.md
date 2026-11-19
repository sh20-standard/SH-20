# SH-20 spec gaps — found by a clean-room second indexer

`indexer-rs/` is a second SH-20 indexer, in Rust, written from [`SPEC-WIRE.md`](SPEC-WIRE.md) draft v0.3 without
opening the reference indexer. This file lists every place where the spec did not settle what the code had to do:
what was unclear, what `indexer-rs` does, why, and whether the vectors confirm it.

## Result

- **The spec was enough for everything the vectors test.** `indexer-rs` reproduces
  `indexer/vectors/v0.3.json` in full: the primitives, the 11 envelopes, and for each of the 8 blocks of the scenario
  the root, `eventsH`, the digest, the one refusal, and the final state. It did so on its first run; no value was
  adjusted to fit.
- **No contradiction** was found between the spec and the vectors.
- **28 points were left open by the spec.** The vectors confirm 6 of them, four only in part; one (3.4) is a remark.
  The other 21 are choices made here that the reference indexer may have made differently. Five points could be met
  on a public signet by ordinary wallets (marked **signet** below); the rest need a transaction built on purpose.
- **One weakness of the rules themselves** turned up on the way: a LIST can be front-run, because its spend is not
  tied to its lock output ([section 7](#7-found-on-the-way-a-list-can-be-front-run)). It is not a gap: the text is
  clear, and `indexer-rs` applies it as written.
- The vectors do not exercise a large part of §5 (list in [section 5](#5-what-the-vectors-do-not-cover)). Agreement
  on the vectors therefore says nothing about CLAIM, CLOSED, CANCELLED, payMode 2, the one-envelope rule or reorgs.

What was read: `docs/SPEC-WIRE.md`, `docs/DESIGN.md`, `indexer/vectors/v0.3.json`, and the root `CLAUDE.md`.
Never opened: `indexer/src`, `indexer/test`, `indexer/bin`, `explorer/`, `vault/`, `circuit/`, and the other files
of `docs/` and `indexer/`. Poseidon is `light-poseidon`, BIP340 is the `secp256k1` crate, SHA-256 is `sha2`.

Each entry says: **Spec** (what the text says), **Chosen** (what `indexer-rs` does), **Why**, and **Vectors**
(whether they confirm the choice). A test in `indexer-rs/tests/` pins every choice.

## Summary

| # | Point | Vectors | Signet |
| --- | --- | --- | --- |
| 1.1 | Byte order of `SHA256(…) mod r` | confirm (`TAG_LEAF` only) | |
| 1.2 | Are openings field elements (`< r`)? | silent | |
| 1.3 | Does `body` include the 6-byte header? No `bodyHash` vector | silent | **signet** |
| 2.1 | What counts as an envelope for "at most one" | silent | |
| 2.2 | "Ignored" against "rejected" | silent | |
| 2.3 | What a "minimal push" is for 0- and 1-byte pushes | silent | |
| 2.4 | Recognising a script-path spend without the spent output | confirm (the common shape) | **signet** |
| 2.5 | "Contains": where, and when the pattern is broken | silent | |
| 2.6 | May a spend ride in an OP_RETURN, a mint in a witness? | silent | |
| 2.7 | Coinbase transactions | silent | |
| 3.1 | `payMode` above 2 | silent | |
| 3.2 | An empty `payScript` (payMode 2, LIST) | silent | |
| 3.3 | An envelope shorter than its header | silent | |
| 3.4 | The re-serialisation rule adds nothing | — | |
| 4.1 | Blocks before `A`, and the first digest | confirm (start at `A` only) | **signet** |
| 4.2 | Which outputs are "OP_RETURN outputs" (payMode 1) | confirm (the envelope's own) | |
| 4.3 | `m × price` beyond 64 bits | silent | |
| 4.4 | `unlock ≥ start` when `pre = 0` | silent | **signet** |
| 4.5 | A DEPLOY with a spend when `D = 0` | silent | |
| 4.6 | A full tree outside spends | silent | |
| 4.7 | A refused envelope in a transaction that spends a lock | silent | |
| 4.8 | The CLAIM message, and a lock key that is not a point | silent | **signet** |
| 4.9 | Several locks spent by one transaction | silent | |
| 4.10 | What "P2TR" means for the lock | silent | |
| 4.11 | Repeated output leaves | silent | |
| 4.12 | `H − W` below zero | confirm | |
| 4.13 | Team allocation with `pre = 0`; ticker order | confirm (`pre = 0`) | |
| 4.14 | A listing whose txid already exists | silent | |

## 1. Primitives

### 1.1 Byte order of `SHA256(…) mod r`

- **Spec.** `TAG_LEAF = SHA256("sh20/v0/leaf") mod r`, `bodyHash = SHA256("sh20/v0/body" ‖ body) mod r`. §1 says
  integers on the wire are little-endian; a hash is not "on the wire", and nothing says how its 32 bytes become an integer.
- **Chosen.** The digest is a big-endian integer, reduced mod `r`.
- **Why.** The usual reading of a hash as a number; the little-endian reading gives another `TAG_LEAF`.
- **Vectors.** `domainLeaf` confirms it for `TAG_LEAF`. Nothing confirms it for `bodyHash` (see 1.3).
- **Suggested text.** "`X mod r` of a hash reads its 32 bytes as a big-endian integer."

### 1.2 Are openings field elements?

- **Spec.** "Field elements on the wire: 32 bytes, little-endian, value `< r` (anything else is rejected)". The tables
  call an opening `opening(32)` and §2 calls it "`npk` (32 bytes)", never a field element. The nullifiers and leaves
  of a spend are not called field elements either.
- **Chosen.** The decoder rejects an envelope whose opening (MINT, TAKE, CLAIM, DEPLOY team opening), nullifier or
  output leaf is `≥ r`. `pk_eph`, `ct`, `listTxid`, the signature and the proof are opaque bytes.
- **Why.** Each of these is an input of Poseidon or a public input of the circuit; reducing mod `r` instead would
  let two byte strings name one note.
- **Vectors.** Silent: every value in them is below `r`.
- **Suggested text.** List the fields that are field elements in §4.

### 1.3 Does `body` include the header? **signet**

- **Spec.** "`body` = every envelope byte before the proof".
- **Chosen.** From the first byte of the envelope (`"SH20"`, version, type) up to the proof: 350 bytes for a TRANSFER.
- **Why.** "Every envelope byte" is taken at its word; it also binds the type to the signature.
- **Vectors.** Silent, and this is the weakest point of the vectors: the test verifier ignores its inputs, so no
  public input (`R[anchorHeight]`, `bodyHash`, `vPub`, `tPub`) is ever checked. Two indexers can agree on every
  vector and hand different inputs to a real verifier. With the PLONK verifier on signet, a wrong `bodyHash` rejects
  every spend.
- **Suggested vectors.** For each spend envelope: `bodyHash`, and the nine public inputs the scenario gives the verifier.

## 2. Carriers and the one-envelope rule

### 2.1 What counts as an envelope for "at most one"

- **Spec.** "A transaction carries at most one envelope. Two envelopes of any kind reject the transaction."
  It does not say whether these count: a second OP_RETURN output starting with `SH20`; several `OP_0 OP_IF "SH20"`
  patterns in one tapscript; an envelope the decoder refuses; an envelope of an unknown version; a carrier that is
  almost one (non-minimal push).
- **Chosen.** An envelope is any byte string starting with `SH20` found by a carrier that matches §3 completely.
  All of them count, in every OP_RETURN output and at every place of the tapscript of input 0, whether or not they
  decode. Two exceptions: an unknown version does not count (2.2), and a carrier that does not match §3 completely
  is not a carrier, so it does not count either. With two or more, the transaction's envelopes are all refused and
  nothing is applied (locks it spends still close, 4.7).
- **Why.** "Of any kind" is read as "valid or not"; a malformed carrier is not an envelope of any kind.
- **Vectors.** Silent: every transaction has exactly one envelope.

### 2.2 "Ignored" against "rejected"

- **Spec.** "Unknown version: ignored. Unknown type: rejected." A rejected envelope "changes nothing", and so does an
  ignored one; the spec gives no case where the two differ.
- **Chosen.** The only place where they can differ is the one-envelope rule, so: an unknown version is treated as if
  it were not there (a v0 envelope beside it applies), an unknown type is an envelope that is refused (a second
  envelope beside it rejects the transaction). An ignored envelope is not reported as a refusal.
- **Why.** It lets a later version share a transaction with v0 without changing what v0 indexers compute.
- **Vectors.** Silent.

### 2.3 What a "minimal push" is for short data

- **Spec.** "Each push is minimal." For data of 2 bytes or more this means the shortest length prefix. For an empty
  push or a single byte in `1..16` or `0x81`, Bitcoin's rule (`CheckMinimalPush`) says the minimal form is `OP_0`,
  `OP_1`…`OP_16`, `OP_1NEGATE`, which are not length-prefixed pushes.
- **Chosen.** Bitcoin's rule. Inside a witness envelope `OP_0` is an empty push, `OP_1`…`OP_16` push the byte
  `0x01`…`0x10`, `OP_1NEGATE` pushes `0x81`; `01 05` is not minimal and breaks the pattern.
- **Why.** "Minimal push" is a Bitcoin term with one definition.
- **Vectors.** Silent. It matters only when a chunk of an envelope is empty or one such byte. Cut every 520 bytes,
  no v0.3 envelope leaves a chunk that short (the last chunk has 34 bytes or more), so only a wallet that cuts
  otherwise can meet it.

### 2.4 Recognising a script-path spend without the spent output **signet**

- **Spec.** "The tapscript of input 0 (script-path spend; annex ignored)". Whether an input is a taproot script-path
  spend depends on the output it spends, which `getblock <hash> 2` does not give.
- **Chosen.** From the witness alone: drop the last element if there are at least two and it starts with `0x50`
  (annex); at least two elements must remain; the last is a control block (`33 + 32·m` bytes, `m ≤ 128`, first byte
  `0xc0` or `0xc1`, that is leaf version `0xc0`); the script is the element before it.
- **Why.** No witness that is valid under today's consensus for another output type has this shape (a P2WSH script
  cannot start with `0xc0`, a P2WPKH key starts with `02` or `03`). An output of a future witness version could.
- **Vectors.** They confirm the common shape (`[signature, script, 33-byte control block]`). Annex, longer control
  blocks and other leaf versions are not in them.
- **Suggested text.** State this test, or require indexers to look at the spent output.

### 2.5 "Contains": where, and when the pattern is broken

- **Spec.** The tapscript "contains `OP_0 OP_IF <push "SH20"> <push>... OP_ENDIF`".
- **Chosen.** The script is split into opcodes from its start; the pattern may begin at any opcode, never inside the
  data of a push. `"SH20"` must be a push of its own (`04 53 48 32 30`). After it, only minimal pushes of at most
  520 bytes until `OP_ENDIF`. If anything else comes first (an opcode, a non-minimal push, a longer push, the end
  of the script) there is no envelope at that place and the search goes on at the next opcode. A script that does
  not split to its end (a push longer than what is left) carries no envelope. `"SH20"` with no other push is an
  envelope of 4 bytes, which the decoder refuses. Whether the branch can execute is not looked at; `OP_SUCCESS`
  opcodes get no special treatment.
- **Vectors.** They confirm the plain case only (`<key> OP_CHECKSIG OP_0 OP_IF …`, two pushes of 520 and 310 bytes).

### 2.6 May any type use any carrier?

- **Spec.** "Proof-carrying envelopes […] use the witness carrier." It is not said whether a TRANSFER in an
  OP_RETURN is refused, or whether a MINT may ride in a witness.
- **Chosen.** Any type in either carrier.
- **Why.** No rule of §5 names the carrier; the sentence reads as advice on cost (`CLAUDE.md` lists it as a cost lever).
- **Vectors.** Silent: spends are in witnesses, the rest in OP_RETURN.

### 2.7 Coinbase transactions

- **Spec.** Silent.
- **Chosen.** Read like any transaction: its OP_RETURN outputs can carry an envelope and pay a mint. It spends no lock.
- **Vectors.** Silent: no coinbase in the scenario.

## 3. Envelope bytes

### 3.1 `payMode` above 2

- **Spec.** "payMode: 0 none, 1 burn, 2 pay to payScript". Other values are not mentioned.
- **Chosen.** The decoder rejects them.

### 3.2 An empty `payScript`

- **Spec.** "`payScript` (≤ 34 bytes) is present only with payMode 2." This forbids a `payScript` without payMode 2;
  it does not say payMode 2 needs one. A LIST has a `payScript` and no payMode.
- **Chosen.** `psLen = 0` is accepted with payMode 2 and in a LIST. Such a mint or sale is paid to outputs with an
  empty script. `psLen > 0` with payMode 0 or 1 is rejected; `psLen > 34` is rejected.
- **Why.** Only what the text rejects is rejected.
- **Vectors.** Silent: payMode 2 is not in them; the LIST has a 22-byte script.

### 3.3 An envelope shorter than its header

- **Spec.** Silent on `SH20` alone (4 bytes) or `SH20` plus a version (5 bytes).
- **Chosen.** `SH20` alone and `SH20 00` are v0 envelopes that are refused (they count for 2.1); `SH20` plus another
  version byte is an unknown version, ignored.

### 3.4 The re-serialisation rule

- **Spec.** "After parsing, re-serialising must give the same bytes."
- **Note.** With fixed sizes, a `k` byte that cannot be 0 or 1, and optional parts that depend on `pre` and on the
  bytes left, no byte string has two parses, so the rule never rejects anything on its own. `indexer-rs` checks it
  anyway.

## 4. Rules

### 4.1 Blocks before `A`, and the first digest **signet**

- **Spec.** "Nothing before `A` is read." But §6 reads: "1. If `H ≥ A`: […] 2. Record `R[H]`. 3. `digest_H = …`":
  taken as written, steps 2 and 3 also run before `A`, and the digest would depend on the block an indexer started from.
  `digest_start = SHA256("sh20-v0")` is not tied to a height.
- **Chosen.** The first block processed is `A`, and `digest_{A−1} = digest_start`. Blocks below `A` get no root and
  no digest; `replay` skips them. An indexer cannot start above `A`.
- **Why.** It is the only reading where two indexers agree whatever they were given before `A`.
- **Vectors.** They confirm `digest_{A−1} = digest_start` when the first block seen is `A` (`A = 1`, no block 0).
  They do not show what the reference does with an earlier block. **If the two indexers disagree from the first
  block on signet, look here first.**
- **Suggested text.** "`digest_{A−1} = SHA256("sh20-v0")`; blocks below `A` have no digest."

### 4.2 Which outputs are "OP_RETURN outputs"

- **Spec.** "payMode 1 = OP_RETURN outputs carry ≥ `m × price` sats".
- **Chosen.** The sum of the values of every output whose script starts with `0x6a`, the envelope's own output included.
- **Vectors.** They confirm that the envelope's own output counts (`mintPaid`, `mintBatch`). The sum over several
  outputs is not in them.

### 4.3 `m × price` beyond 64 bits

- **Spec.** `price` is a u64 and `m` goes up to 10.
- **Chosen.** The product and the sums of output values are computed without overflow (128 bits). A price nobody can
  pay makes the mint impossible, not free.

### 4.4 `unlock ≥ start` when `pre = 0` **signet**

- **Spec.** DEPLOY is accepted when "`unlock ≥ start`", with no exception.
- **Chosen.** Applied even when `pre = 0`, where `unlock` has no use: a DEPLOY with no team and `unlock = 0` is rejected.
- **Why.** The text has no exception. A wallet that writes `unlock = 0` for "no team" would lose its DEPLOY.
- **Vectors.** Silent: `deployNoTeam` has `unlock = start`.

### 4.5 A DEPLOY with a spend when `D = 0`

- **Spec.** "if `D = 0`: no spend".
- **Chosen.** With `D = 0` a DEPLOY that carries a spend is rejected; with `D > 0` a DEPLOY without one is rejected.
- **Vectors.** Silent on `D = 0` (the scenario has `D = 1000`).

### 4.6 A full tree outside spends

- **Spec.** "Room in the tree" is a condition of "every spend" only.
- **Chosen.** MINT, TAKE and CLAIM are rejected when no leaf is left. A team note that cannot be appended is not
  appended: no event, and the token stays not unlocked. Out of reach in practice (2^32 leaves).

### 4.7 A refused envelope in a transaction that spends a lock

- **Spec.** "A rejected envelope changes nothing"; §6: "note the ACTIVE listings whose lock it spends; apply its
  envelope; set any of those still ACTIVE to CLOSED".
- **Chosen.** The closing does not depend on the envelope: a transaction that spends a lock and carries a refused
  envelope, two envelopes or none closes the listing (event CLOSED). A CLAIM in the very transaction that spends the
  lock is refused (the listing is ACTIVE when the envelope applies) and the listing is then CLOSED.

### 4.8 The CLAIM message, and a lock key that is not a point **signet**

- **Spec.** "BIP340 signature by the lock's output key over `SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)`".
- **Chosen.** `listTxid` and `npk` are the 32 bytes of the envelope as they are (txid in display order, `npk`
  little-endian); the BIP340 message is the 32-byte hash; the key is the 32 bytes after `OP_1 <push 32>` in the lock
  output's script. If they are not the x coordinate of a point, no CLAIM can succeed and the listing stays CLOSED.
- **Vectors.** Silent: there is no CLAIM in them at all, envelope or event. Any wallet that signs a CLAIM on signet
  tests this for the first time.
- **Suggested vectors.** A CLAIM envelope with a fixed key and a BIP340 signature without auxiliary randomness.

### 4.9 Several locks spent by one transaction

- **Spec.** TAKE takes "the lock of an ACTIVE listing (first in input order)".
- **Chosen.** The first input, in order, that spends the lock of an ACTIVE listing designates the listing a TAKE
  takes. Every other ACTIVE listing whose lock the transaction spends is CLOSED, one CLOSED event each, in input
  order, after the envelope's event.

### 4.10 What "P2TR" means for the lock

- **Chosen.** A script of exactly 34 bytes, `51 20 <32 bytes>`. Whether the 32 bytes are a valid key is not checked
  at LIST (see 4.8). The output must exist at index `lockVout` of the LIST transaction and hold at least 330 sats.

### 4.11 Repeated output leaves

- **Spec.** Nullifiers must be distinct; nothing is said of output leaves.
- **Chosen.** Equal leaves inside a spend, or equal to a leaf already in the tree, are accepted.

### 4.12 `H − W` below zero

- **Chosen.** When `H < W` the lower bound is 0. The vectors confirm it (anchors 1 to 7 with `W = 100`).

### 4.13 Team notes

- **Chosen.** A token with `pre = 0` gets no team note and no TEAM_UNLOCK event (the vectors confirm it: `SEC2`).
  "By ticker, in byte order" is the ascending order of the 4 ASCII bytes. The vectors never unlock two tokens in one block.

### 4.14 A listing whose txid already exists

- **Chosen.** Listings are named by the txid of their LIST transaction; a LIST whose txid already names a listing is
  rejected. It cannot happen on a chain with BIP30 and BIP34.

## 5. What the vectors do not cover

Agreement on the vectors proves nothing about these. Each has a test in `indexer-rs/tests/rules.rs`, which states
this implementation's reading only.

- **CLAIM**: no envelope, no event, no signature.
- **CLOSED**: no lock spent without a TAKE; and **CANCELLED**: no unpaid TAKE.
- **payMode 2** for mints, and a mint that is refused for lack of payment.
- The mint window (`start`, `end`), a minted-out token, and the last batch that gets what is left.
- A DEPLOY that is refused, for any of its conditions; `D = 0`.
- The one-envelope rule, an unknown version, an unknown type, any malformed envelope.
- Non-minimal pushes, the annex, a control block longer than 33 bytes, an envelope on another input.
- The anchor window at its bounds; an anchor before `A`; a reused nullifier; a refused proof.
- Any public input of the verifier (1.3).
- Two team notes in one block.
- A reorg.
- A block with a coinbase, and a block before `A` (4.1).

## 6. Outside the rules

- **`replay`.** The spec does not define what a replay prints. `sh20-indexer-rs replay <folder>` prints
  `<height> <digest>` per block from `A` on, and with `--json` one object per block with the vectors' field names
  (`height`, `root`, `events`, `eventsH`, `digest`) plus `rejected`.
- **Profile.** `A` and `D` are not final (§7). `replay` takes `--activation` (default: the lowest height in the
  folder) and `--deploy-burn` (default 0), and prints the profile it used on standard error.
- **Verifier.** `replay` has `--verifier reject` (default: every spend is refused) and `--verifier test` (the rule of
  the vectors). The PLONK verifier is not wired in: it lives in `circuit/`, which this work did not open. It plugs
  into the `SpendVerifier` trait.
- **Undo depth.** The spec says "per-block undo log" without a depth. `indexer-rs` keeps 288 blocks by default, the
  figure `CLAUDE.md` gives for the reference follower.


## 7. Found on the way: a LIST can be front-run

This is not an unclear point. The text is clear, `indexer-rs` follows it, and the reference presumably does too.
It is a weakness of the rule, seen while implementing it from the text alone. It needs the maintainer: the fix
changes bytes.

- **What the spec binds.** The authorisation of a spend signs `bodyHash`, and `body` is the envelope before the
  proof. For a LIST that is `ticker`, `amount`, `price`, `lockVout`, `payScript`, the anchor, the nullifiers and
  the outputs. `lockVout` is an index. The script at that index, and so the key that controls the lock, is in the
  transaction and not in `body`.
- **What follows.** A LIST envelope is valid in any transaction whose output `lockVout` is P2TR with 330 sats. It
  is public as soon as its reveal transaction is in a mempool. Someone who copies it into a transaction of their
  own, with a lock they control, and confirms first (a higher fee, or a miner) gets the listing: the seller's
  transaction is then refused (nullifiers already seen). The holder of the lock spends it with an unpaid TAKE,
  which is CANCELLED and creates the note `(t, amount, npk)` for the `npk` in that TAKE. Or they spend it with no
  envelope and CLAIM. Either way the listed amount is theirs, and `payScript` and `price` protect nothing because
  no sale takes place.
- **Scope.** LIST only, as far as this reading goes. A copied TRANSFER, BURN or DEPLOY has the same effect whoever
  publishes it; a copied MINT pays for the first minter's `npk`; a CLAIM is signed over `listTxid` and `npk`.
  This was derived from `SPEC-WIRE.md` alone; `SPEC-NOTES.md` was not read, but a wallet rule could not close it,
  since indexers accept the copy.
- **Shown by.** `a_list_is_not_bound_to_its_lock_output` in `indexer-rs/tests/rules.rs`.
- **Possible fix.** Put the lock's 32-byte output key in the LIST body (`… lockVout(1) lockKey(32) …`, 32 more
  bytes, about 8 vB) and accept the LIST only when output `lockVout` is `OP_1 <lockKey>`. The signature then covers
  the key, and a copy with another lock is refused. It is a change of wire format: spec, vectors and both indexers.
