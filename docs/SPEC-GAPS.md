# SH-20 spec gaps — found by a clean-room second indexer

`indexer-rs/` is a second SH-20 indexer, in Rust, written from [`SPEC-WIRE.md`](SPEC-WIRE.md) draft v0.3 without
opening the reference indexer. This file lists every place where the spec did not settle what the code had to do:
what was unclear, what `indexer-rs` does, why, and whether the vectors confirm it.

## Resolution (2026-11-19)

Every point below is now settled in [`SPEC-WIRE.md`](SPEC-WIRE.md), in the place listed here. The spec, not this file, is
normative: an implementation re-reads the spec for each point. Where the reference indexer read a point differently from
the text now written, the reference was changed to match the text; the vectors were extended to pin the points that
can be pinned (`bodyHash` of every spend envelope, the nine verifier inputs of every spend in the scenario, 23 carrier
cases, a CLAIM with its signature, a listing CLOSED then claimed and one CANCELLED, `digest_{A−1}`).

| # | Settled in | Pinned by the vectors |
| --- | --- | --- |
| 1.1 | §1, `SHA256(…) mod r` | `domainLeaf`, every `bodyHash` |
| 1.2 | §4, "Field elements" | — |
| 1.3 | §4, `body` | `envelopes.*.bodyHash`, `scenario.verifierCalls` |
| 2.1, 2.2, 3.3 | §3, last paragraph; §4, header | `carriers` |
| 2.3 | §3, "minimal push" | `carriers` |
| 2.4, 2.5 | §3, "Witness" | `carriers` |
| 2.6, 2.7 | §3, last paragraph | `carriers` (coinbase) |
| 3.1, 3.2 | §4, `payMode` and `payScript` | — |
| 3.4 | §4, re-serialising | — |
| 4.1 | §5 intro, §6 | `preActivation` |
| 4.2, 4.3 | §5 Details, "Payment" | `mintPaid`, `mintBatch` |
| 4.4, 4.5, 4.13 | §5 Details, "DEPLOY"; §6 step 1 | — |
| 4.6 | §5 Details, "Room in the tree" | — |
| 4.7, 4.9, 4.10 | §5 Details, "Locks" | blocks 9 to 11 |
| 4.8 | §5 Details, "CLAIM message" | `claim`, block 11 |
| 4.11, 4.12 | §5, "Every spend" | anchors 1 to 8 |
| 4.14 | §5 Details, "Listings" | — |

## Recheck against the settled spec (2026-11-19)

`indexer-rs` was re-read against the new `SPEC-WIRE.md`, point by point, and against the extended vectors, again
without opening `indexer/` (read: `SPEC-WIRE.md`, the table above, `indexer/vectors/v0.3.json`).

- **It replays the extended vectors in full**: the 11 blocks (roots, events, `eventsH`, digests), the 3 refusals, the
  final state with its 3 listings, the `bodyHash` of the 8 spend envelopes, the 7 verifier calls with their nine
  inputs each, the 23 carrier cases, the CLAIM message and signature, and `digest_{A−1}`.
- **The text sides with what `indexer-rs` already did on 26 of the 28 points.** Two needed a change:
  - **3.2** An empty `payScript` is now rejected with payMode 2 and in a LIST (it was accepted).
  - **2.3** `OP_PUSHDATA4` is no longer a minimal push for any length (see R1).
- **No contradiction** between the new text and the vectors.
- Blocks 9 to 11 (CLOSED, CANCELLED, the forged and the signed CLAIM) replayed with the code as it was, written
  from the first text. The two changes above cannot touch the other new vectors: none has an empty `payScript` or
  a push above 65,535 bytes.

### Still open

All six are settled since: see [the second recheck](#second-recheck-2026-11-19-after-r1-to-r6).

Six points where the text can still be read two ways, or where the vectors need a guess. None changes a digest on
a chain of ordinary transactions.

| # | Point | Chosen in `indexer-rs` | Vectors |
| --- | --- | --- | --- |
| R1 | **A push of more than 65,535 bytes.** §3 calls "minimal" Bitcoin's `CheckMinimalPush`, then lists forms up to `OP_PUSHDATA2` and says any other way is not minimal. Under `CheckMinimalPush`, `OP_PUSHDATA4` is the minimal form above 65,535 bytes; under the list, such data has no minimal push. It matters for the count only: an OP_RETURN of 70,000 bytes starting with `SH20` beside a real envelope either refuses the transaction or is not there. | The list: `OP_PUSHDATA4` never carries an envelope. | silent |
| R2 | **The order of the checks before the proof.** §5 puts the turnstile before the proof and says nothing of the other conditions. A refusal has no effect, so the order does not change the state; it does change which spends reach the verifier, and `verifierCalls` lists 7 calls: none for the copied LIST of block 2, whose proof is the valid one. Either the lock is checked before the proof, or the list holds accepted spends only. The vectors do not say which. | Every other condition first, the proof last: 7 calls. | agree, without saying what they list |
| R3 | **Coinbase.** "Read like any other (only its OP_RETURN outputs can carry an envelope)": a remark (a coinbase witness is one 32-byte element, so it can hold no tapscript), or a rule (the witness of a coinbase is not looked at)? The same on a valid chain; different on hand-made JSON. | A remark: both carriers are read. | the case has no witness |
| R4 | **A second listing under one txid.** §5 states that a LIST txid is unique (BIP30, BIP34) and so gives no rule. An implementation still does something if it is not, for example on a regtest chain built by hand. | The second LIST is refused. | silent |
| R5 | **The new vector sections are not described.** `notes` covers the scenario only. Guessed here: `carriers[].expect` is the one *counted* envelope, `"none"` or `"many"` (case 21, a version-1 envelope alone, is `"none"` though a carrier holds it); an input written `{"coinbase": "true"}` spends nothing; `verifierCalls[].publicInputs` are the nine inputs, big-endian hex, in the order of §4; `claim.npk` is big-endian like every field element of the file, and little-endian inside the message. | As guessed; every test passes. | — |
| R6 | **Editorial.** The first lines still say the file is "normative for `indexer/src/`". With two implementations it is normative for every indexer. | — | — |

### Pinned less than the table above says

The table's last column is right for most rows. For these, the vectors pin part of the point only:

- **4.1** `preActivation` pins the constant `SHA256("sh20-v0")`. No vector has a block below `A`, and no spend is
  anchored below `A`, so "the empty root before `A`" is not pinned either (every anchor is 1 to 8, with `A = 1`).
- **4.7, 4.9** Blocks 9 to 11 pin: a lock spent with no envelope (CLOSED), an unpaid TAKE (CANCELLED), a forged CLAIM
  refused, a signed CLAIM accepted. Not pinned: a lock spent by a transaction whose envelope is refused or that has
  two envelopes, several locks spent by one transaction, a CLAIM in the transaction that spends the lock.
- **2.1** The carrier cases pin what is counted. No scenario transaction has two envelopes, so the refusal itself
  (nothing applied, locks still closed) is not pinned.
- **2.6** A MINT in a witness is pinned (carrier cases through the rules). A spend in an OP_RETURN is not.
- Still with no vector, as the table says: 1.2, 3.1, 3.2, 3.4, 4.4, 4.5, 4.6, 4.13 (two team notes in one block),
  4.14. Also: payMode 2, a refused DEPLOY, a minted-out token, the anchor window at its bounds, a reused nullifier,
  a reorg.

Each of these has a test in `indexer-rs/tests/rules.rs` or `tests/codec.rs`; they state this implementation's reading.

## Second recheck (2026-11-19, after R1 to R6)

`indexer-rs` was re-read against `SPEC-WIRE.md` as it settles R1 to R6, and against the vectors with blocks 12 and
13 and their `sections` part, again without opening `indexer/`.

- **It replays the vectors in full**: the 13 blocks (roots, events, `eventsH`, digests), the 5 refusals, the final
  state with its 7 listings, the `bodyHash` of the 12 spend envelopes, the 11 verifier calls with their nine inputs
  each, the 23 carrier cases, the CLAIM and `digest_{A−1}`.
- **Nothing in the text is left unclear** for an indexer, as far as this reading goes. **No contradiction** between
  the text and the vectors.

| # | Settled in | What `indexer-rs` does now | Pinned by the vectors |
| --- | --- | --- | --- |
| R1 | §3, "minimal push" | **Changed back**: `OP_PUSHDATA4` is the minimal push above 65,535 bytes, and only there | no carrier case is that long |
| R2 | §5, "Every spend" | Unchanged: the proof is checked last | `verifierCalls`: 11 calls, which are the 11 accepted spends |
| R3 | §3, last paragraph | **Changed**: the witness of a coinbase input is not looked at | the coinbase case has no witness |
| R4 | §5 Details, "Listings" | Unchanged: a LIST whose txid already names a listing is refused | cannot be, on a valid chain |
| R5 | `sections` in the vectors | Every guess was right, but one was written wrongly above: the input of a coinbase is `{"coinbase": true}`, a boolean, not the string `"true"` | — |
| R6 | first lines | — | — |

Blocks 12 and 13 pin four things that had no vector: an anchor below `A` checked against the empty root, a
transaction with two envelopes (refused, and the lock it spends still closes), a CLAIM in the transaction that
spends the lock (refused, then CLOSED), and a TAKE that spends two locks (the first taken, the other CLOSED).

**Still with no vector.** These are clear in the text; only `indexer-rs`'s own tests cover them (and nothing
covers a full tree, which no test can reach):

- a push above 65,535 bytes (R1), and a coinbase whose input has a witness shaped like a script-path spend (R3);
- a field element at or above `r` (1.2), a `payMode` above 2 (3.1), an empty or too long `payScript` (3.2);
- a refused DEPLOY for each of its conditions, `unlock < start` with `pre = 0` (4.4), a spend with `D = 0` (4.5);
- payMode 2, an unpaid mint, a mint outside its window, a minted-out token, the last batch that gets what is left;
- the anchor window at its bounds, a reused or zero nullifier, a zero leaf, a refused proof;
- two team notes in one block (4.13), a spend carried by an OP_RETURN (2.6), a full tree of 2^32 leaves (4.6);
- a block below `A` (the file has no place for one), and a reorg.

## DEPLOY maturity (2026-11-19)

`indexer-rs` follows the rule against ticker sniping from `SPEC-WIRE.md` §5 ("DEPLOY maturity") and §6 (GENESIS
ends with `N`), read alone, and replays the vectors that go with it (`N = 3`): the two copies of the DEPLOY refused
in block 4, the same 11 verifier calls, the 73-byte GENESIS record, and every digest up to block 13.
**No contradiction** between the text and the vectors. Three points had to be decided:

| # | Point | Chosen in `indexer-rs` | Vectors |
| --- | --- | --- | --- |
| M1 | **When a missing height stops the indexer.** The text needs the height "for input 0 of a transaction that carries a DEPLOY in its witness". It does not say whether an indexer stops when that DEPLOY would be refused anyway (a taken ticker, a bad `start`). | It stops whenever a transaction has exactly one counted envelope, in the witness, that decodes as a DEPLOY, before any other condition. No height is needed for a DEPLOY in an OP_RETURN, a transaction with two envelopes, or an envelope the decoder refuses. | confirm the OP_RETURN case (no height given, refused); silent on the rest |
| M2 | **What a stop leaves behind.** "Must stop, not guess" does not say what becomes of the transactions of that block before the DEPLOY. | Nothing of the block is applied; the same block can be given again with the height. | cannot be expressed |
| M3 | **`H − N` below zero.** The anchor rule writes `max(0, H − W)`; this one writes `≤ H − N`. | Read as integers: below block `N` no commit is old enough, not even one of block 0. | silent: the first DEPLOY is in block 4 |

M1 and M2 cannot change a digest: an indexer that stops has no digest for that block. They decide whether two
indexers given the same incomplete data both stop. The vectors pin a commit exactly `N` blocks old (accepted, blocks
4 and 5) and one `N − 2` blocks old (refused); `N − 1` has only this crate's test.

The sections below are the record of the first pass, before the resolution. They are left as written.

## Result

- **The spec was enough for everything the vectors test.** `indexer-rs` reproduces
  `indexer/vectors/v0.3.json` in full: the primitives, the 11 envelopes, and for each of the 8 blocks of the scenario
  the root, `eventsH`, the digest, the one refusal, and the final state. It did so on its first run; no value was
  adjusted to fit.
- **No contradiction** was found between the spec and the vectors.
- **28 points were left open by the spec.** The vectors confirm 6 of them, four only in part; one (3.4) is a remark.
  The other 21 are choices made here that the reference indexer may have made differently. Five points could be met
  on a public signet by ordinary wallets (marked **signet** below); the rest need a transaction built on purpose.
- **One weakness of the rules themselves** turned up on the way, and is **fixed**: a LIST could be front-run,
  because its spend was not tied to its lock output ([section 7](#7-fixed-a-list-could-be-front-run)). The LIST now
  carries `lockKey` in its signed body, and `indexer-rs` follows the new text and the new vectors.
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


## 7. Fixed: a LIST could be front-run

**Status: fixed in the spec (2026-11-19, "LIST binds its lock key in the signed body").** `SPEC-WIRE.md` §4 and §5
now read: a LIST is `ticker(4) amount(8) price(8) lockVout(1) lockKey(32) psLen(1) payScript(psLen) spend`
(884 bytes + `payScript`), output `lockVout` must be `OP_1 <lockKey>` with at least 330 sats, and a CLAIM is signed
by `lockKey`. `indexer-rs` was updated from that text alone and replays the new vectors: the same roots, `eventsH`
and digests as before, and two refusals, the copied LIST of block 2 and the over-burn of block 8.
Tests: `scenario_refuses_the_copied_list` (`tests/vectors.rs`), `list_layout` (`tests/codec.rs`),
`a_copied_list_is_refused` (`tests/rules.rs`).

Sections 1 to 6 were written before this fix and are left as they were. Where they speak of "the one refusal" or
of the lock key read from the lock output's script (4.8, 4.10), read: two refusals, and the `lockKey` of the envelope.

What was found, for the record:

- **What the spec bound.** The authorisation of a spend signs `bodyHash`, and `body` is the envelope before the
  proof. For a LIST that was `ticker`, `amount`, `price`, `lockVout`, `payScript`, the anchor, the nullifiers and
  the outputs. `lockVout` is an index. The script at that index, and so the key that controls the lock, was in the
  transaction and not in `body`.
- **What followed.** A LIST envelope was valid in any transaction whose output `lockVout` was P2TR with 330 sats.
  It is public as soon as its reveal transaction is in a mempool. Someone who copied it into a transaction of their
  own, with a lock they controlled, and confirmed first (a higher fee, or a miner) got the listing: the seller's
  transaction was then refused (nullifiers already seen). The holder of the lock could spend it with an unpaid
  TAKE, which is CANCELLED and creates the note `(t, amount, npk)` for the `npk` in that TAKE, or spend it with no
  envelope and CLAIM. Either way the listed amount was theirs.
- **Scope.** LIST only, as far as this reading goes. A copied TRANSFER, BURN or DEPLOY has the same effect whoever
  publishes it; a copied MINT pays for the first minter's `npk`; a CLAIM is signed over `listTxid` and `npk`.
- **After the fix.** The copy with another lock is refused and records nothing, so the seller's transaction still
  goes through. A copy that keeps the seller's lock creates the same listing under another txid; the lock still
  belongs to the seller's key.
