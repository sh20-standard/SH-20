# The audit prompt

What a session runs to audit one part of SH-20: open a new Claude Code session in the repository and
type `/audit <part>` (`.claude/commands/audit.md`), or say "read `docs/AUDIT-PROMPT.md` and run part
`<part>`". One part per session. The parts and their order are below.

It is the review we can run ourselves, again on every change, before the external audit by people
that mainnet waits for (`docs/PLAN.md` §6). It does not replace that one: the code was written by
sessions of the same kind as the one that reads it, so the two can share a blind spot.

## You are the auditor

You did not write this code and you do not trust it. Its author's claims (`docs/AUDIT.md`, comments,
test names, commit messages) tell you where to look, never what is true. The specs are the reference:
[`SPEC-WIRE.md`](SPEC-WIRE.md) for what indexers accept, [`SPEC-NOTES.md`](SPEC-NOTES.md) for what
wallets compute. Where code and spec differ, both are suspect: say which one is wrong and why.

Model: Fable 5.2 for the parts `circuit`, `verifier`, `sealing` and `vault` (`CLAUDE.md`, "Model").
Read `CLAUDE.md` first for the hard requirements and the anonymity rules, which hold for you too.

### The attacker

- writes every byte of every envelope and transaction, in any order within a block, and can see the
  mempool and copy, reorder or front-run what others broadcast;
- chooses every witness value of a proof, including values no honest wallet would choose (dummy notes,
  zero keys, points of small order, amounts near the field order `r`, a Merkle path through any leaf);
- can reorganise the last few blocks;
- can run a dishonest indexer that a vault is pointed at, or be the external wallet that signs;
- can send a victim a note, an address or an offer of their choosing.

What the attacker wins, worst first: tokens that never entered the pool (inflation); spending a note
that is not theirs; spending one note twice; the BTC or the tokens of a sale; a secret key; learning an
amount, a ticker, a sender or a recipient that a spend hides; two honest indexers that disagree; an
indexer or a vault that crashes or stalls on some input.

### Method

1. Write down, before reading any code, what the spec says the part must enforce: a numbered list of
   properties. Then read the code and check each property against it, line by line.
2. For a circuit: every rule of the spec has gates, and every witness value is fixed by gates. A value
   that a gate does not pin is a finding until proved harmless.
3. Look hardest at: arithmetic that can wrap modulo `r` or `2^n`; comparisons and range checks; values
   that must be distinct or on a curve or in a subgroup; encodings with more than one form; what a hash
   or a signature covers and what it leaves out; anything taken from an indexer or a wallet without a
   check; the order of checks and what a refusal leaves behind.
4. Prove each finding: a test that fails, a witness the circuit accepts and the spec forbids, an
   envelope two indexers treat differently, a computed counterexample, or an argument precise enough to
   be checked line by line. A suspicion you could not settle is not a finding: put it under "open".
5. Say what you checked and found to hold, with how. Coverage is half of the report.
6. Run the suites the part has (`CLAUDE.md` lists them) and say which ran. Build nothing that changes
   a key: any change to the gates is the maintainer's (`CLAUDE.md`, rules 4 and 5).

### Severity

| Level | Means |
| --- | --- |
| Critical | inflation, theft of notes, BTC or secrets, or a double spend, by anyone, now |
| High | the same under a condition an attacker can bring about (a reorg, a chosen note, a dishonest indexer), or a loss of what a spend hides |
| Medium | two honest indexers can be made to disagree; a vault or indexer can be stopped; a leak of something partial |
| Low | needs an unlikely condition, or links without revealing; a hardening |
| Note | as designed, but a user or an integrator should be told |

### What you hand in

`docs/audit/<YYYY-MM-DD>-<part>.md`, in this order:

1. **Scope**: the commit (`git rev-parse HEAD`), the files read, the spec sections they were held to.
2. **Properties**: the numbered list of step 1.
3. **Findings**: a table (id `<part>-<n>`, severity, title, where, one line on the evidence), then one
   paragraph each: what is wrong, how to reproduce it (commands or code), what fixes it.
4. **Holds**: each property found to hold, with how it was checked.
5. **Open**: what you suspected and could not settle, and what you did not cover.

Fixes are separate pull requests, each with a test that fails before it and passes after, and the
finding id in its title. Never weaken a check to make a test pass. Commit as `CLAUDE.md` rule 5 says,
in UTC, with no session link; edit the body of a pull request once after opening it so that the footer
GitHub adds loses its session link.

## The parts

Run them in this order; the first three are what an external audit must cover before mainnet.

### `circuit`: the spend relation

Held to `SPEC-WIRE.md` §4 and `SPEC-NOTES.md` §2–3. Read `circuit/src/spend.rs`, `gadgets.rs`,
`model.rs`, `cs.rs`, `poseidon.rs`; `docs/AUDIT.md` §2 maps each line of the relation to its gates.
At least:
- conservation: `v0 + v1 = w0 + w1 + w2 + vPub` over the integers, not only modulo `r`; the range of
  every amount, and what a sum near `r` does;
- one ticker for the five notes, tied to `tPub` by `vPub × (t − tPub) = 0`; a spend with `vPub = 0` and
  any `tPub`; `t = 0` (BTC) and tickers that were never deployed;
- the leaf, the nullifier and the note key: one note has exactly one nullifier; a dummy input cannot
  create value or spend a real note; two inputs that are the same note;
- the Merkle path: depth 32, the order of siblings, an index outside the tree, the empty leaf;
- EdDSA-Poseidon over `bodyHash`: the key and `R8` on the curve and in the subgroup, `S < l`, what the
  signature binds, and what `bodyHash` covers in the envelope;
- the nine public inputs: order, encoding, values `≥ r`;
- Poseidon: its constants and round numbers against circomlib for every width used.
Tools: `cargo test --release` in `circuit/`, the adversarial witnesses there (add your own), and the
circom statement in `circuit/circom/` as a second reading.

### `verifier`: PLONK and its boundary

Held to the PLONK paper (Gabizon, Williamson, Ciobotaru, 2019) and to snarkjs' verifier, which hard
requirement 4 says ours must match. Read `circuit/src/plonk/` (the verifier, the transcript, the keys,
the proof decoding), `circuit/src/ffi.rs`, `indexer/src/adapters/plonk.js`. At least: every commitment
and every public input enters the transcript before the challenge it must precede; points are checked
on the curve and scalars below `r` when decoded; the point at infinity; the number of public inputs; the
verifying key is the pinned one wherever a verifier is built; nothing at the WebAssembly boundary reads
or writes outside what it was given. Tools: `bench/cross-check.sh`, and proofs you damage on purpose.

### `sealing`: keys, addresses, ciphertexts, scanning

Held to `SPEC-NOTES.md`. Read `circuit/js/` (both entry points), `circuit/src/notes.rs`, and where the
vault calls them. At least: the separation of every derived key; X25519 with low-order or zero public
keys; that no key and nonce pair of AES-GCM can repeat; what `ct` and its tag reveal, and to whom; what
an indexer learns from a wallet's requests; the one ephemeral key for several recipients that the
v0.4 body proposes (`circuit/README.md`, "The transfer body of wire v0.4, on paper").

### `vault`: the browser wallet

Held to `SPEC-NOTES.md`, BIP340, BIP341 and the vault's own README. Read `vault/src/`. At least: what
the vault asks an external wallet to sign, and whether a wallet or an indexer can make it sign
something else; the sale (LIST, TAKE, CLAIM): whether the buyer or the seller can take both sides;
backups, restores and the passphrase; the service worker and the content security policy; what a
dishonest indexer can make the vault do. `docs/AUDIT.md` §8 is a first reading: check its fixes, do
not start from its conclusions.

### `indexer`: the consensus rules

Held to `SPEC-WIRE.md` §3–6. Read `indexer/src/` (and `indexer-rs/src/` as a second reading). At least:
an envelope with two encodings of one meaning; the order of checks and what a refusal leaves behind;
reorgs and the undo log; the digest; the turnstile; DEPLOY maturity; batches; inputs that cost an
indexer much more than they cost to send. Tools: `npm run fuzz`, `bin/api-diff.js`, the vectors.
