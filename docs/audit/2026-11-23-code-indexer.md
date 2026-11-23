# Code audit, part `indexer` (2026-11-23)

Run from [`docs/AUDIT-PROMPT.md`](../AUDIT-PROMPT.md), "The code audit", part `indexer`, by the
coordination session (Opus 5.5).

**Result:** one change that matters, BIP340 verification 67 times faster (code-indexer-1), which
also closes a cheap way to slow an indexer down; a dead reader and writer removed; three paths that
only a tool outside `npm test` reached now have tests. Two findings are left open with their
numbers: Poseidon, which is now 87 % of a replay, and the event field names the API translates.
No byte and no rule changed.

## 1. Scope

- Commit `d69d3e4` (`main` after #69), then the changes of this run.
- Read: `indexer/src/` (every file), `indexer/bin/` for what it exercises.
- Duties, from `SPEC-WIRE.md` §3–6, `docs/API.md` and `indexer/README.md`:
  1. find the envelopes of a transaction in both carriers, and batches (§3);
  2. decode and re-encode the seven types strictly (§4);
  3. apply the rules of §5: DEPLOY (maturity, burn, ticker), MINT, the spends (window, nullifiers,
     leaves, proof), BURN and the turnstile, LIST, TAKE, CLAIM, team unlocks;
  4. keep the note tree, a root per height and Merkle paths;
  5. keep the digest over the events' encoding (§6);
  6. undo up to 288 blocks on a reorg;
  7. follow Bitcoin Core or Esplora, keeping the blocks read (`--data`);
  8. serve the read-only API of `docs/API.md`;
  9. verify spends through the pinned verifier (`adapters/plonk.js`);
  10. the tools the README names: replay, vectors, fuzz, api-diff and their chain generator.

## 2. Measurements

Machine: a 2-core Intel Xeon at 2.10 GHz, Node 22.23.4; best of 5 runs (`node bin/bench.js`, added
by this run).

| | Before | After |
| --- | ---: | ---: |
| BIP340 verification, one signature | 99.9 ms | 1.49 ms |
| BIP340 signature (tests, vectors) | — | 2.14 ms |
| Replay of a random chain of 400 blocks (1,376 leaves, 756 nullifiers, test verifier) | 2,220 ms (180 blocks/s) | 1,746 ms (229 blocks/s) |
| Poseidon of two inputs | 7,103 a second | unchanged |
| Tree, 20,000 appends | 3,105 ms | unchanged |
| Tree, one path | 4.6 µs | unchanged |
| Codec, one MINT parsed | 3.0 µs | unchanged |
| API, largest route (`/notes`, 320 KiB for 1,376 notes) | 3.3 ms | unchanged |
| Lines of code in `src/` (no comments, no blank lines) | 1,696 | 1,720 |
| Line coverage of `src/` by `npm test` | 97.27 % | 98.38 % |
| Branch coverage | 87.05 % | 88.18 % |
| `npm test` | 68 tests | 72 tests |

Where the time of a replay goes, by a CPU profile of three replays of that chain: before this run,
BIP340 point arithmetic (`powMod` in `schnorr.js`, the inversions) took most of a run that included
generating the chain's signatures; after it, `permute` in `poseidon.js` is 86.7 %, the tree 3.7 %,
the garbage collector 2.8 %, everything else under 1 % each.

## 3. Findings

| Id | Kind | Where | Evidence | Gain |
| --- | --- | --- | --- | --- |
| code-indexer-1 | faster | `src/schnorr.js` | 99.9 ms a verification: affine coordinates, one Fermat inversion (≈ 256 squarings) per point operation | 67 times faster; done |
| code-indexer-2 | superfluous | `src/codec.js`, `Reader.u16` and `Writer.u16` | no caller anywhere (search), never run (coverage); no field of the wire has 2 bytes | 11 lines; done |
| code-indexer-3 | untested | `src/api.js`, the `vPub` and `pre` names of BURN and TEAM_UNLOCK events, and `/block/:height` for a block with no activity | reached only by `bin/api-diff.js`, which `npm test` does not run | a test; done |
| code-indexer-4 | untested | `src/indexer.js`, refusing a block that does not follow the last one | never run (coverage) | a test; done |
| code-indexer-5 | faster | `src/poseidon.js`, `permute` | 86.7 % of a replay; 141 µs a hash of two inputs, about 828 products | about a quarter of the products; open |
| code-indexer-6 | better (done, §6) | event records (`v`, `positions`, a nested `burn`) and `src/api.js` `apiEvent`, which renames them to the spec's (`vPub`, `pre`, `pos`, flat `nullifiers`) | two names for one field, kept apart by a translation | the translation goes; open |
| code-indexer-7 | superfluous | exports nothing imports: `parseScript`, `minimalPushData`, `tapscriptOf` (`carrier.js`), `OUT_BYTES` (`constants.js`), `EVENT_CODE`, `TAKE_OUTCOME` (`events.js`), `Reject`, `rejectAllVerifier` (`indexer.js`), `DEFAULT_VK` (`adapters/plonk.js`) | search across the repository | a narrower module surface; open, low |

**code-indexer-1.** The indexer verifies a BIP340 signature for each CLAIM, and the vault verifies
each signature it makes before it returns it (`vault/src/secp256k1.js` imports this `verify`). Each
point addition paid a modular inversion by exponentiation, so a verification took about 100 ms.
Besides the time, that was a cheap way to slow an indexer down: a CLOSED listing accepts CLAIM
attempts without limit until one succeeds, the signature is checked after the cheap checks, and so
each attempt with a wrong signature cost the indexer 100 ms; 1,000 of them in a block, about
200,000 satoshis of fees at 1 sat/vB, cost it 100 s. Now the points stay in Jacobian coordinates
during a multiplication (one inversion at the end), and `s·G − e·P` shares its doublings, with
4-bit windows: 1.49 ms. The bytes are the same: the eight signing vectors of BIP340 (keys,
signatures, and that they verify), and the same key, signature and verdict as the old code for 14
keys (among them `1`, `2`, `3`, `n − 1`, `n − 2`, `(n − 1)/2`, `2^255`) and eight inputs each,
valid and broken (`s + 1`, another message, another key, `r = p`, `s = n`, `s = 0`, a key at `p`):
`test/schnorr.test.js`. The old code stays, for that test only, in `test/schnorr-reference.js`.
`npm run vectors` gives the same bytes; the fuzzer (30 chains, 1,190 blocks, 2,607 refused
envelopes) and `api-diff` through a reorg find no divergence; the vault's 146 tests pass on it.

**code-indexer-5.** Every leaf costs three Poseidon hashes and the tree about one more, so a
restart of a mainnet indexer with a million leaves spends about 9 minutes in Poseidon at today's
speed. The permutation is already written with lazy reductions. What is left is the optimised form
of the partial rounds (the sparse matrices of the Poseidon paper's appendix B, which circomlib ships
as `poseidon_constants_opt`): each of the 57 partial rounds of width 3 would multiply by a sparse
matrix (5 products) instead of the full one (9). Not done here: the decomposition has to be derived
for widths 3 to 6 and checked against circomlibjs for each, which `test/primitives.test.js` already
does for the plain form.

**code-indexer-6.** The indexer's event records keep their own field names, the ones the digest
encoder reads; the API renames them to the spec's names (`docs/API.md`, "Events"). The encoding of
the digest goes by position, so renaming the record fields to the spec's would change no byte and
remove `apiEvent`'s renaming. It touches `indexer.js`, `events.js` and `api.js` at once, so it is
left for a pull request of its own, checked with the vectors, the fuzzer and `api-diff`.

**code-indexer-7.** Harmless, and some of these names are cited by `docs/AUDIT.md`; removing an
`export` would make the module's surface say what is used. Low.

## 4. Changed in this run

- `src/schnorr.js`: Jacobian coordinates and a joint windowed multiplication (code-indexer-1).
- `src/codec.js`: the unused `u16` reader and writer removed (code-indexer-2).
- `test/schnorr.test.js` and `test/schnorr-reference.js`; a test in `test/api.test.js` and one in
  `test/indexer.test.js` (code-indexer-3 and -4).
- `bin/bench.js`: the timings of §2, so that the next run starts from numbers.
- `docs/AUDIT.md`: the line numbers this moved, and the verification time §8.7 quoted.

Suites: `npm test` in `indexer/`, 72 tests, all pass; `npm run vectors`, the same bytes; `node
bin/fuzz.js --seed ci --chains 30 --blocks 40` and `node bin/api-diff.js --seed ci --reorg 3,2`
against `indexer-rs`, no divergence; `npm test` in `vault/`, 146 tests, 145 pass, 1 skipped (the
prover rebuild); `docs/tools/check-audit-refs.py`, 0 problems.

## 5. Open

- code-indexer-5, -6 and -7, above.
- Branches that a stricter check before them always takes first, kept as the prompt says: the
  `unknown type` refusal of `indexer.js` (the codec refuses an unknown type before) and the
  `unknown event type` of `events.js`.
- The block file's handling of a damaged line in the middle of the file (`blockfile.js`, a line
  that does not parse, or parses and is not a block) has no test of its own; a cut last line has.
- The follower's loop (`run`) and the Bitcoin Core source are exercised by processes (the regtest
  flow, `follow-data.test.js`), which the coverage figure does not count.

## 6. Follow-up, the same day

After the report, two more changes, each behind the same checks (`npm test` 72/72; the vectors and
the explorer's demo data regenerated, the vectors unchanged; the fuzzer, 30 chains and 1,190 blocks,
and `api-diff` through a reorg of 3 blocks into 5 and of 2 into 2: no divergence):

- **code-indexer-6, done.** The event records now carry the spec's names (`pos`, `vPub`, `pre`, and a
  DEPLOY's burn as flat `nullifiers` and `pos`), which the digest encoder reads; `apiEvent` shrinks to
  dropping a LIST's own txid. The demo data of the explorer changes only in the order of keys. The
  explorer still reads the old shapes too (`e.burn`, `e.v`): that fallback is now dead, for the code
  audit of `explorer`.
- **A leaf costs fewer hashes (new, code-indexer-8).** `noteLeaf` keeps `H(TAG_LEAF, t)` and
  `H(H(TAG_LEAF, t), v)`, which every MINT of a ticker shares: a MINT's leaf is two Poseidon hashes
  instead of four. Each cache holds at most 4,096 entries and starts again when full, so amounts that
  anyone chooses cannot make it grow. The replay of §2: 1,746 ms → 1,582 ms (253 blocks a second);
  more on a chain that is mostly mints, as the first blocks after an activation are.
- **code-indexer-5, revised.** The sparse partial rounds remove about a quarter of the products, but
  not one of the reductions modulo `p`, which cost as much: about 10 to 15 % of a hash. Still open, and
  lower than the leaf cache was.
