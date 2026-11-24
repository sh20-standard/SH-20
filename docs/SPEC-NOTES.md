# SH-20 notes for wallets: keys, addresses, sealing and scanning — draft v0.3

Status: draft, **security-critical, not audited**; reviewed once by the circuit session (2026-11-18, changes in §8). Indexers never open a note and do not depend on
anything here except the byte sizes of `pk_eph` and `ct` (`SPEC-WIRE.md` §4). This document is normative for wallets:
two wallets that follow it can send to each other and restore each other's seeds.

Notation: `‖` concatenation; `B8`, `l` and BabyJubJub as in `SPEC-WIRE.md` §4; `r` the BN254 scalar field;
`noteLeaf`, `tickerT` as in `SPEC-WIRE.md` §2; `Poseidon(n inputs)` circomlib's; tags are ASCII strings.

```
hs(tag, x) = int_be( SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01) ) mod l      (a BabyJubJub scalar)
hr(tag, x) = int_be( SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01) ) mod r      (a field element)
```

`x` is always 32 bytes, so no two uses of `hs` or `hr` hash the same string. `hs` returns 0 with probability below
2^-250; a wallet that meets it treats the note (or the seed) as invalid, and so it does if a note's signing or
nullifier key of §4.5 comes out as 0.

Encodings: a field element is 32 bytes little-endian (`SPEC-WIRE.md` §1); `v` is a u64 little-endian; a ticker is its
4 ASCII bytes; `X25519` is the function of RFC 7748 on 32-byte strings (it clamps its private key).

## 1. Keys

A wallet holds one 32-byte master secret `m`. From a BIP39 mnemonic (and optional passphrase), with `seed` its
64-byte BIP39 seed and `hrp` the address prefix of the network (§2) in ASCII:
`m = first 32 bytes of HMAC-SHA512(key = "sh20/v0/seed", data = seed ‖ hrp)`.

`hrp` is `sh20` on mainnet and `tsh20` on every test network: 4 or 5 bytes after a seed that is always 64, so the two
inputs are never the same string. **The network is in every key.** One set of words gives unrelated keys on mainnet and
on the test networks: the address, the public openings (§5) and anything else derived from `m` on a test network do
not appear on mainnet, and seeing a wallet on one does not recognise it on the other. A wallet names its network when
it derives `m` and refuses any other prefix, or none; a seed of another length is refused too.

| Key | Value | Role |
| --- | --- | --- |
| `ask` | `hs("sh20/v0/key/ask", m)` | spend authority (signs, through a per-note tweak) |
| `nsk` | `hs("sh20/v0/key/nsk", m)` | nullifier key (computes spends, through a per-note tweak) |
| `ivk` | `SHA256("sh20/v0/key/ivk" ‖ m)` | X25519 private key (RFC 7748; clamped when used) |
| `A`, `N`, `IVK` | `ask·B8`, `nsk·B8`, `X25519(ivk, 9)` | the public halves, in the address |

Capabilities: `(ivk, A, N)` finds and reads every note of the wallet, sealed (§4) or public (§5): an *incoming viewing
key*. Adding `nsk` also shows which of them are spent (a *full viewing key*). Spending needs `ask` as well. The Bitcoin keys that pay fees are separate and stay in
the user's Bitcoin wallet.

## 2. Address

`address = bech32m(hrp, 0x00 ‖ IVK (32) ‖ pack(A) (32) ‖ pack(N) (32))`, 97 bytes of payload, 167 characters on mainnet.
`hrp` is `sh20` on mainnet and `tsh20` on signet and testnet. The first payload byte is the address version.

- `bech32m` is BIP-350 without the 90-character limit of BIP-173 (as for Zcash unified addresses). At this length the
  checksum no longer guarantees to catch every error of up to four characters; it still misses a random error only once
  in 2^30.
- `pack` is circomlib's `packPoint`: `y` as 32 bytes little-endian, with the top bit of the last byte set when
  `x > (r − 1) / 2`.

**A payer checks an address before sending to it, and refuses it unless all of this holds:**

1. The string is all lowercase or all uppercase, its bech32m checksum is valid, and its `hrp` is the one of the network.
2. The payload is exactly 97 bytes (fewer than 5 padding bits, all zero) and starts with the version `0x00`.
3. `pack(A)` and `pack(N)` decode: `y < r`; `x² = (1 − y²) / (168700 − 168696·y²)` has a square root, and `x` is the
   root with the stated sign; the encoding of `x = 0` with the sign bit set is refused.
4. `A` and `N` are in the subgroup of order `l` (`l·P` is the identity) and are not the identity.
5. `IVK` is not a low-order point: `X25519(k, IVK)` is not 32 zero bytes (for any `k`; it does not depend on it).
6. `IVK` is in its one encoding: read as a little-endian integer it is below `p = 2^255 − 19` (so bit 255 is clear).

Without 3 and 4 the payer would compute note keys with an addition law that does not hold, and the note could never be
spent. Without 5 the "shared secret" is known to everyone. Without 6 an address has other writings that X25519 reads as
the same key (RFC 7748 ignores bit 255 and reduces modulo `p`: `IVK` with that bit set, and `IVK + p` for the nineteen
smallest values), while §3 hashes the 32 bytes of `IVK` into `s` as the address writes them: the owner, who scans with
its own writing, never finds what was sealed to another one. A sender refuses such an `IVK` in an address it did not
decode itself as well.

One address can be published and reused forever: nothing on chain links two notes sent to it. Payers who compare
notes do see that they pay the same address.

## 3. Sealing an output (sender)

For an output of `v` units of the token `ticker` to the address `(IVK, A, N)`:

1. Draw a fresh X25519 private key `e` for **this output only** (never reuse it). `pk_eph = X25519(e, 9)`, 32 bytes.
2. `z = X25519(e, IVK)`. If `z` is 32 zero bytes the address is invalid (§2, check 5): stop. A new `e` would not help.
3. `s = HKDF-SHA256(salt = "sh20/v0/note", ikm = z, info = pk_eph ‖ IVK (64 bytes), L = 32)`, with `IVK` the 32 bytes
   of the address (its one encoding: §2, check 6).
4. Note values: `τa = hs("sh20/v0/note/tweak-a", s)`, `τn = hs("sh20/v0/note/tweak-n", s)`,
   `rho = hr("sh20/v0/note/rho", s)`.
5. Note keys: `Ak = A + τa·B8`, `NK = N + τn·B8`, `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)`;
   `leaf = noteLeaf(tickerT(ticker), v, npk, rho)`.
6. `key (32) ‖ nonce (12) = HKDF-SHA256(salt = "sh20/v0/note/aead", ikm = s, info = leaf (32 bytes), L = 44)`.
7. `ct = AES-256-GCM(key, nonce, plaintext = v (8) ‖ ticker (4), aad = leaf (32 bytes))`:
   12 bytes of ciphertext followed by the 16-byte tag, 28 bytes.

The output on the wire is `leaf ‖ pk_eph ‖ ct`. `ct` carries no key and no `rho`: both follow from `s`.

**Unused outputs.** A spend always has three outputs. An unused one carries `v = 0`, sealed to the sender's own address
with its own fresh `e`, so that every output looks the same. The third output is meant to pay a relayer in tokens.

**Unused inputs.** A spend always has two inputs. An unused one is a note of `v = 0` that is not in the tree
(`SPEC-WIRE.md` §4): the wallet makes it up with fresh random `sk`, `nk` in `[1, l)` and `rho`, any `index`, and signs for
it like for a real one. Its nullifier is published and must never have been seen, which fresh randomness ensures.

**What the sender keeps.** Nothing here lets a restored wallet read what it sent: there is no outgoing viewing key. Its
balance is still right after a restore (its spent notes show by their nullifiers, its change is found by scanning), but
amounts and recipients of past payments are only in the wallet's own records.

## 4. Scanning (recipient)

For every note of kind `OUT` (`docs/API.md`: `leaf`, `pkEph`, `ct`, position `pos`):

1. Skip the note if `pk_eph` is a point of low order: with bit 255 cleared, one of the seven encodings below, the only
   values for which `X25519(k, pk_eph)` is all zeros (for any `k`). Decide it from the bytes of `pk_eph`, before the
   library is asked: some libraries refuse such a point instead of returning zeros, with the error they also give for
   a failure of their own. Otherwise `z = X25519(ivk, pk_eph)`; a library that fails here, or returns zeros, is an
   error to report, never a skipped note. Derive `s`, then `key ‖ nonce` with this `leaf`.

   ```
   0000000000000000000000000000000000000000000000000000000000000000    0
   0100000000000000000000000000000000000000000000000000000000000000    1
   e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800    order 8
   5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157    order 8
   ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f    p − 1
   edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f    p = 2^255 − 19
   eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f    p + 1
   ```
2. Open `ct` with AES-256-GCM and `aad = leaf`. A failed tag means the note is not for this wallet.
3. Skip the note unless the last 4 bytes of the plaintext are a ticker (`[A-Z0-9]`).
4. **Check the leaf.** Derive `τa, τn, rho` from `s`, compute `npk` from `A, N` and
   `leaf' = noteLeaf(tickerT(ticker), v, npk, rho)`. If `leaf' ≠ leaf`, ignore the note: it was sealed wrong or on purpose
   to mislead, and it cannot be spent.
5. Keep `(pos, leaf, ticker, v, rho, τa, τn)`. To spend: signing key `ask + τa mod l`, nullifier key
   `nk = nsk + τn mod l`, nullifier `Poseidon(nk, leaf, pos)` (`SPEC-WIRE.md` §4).

A note is identified by its position, never by its leaf: the same leaf can be in the tree twice (a sender repeating an
output, two public notes with one `npk`), and both are then real notes with different nullifiers. A wallet that keyed
its notes by leaf would lose one. A note of `v = 0` is an unused output: keep it out of the balance.

The wallet downloads every note and every nullifier (`/notes`, `/nullifiers`) and does all of this on the device; it
never asks an indexer about one of its own notes. One X25519 and one AES-GCM attempt per output, both native in
WebCrypto in current browsers and in Node.

## 5. Public notes (mint, purchase, reclaim, team)

These notes publish their opening, `npk` alone, use `rho = 0` (`SPEC-WIRE.md` §2) and have no `pk_eph` or `ct`. A wallet
derives them from its viewing key and a counter `i`, so that a restored wallet, or a watch-only one, finds them:

`s_i = HKDF-SHA256(salt = "sh20/v0/self", ikm = ivk, info = u32le(i), L = 32)`, then `τa, τn` from `s_i` and `npk` from
them as in §3 (no `rho`: it is 0). The keys that spend the note are those of §4.5.

The counter must never repeat: two public notes with the same `npk` would be linked to each other, and would have the
same leaf if they also carry the same token and amount (still two notes, see §4).

On restore, a wallet scans the public notes for `npk` with `i = 0, 1, …` and stops after 50 unused values in a row.
A public note is linked to the Bitcoin transaction that created it, by design. It becomes private the first time it is
spent. Change sent to oneself in a spend uses §3 with the wallet's own address, so scanning finds it like any other note.

## 6. Security notes

- `e` must be fresh for each output. The key and the nonce also depend on the leaf, so a reused `e` never repeats a
  (key, nonce) pair for two different notes; two identical notes would only show up as identical bytes. A reused `e`
  does show on chain as a repeated `pk_eph`.
- The leaf check (§4.4) is what makes a sealed note trustworthy: the plaintext alone proves nothing. AES-GCM does not
  commit to its key, so a sender can build one `ct` that opens under two recipients' keys; the leaf, a hash of each
  recipient's own `npk` and `rho`, can only be right for one of them.
- Per-note keys: `Ak`, `NK`, `τa`, `τn` never appear on chain (only `npk`, inside a leaf or a public opening). The
  tweaks keep public notes unlinkable to each other. They do **not** make a note's keys independent of the wallet's: a
  per-note secret (`ask + τa`, or `nsk + τn`) together with its tweak gives the wallet secret back, and the tweak is
  known to the sender of the note and to anyone holding `ivk`. So a per-note secret is as sensitive as `ask` or `nsk`.
  A prover that is not the wallet receives `nsk + τn` for each input it proves (it needs it for the nullifier); it must
  not also be given `ivk`, and it never receives a signing key (the wallet hands it signatures).
- Signatures are never published: they stay inside proofs. Nothing in this scheme relies on them being safe to show.
- An address is three keys that nothing ties together. Someone who replaces `IVK` in a victim's address makes payers
  seal notes that the victim cannot find and nobody can spend. Addresses must reach payers through a channel the payer
  trusts; the checksum only catches typing errors.
- Public notes with `rho = 0`. Nothing else relied on a random `rho` there: the leaf of a public note hides nothing (token,
  amount and `npk` are published), the nullifier `Poseidon(nk, leaf, pos)` is unlinkable to the note because `nk` is
  secret, and two notes with the same leaf still have different nullifiers because `pos` differs. Anyone can now compute
  the leaf of a public note for an `npk` seen on chain and create a second note with it; that is a gift to the owner of
  `npk`, who alone can spend it. The one consequence for wallets is the rule of §4: identify a note by its position.
- Not post-quantum, like Zcash today: an attacker with a large quantum computer could open old notes (token, amount,
  recipient). The tweak and nullifier keys stay inside proofs and hashes.
- Reference code must not branch on secrets. The JavaScript BigInt arithmetic of `circuit/js` is not constant time.

## 7. Test vectors

`circuit/js/vectors.json`, written from fixed seeds by the Rust model (`circuit/src/notes.rs`, through
`circuit/src/vectors.rs`): three wallets from their BIP39 seeds, each on the test networks and on mainnet (every key
and the address; the rest of the file uses the keys of the test networks), fifteen addresses a payer must refuse, sealed
outputs with their ephemeral keys, public notes, and a whole transfer between the three wallets with its envelope body. `circuit/js` (`address.js`, `seal.js`) restates this document with Node's own X25519, HKDF and
AES-GCM and reproduces every byte; `cargo test` fails if the file is not the one the model writes. The indexer's
end-to-end test replays a chain made the same way (`indexer/test/fixtures/plonk-scenario.json`).

## 8. Review log

2026-11-18, circuit session, against the reference code and the vectors above. Changed:

1. §3.2: a zero `z` means the address is invalid; the text said to draw a new `e`, which would loop forever.
2. §2: the checks a payer makes on an address are now written out (canonical points, the subgroup, a low-order `IVK`).
   The text only gave the encoding.
3. §5: public notes are derived from `ivk`, not from `m`. With `m`, a viewing key could not find the wallet's own mints,
   against what §1 says a viewing key does.
4. §6: the claim that tweaks "bound what one leaked note key reveals" was wrong for anyone who knows the tweak.
5. §4: the ticker check before the leaf check; notes are identified by position; some libraries throw on a low-order `pk_eph`.
6. Added: encodings, unused inputs, what a restored wallet cannot recover, the address-substitution risk, why the leaf
   check also covers the lack of key commitment in AES-GCM, and the review of `rho = 0`.

2026-11-20, circuit session. Changed:

7. §4, step 1: a low-order `pk_eph` is recognised from its bytes, listed there, and a failure of the library no longer
   skips a note. The text let any refusal of the library be read as "not for this wallet"; the reference did the same
   with every `OperationError` of WebCrypto (`docs/AUDIT.md` §8.6).

2026-11-24, our own audit, part `sealing` ([`audit/2026-11-24-sealing.md`](audit/2026-11-24-sealing.md)). Nothing
changed here. Three things are left to this document's owner. §4, "never asks an indexer about one of its own notes":
true of what a wallet asks, not of how long it takes to answer (sealing-1 of that report). §1: whether the network
should enter `m` (sealing-4: the same words give the same keys on signet and on mainnet). §2 and §4: whether an `IVK`
or a `pk_eph` that is not a canonical encoding should be refused, as one of low order is (sealing-6, sealing-2).

2026-11-24, circuit session, two decisions of the maintainer on that report. Changed:

8. §1: the network is in `m`, through its address prefix (sealing-4). Before, the same words gave the same `IVK`, `A`,
   `N`, public openings and everything a wallet derives from `m` on signet and on mainnet, and whoever had used a set of
   words on a test network was recognised on mainnet at the first thing it published. The prefix is in the derivation
   on every network, the test ones included: **words written before this change give other keys now, on signet too.**
   No network with value ran before it. A wallet that kept `m` itself keeps its keys.
9. §2, check 6: an address has one encoding of `IVK` (sealing-6). The decoders accepted the others, and what was sealed
   to them was lost to its owner. §3.3 says which bytes of `IVK` are hashed.

`pk_eph` is not touched: a scan reads every encoding of it as RFC 7748 does (the reference hands its library the
canonical one, sealing-2), and whether a wallet should refuse the others is still open. So is sealing-1.

Still to do: an outside review.
