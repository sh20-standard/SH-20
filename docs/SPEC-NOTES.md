# SH-20 notes for wallets: keys, addresses, sealing and scanning — draft v0.3

Status: draft, **security-critical, not reviewed and not audited**. Indexers never open a note and do not depend on
anything here except the byte sizes of `pk_eph` and `ct` (`SPEC-WIRE.md` §4). This document is normative for wallets:
two wallets that follow it can send to each other and restore each other's seeds.

Notation: `‖` concatenation; `B8`, `l` and BabyJubJub as in `SPEC-WIRE.md` §4; `r` the BN254 scalar field;
`noteLeaf`, `tickerT` as in `SPEC-WIRE.md` §2; `Poseidon(n inputs)` circomlib's; tags are ASCII strings.

```
hs(tag, x) = int_be( SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01) ) mod l      (a BabyJubJub scalar)
hr(tag, x) = int_be( SHA256(tag ‖ x ‖ 0x00) ‖ SHA256(tag ‖ x ‖ 0x01) ) mod r      (a field element)
```

`hs` returns 0 with probability below 2^-250; a wallet that meets it treats the note as invalid.

## 1. Keys

A wallet holds one 32-byte master secret `m`. From a BIP39 mnemonic (and optional passphrase), with `seed` its
64-byte BIP39 seed: `m = first 32 bytes of HMAC-SHA512(key = "sh20/v0/seed", data = seed)`.

| Key | Value | Role |
| --- | --- | --- |
| `ask` | `hs("sh20/v0/key/ask", m)` | spend authority (signs, through a per-note tweak) |
| `nsk` | `hs("sh20/v0/key/nsk", m)` | nullifier key (computes spends, through a per-note tweak) |
| `ivk` | `SHA256("sh20/v0/key/ivk" ‖ m)` | X25519 private key (RFC 7748; clamped when used) |
| `A`, `N`, `IVK` | `ask·B8`, `nsk·B8`, `X25519(ivk, 9)` | the public halves, in the address |

Capabilities: `(ivk, A, N)` finds and reads incoming notes (an *incoming viewing key*); adding `nsk` also shows which
of them are spent (a *full viewing key*); spending needs `ask`. The Bitcoin keys that pay fees are separate and stay in
the user's Bitcoin wallet.

## 2. Address

`address = bech32m(hrp, 0x00 ‖ IVK (32) ‖ pack(A) (32) ‖ pack(N) (32))`, 97 bytes of payload, about 167 characters.
`hrp` is `sh20` on mainnet and `tsh20` on signet and testnet. The 90-character limit of BIP173 does not apply (as for
Zcash unified addresses). `pack` is circomlib's `packPoint`: `y` as 32 bytes little-endian, with the top bit of the last
byte set when `x > (r − 1) / 2`. The first payload byte is the address version; a wallet rejects any other value.

One address can be published and reused forever: nothing on chain links two notes sent to it.

## 3. Sealing an output (sender)

For an output of `v` units of the token `ticker` to the address `(IVK, A, N)`:

1. Draw a fresh X25519 private key `e` for **this output only** (never reuse it). `pk_eph = X25519(e, 9)`, 32 bytes.
2. `z = X25519(e, IVK)`. If `z` is 32 zero bytes, start again with a new `e`.
3. `s = HKDF-SHA256(salt = "sh20/v0/note", ikm = z, info = pk_eph ‖ IVK, L = 32)`.
4. Note values: `τa = hs("sh20/v0/note/tweak-a", s)`, `τn = hs("sh20/v0/note/tweak-n", s)`,
   `rho = hr("sh20/v0/note/rho", s)`.
5. Note keys: `Ak = A + τa·B8`, `NK = N + τn·B8`, `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)`;
   `leaf = noteLeaf(tickerT(ticker), v, npk, rho)`.
6. `key ‖ nonce = HKDF-SHA256(salt = "sh20/v0/note/aead", ikm = s, info = leaf (32, as on the wire), L = 44)`.
7. `ct = AES-256-GCM(key, nonce, plaintext = v (u64 LE) ‖ ticker (4 ASCII), aad = leaf (32, as on the wire))`:
   12 bytes of ciphertext and a 16-byte tag, 28 bytes.

The output on the wire is `leaf ‖ pk_eph ‖ ct`. `ct` carries no key and no `rho`: both follow from `s`.

**Unused outputs.** A spend always has three outputs. An unused one carries `v = 0`, sealed to the sender's own address
with its own fresh `e`, so that every output looks the same. The third output is meant to pay a relayer in tokens.

## 4. Scanning (recipient)

For every note of kind `OUT` (`docs/API.md`: `leaf`, `pkEph`, `ct`, position `pos`):

1. `z = X25519(ivk, pk_eph)`; skip if `z` is all zeros. Derive `s`, then `key ‖ nonce` with this `leaf`.
2. Open `ct` with AES-256-GCM and `aad = leaf`. A failed tag means the note is not for this wallet.
3. **Check the leaf.** Derive `τa, τn, rho` from `s`, compute `npk` from `A, N` and
   `leaf' = noteLeaf(tickerT(ticker), v, npk, rho)`. If `leaf' ≠ leaf`, ignore the note: it was sealed wrong or on purpose
   to mislead, and it cannot be spent.
4. Keep `(pos, leaf, ticker, v, rho, τa, τn)`. To spend: signing key `ask + τa mod l`, nullifier key
   `nk = nsk + τn mod l`, nullifier `Poseidon(nk, leaf, pos)` (`SPEC-WIRE.md` §4).

The wallet downloads every note and every nullifier (`/notes`, `/nullifiers`) and does all of this on the device; it
never asks an indexer about one of its own notes. One X25519 and one AES-GCM attempt per output, both native in
WebCrypto in current browsers and in Node.

## 5. Public notes (mint, purchase, reclaim, team)

These notes publish their opening, `npk` alone, use `rho = 0` (`SPEC-WIRE.md` §2) and have no `pk_eph` or `ct`. A wallet
derives them from its master secret and a counter `i`, so that a restored wallet finds them:

`s_i = HKDF-SHA256(salt = "sh20/v0/self", ikm = m, info = u32le(i), L = 32)`, then `τa, τn, npk` from `s_i` as in §3
(no `rho`: it is 0). The counter must never repeat: two public notes with the same `npk` would be linked.

On restore, a wallet scans the public notes for `npk` with `i = 0, 1, …` and stops after 50 unused values in a row.
A public note is linked to the Bitcoin transaction that created it, by design. It becomes private the first time it is
spent. Change sent to oneself in a spend uses §3 with the wallet's own address, so scanning finds it like any other note.

## 6. Security notes and review items

- `e` must be fresh for each output. The nonce also depends on the leaf, so a reused `e` still never repeats a
  (key, nonce) pair for two different notes; two identical notes would only show up as identical bytes.
- Per-note keys: `Ak`, `NK`, `τa`, `τn` never appear on chain (only `npk`, inside a leaf or a public opening), so the
  tweaks are there to keep public notes unlinkable to each other, and to bound what one leaked note key reveals.
- The leaf check (§4.3) is what makes a sealed note trustworthy: the plaintext alone proves nothing.
- Not post-quantum, like Zcash today: an attacker with a large quantum computer could open old notes (token, amount,
  recipient). The tweak and nullifier keys stay inside proofs and hashes.
- Reference code must not branch on secrets. The JavaScript BigInt arithmetic of `circuit/js` is not constant time.
- Public notes with `rho = 0`: their leaf hides nothing anyway, and the nullifier `Poseidon(nk, leaf, pos)` differs for two notes
  with the same leaf because `pos` differs. Review item: confirm nothing else relied on a random `rho` in public notes.
- To review before activation (circuit session, then the audit): the whole of §1–§5, and the test vectors.

## 7. Test vectors

To be written with the reference implementation in `circuit/js` (sealing, scanning, the leaf check, the address
encoding, the self-note derivation), from fixed seeds, and checked by the Rust model.
