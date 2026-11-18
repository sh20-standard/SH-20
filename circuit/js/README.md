# circuit/js

What a wallet computes, in plain JavaScript with no dependency: the values the spend circuit
recomputes from the wallet's secrets and checks (`docs/SPEC-WIRE.md` §4), and the note scheme of
`docs/SPEC-NOTES.md` (keys, addresses, sealing, scanning). If the vault derives a key, a nullifier, a
signature or a sealed note any other way, its proofs do not verify or its notes are never found;
this folder is the reference to compare against.

| Function | What |
| --- | --- |
| `noteKeys(sk, nk)` | `Ak = sk·B8`, `NK = nk·B8`, `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)` |
| `npkOf(ak, nkPub)` | `npk` from the two points |
| `nullifier(nk, leaf, index)` | `Poseidon(nk, leaf, index)` |
| `bodyHash(body)` | `SHA256("sh20/v0/body" ‖ body) mod r` |
| `sign(sk, m)` | EdDSA-Poseidon over BabyJubJub: `{ r8, s }` with `S·B8 = R8 + h·8·Ak`, `h = Poseidon(R8, Ak, m)` |
| `verify(ak, m, sig)` | true exactly when the circuit accepts the signature |
| `masterSecret(bip39Seed)`, `walletKeys(m)` | `{ ask, nsk, ivk, address: { ivkPub, a, n } }` (SPEC-NOTES §1) |
| `encodeAddress(hrp, address)`, `decodeAddress(hrp, string)` | bech32m; decoding makes every check a payer owes (§2) and throws otherwise |
| `seal(address, ticker, v, e)` | an output `{ leaf, pkEph, ct }` for an address, with the note's `{ secrets, npk }` for the proof (§3) |
| `scan(ivk, address, output)` | the note `{ ticker, v, secrets, npk }`, or `null` unless it is ours **and** hashes to its leaf (§4) |
| `spendKeys(keys, secrets)` | the note keys `sk = ask + τa`, `nk = nsk + τn` |
| `publicOpening(ivk, address, i)` | the `npk` of the wallet's i-th public note, `rho = 0` (§5) |
| `poseidon`, `noteLeaf`, `tickerT` | re-exported from `indexer/src/` |
| `add`, `mul`, `mulBase8`, `onCurve`, `packPoint`, `unpackPoint`, `x25519`, `L`, `BASE8` | BabyJubJub, X25519 |

Scalars and field elements are `BigInt`; points are `[x, y]`. A scalar or a position out of range
is a `RangeError`, never silently reduced: `nk + l` is the same point as `nk` but would be another
nullifier, and the circuit refuses it.

```sh
npm test        # 25 tests, Node 20 or newer
```

## The vectors

`vectors.json` is written by the models on the Rust side (`circuit/src/model.rs`, which the circuit
constrains, and `circuit/src/notes.rs`, through `circuit/src/vectors.rs`), from fixed seeds:

- Poseidon for 2 to 5 inputs, ticker ids, note keys at both ends of the scalar range, leaves,
  nullifiers at the first and the last position of the tree, body hashes, signatures;
- three wallets from their BIP39 seeds with every key and both addresses, thirteen addresses a
  payer must refuse, sealed outputs with their ephemeral keys, public notes;
- one whole transfer between the three wallets: public notes spent, three sealed outputs, the tree,
  the envelope body (wire v0.3) and the nine public inputs. It satisfies the circuit's gates; the
  generator checks it, and that each wallet finds exactly its own output.

The sealing side shares no cryptographic code with the Rust model: X25519, HKDF and AES-GCM are
Node's here and RustCrypto's there, and both are also checked against RFC 7748 and BIP-350.

```sh
cd circuit && cargo run --release --example vectors -- js/vectors.json
```

`cargo test` fails if the file is not the one the model writes, and `npm test` here fails if the
JavaScript disagrees with it. Poseidon itself is tied to circomlib by
`indexer/test/fixtures/poseidon-circomlibjs.json` (from circomlibjs, `bench/poseidon-vectors.mjs`),
which both the indexer's tests and `cargo test` read.

## What this is not

- **Not hardened.** `BigInt` arithmetic is not constant-time, so signing with this code leaks timing.
  It says what to compute, not how to compute it safely.
- **Not reviewed outside.** `docs/SPEC-NOTES.md` and this code were read once by the session that
  wrote the circuit. That is not an audit.
- **The nonce is a convention.** `sign` derives it from the key and the message as the Rust model
  does, so that signatures are reproducible. Any nonce gives a signature the circuit accepts; one
  that repeats across two messages gives away the key.
- SHA-256, HMAC, HKDF, X25519 and AES-GCM come from `node:crypto`. A browser build puts WebCrypto
  (asynchronous) or its own code in their place: `notes.js`, `eddsa.js`, `address.js`, `seal.js`.
