# circuit/js

What a wallet computes for an SH-20 spend, in plain JavaScript with no dependency: the values the
spend circuit recomputes from the wallet's secrets and checks. If the vault derives a key, a
nullifier or a signature any other way, its proofs do not verify; this folder is the reference to
compare against.

| Function | What |
| --- | --- |
| `noteKeys(sk, nk)` | `Ak = sk·B8`, `NK = nk·B8`, `npk = Poseidon(Ak.x, Ak.y, NK.x, NK.y)` |
| `npkOf(ak, nkPub)` | `npk` from the two points |
| `nullifier(nk, leaf, index)` | `Poseidon(nk, leaf, index)` |
| `bodyHash(body)` | `SHA256("sh20/v0/body" ‖ body) mod r` |
| `sign(sk, m)` | EdDSA-Poseidon over BabyJubJub: `{ r8, s }` with `S·B8 = R8 + h·8·Ak`, `h = Poseidon(R8, Ak, m)` |
| `verify(ak, m, sig)` | true exactly when the circuit accepts the signature |
| `poseidon`, `noteLeaf`, `tickerT` | re-exported from `indexer/src/` |
| `add`, `mul`, `mulBase8`, `onCurve`, `L`, `BASE8` | BabyJubJub |

Scalars and field elements are `BigInt`; points are `[x, y]`. A scalar or a position out of range
is a `RangeError`, never silently reduced: `nk + l` is the same point as `nk` but would be another
nullifier, and the circuit refuses it.

```sh
npm test        # 13 tests, Node 20 or newer
```

## The vectors

`vectors.json` is written by the model the circuit constrains (`circuit/src/vectors.rs`), from fixed
seeds: Poseidon for 2 to 5 inputs, ticker ids, note keys at both ends of the scalar range, leaves,
nullifiers at the first and the last position of the tree, body hashes, signatures, and one whole
transfer with its tree, its envelope body and its nine public inputs. That transfer satisfies the
circuit's gates; the generator checks it.

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
- **Not a key scheme.** How a wallet gets `sk`, `nk` and `rho` for each note (from a seed, from a
  shared secret with the payer) is not specified yet, and neither is the sealed note `ct`.
- **The nonce is a convention.** `sign` derives it from the key and the message as the Rust model
  does, so that signatures are reproducible. Any nonce gives a signature the circuit accepts; one
  that repeats across two messages gives away the key.
- SHA-256 comes from `node:crypto`, like the indexer's. A browser build needs a synchronous SHA-256
  in its place (`notes.js`, `eddsa.js`).
