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
npm test                # 48 tests, Node 20 or newer
npm run test:browser    # the WebCrypto primitives in headless Chrome
```

## Two entry points

| | `index.js` | `webcrypto.js` |
| --- | --- | --- |
| For | Node: tests, tools, the vectors | a browser wallet |
| Calls | synchronous | asynchronous where a secret is hashed, agreed on or encrypted |
| X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA512, SHA-256 | `node:crypto` | the browser's WebCrypto (`subtle.js`) |
| Bytes | `Buffer` | `Uint8Array` |

Both export the same names and return the same values; `npm test` runs both through the same
vectors. Asynchronous in `webcrypto.js`: `masterSecret`, `walletKeys`, `decodeAddress`, `seal`,
`scan`, `selfSecret`, `publicOpening`, `noteSecrets`, `hs`, `hr`, `x25519`, `x25519Public`,
`hashToScalar`, `sign`. Everything else is the same function in both.

```js
import { available, masterSecret, walletKeys, decodeAddress, seal, scan } from './webcrypto.js';

if (!(await available())) throw new Error('this browser has no X25519');
const keys = await walletKeys(await masterSecret(bip39Seed));
const out = await seal(await decodeAddress('sh20', string), 'GENE', 700n, e);
const note = await scan(keys.ivk, keys.address, out);
```

Why a wallet in a browser should take `webcrypto.js`: written in JavaScript, X25519 is `BigInt`
arithmetic and AES is table look-ups, and both take a time that depends on the key. WebCrypto runs
them in the browser's own library, with keys imported as non-extractable.

What a browser needs for it:

- **A secure context** (https, or localhost): browsers give `crypto.subtle` to nothing else.
- **X25519 in WebCrypto**: Safari 17, Firefox 130, Chrome 133 by their compatibility tables.
  `available()` checks it with a known answer and is what a wallet should go by. Without X25519 the
  functions reject; they never return "not found" for a note they could not try to open. The same
  holds for every other failure of the platform: a point of low order, the one case where the secret
  is all zeros, is recognised from its bytes (`isLowOrder` in `subtle.js`) and the platform is not
  asked, so an `OperationError` is never read as one. `index.js` follows the same rule with OpenSSL.
- **A stand-in for `node:crypto`**, by an import map. The modules `webcrypto.js` shares with
  `index.js` import it by name: the indexer's constants hash their public tags with
  `createHash('sha256')` when they load, and `address.js` and `seal.js` import what their
  synchronous functions call (`createHmac`, `hkdfSync`, `createCipheriv`, `createDecipheriv`,
  `createPrivateKey`, `createPublicKey`, `diffieHellman`). The stand-in implements `createHash` for
  those public tags and exports the other names; no path of `webcrypto.js` calls them, so they can
  throw. A global `Buffer` is needed for the same shared modules.

`subtle.js` alone has no import and needs none of that: `test/subtle.html` runs its known answers
(RFC 7748, RFC 5869, RFC 4231, the GCM specification, the seven low-order points, and two odd
encodings a platform must accept: bit 255 set, a value above the field size) in any browser.
Checked in Chrome 158; not yet in Safari or Firefox.

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
Node's or the browser's here and RustCrypto's there, and both are also checked against RFC 7748 and
BIP-350.

```sh
cd circuit && cargo run --release --example vectors -- js/vectors.json
```

`cargo test` fails if the file is not the one the model writes, and `npm test` here fails if the
JavaScript disagrees with it. Poseidon itself is tied to circomlib by
`indexer/test/fixtures/poseidon-circomlibjs.json` (from circomlibjs, `bench/poseidon-vectors.mjs`),
which both the indexer's tests and `cargo test` read.

## What this is not

- **Not hardened.** `BigInt` arithmetic is not constant-time, so signing with this code leaks timing.
  It says what to compute, not how to compute it safely. `webcrypto.js` moves X25519, HKDF, AES-GCM
  and the hashes of secrets into the browser's library; BabyJubJub and Poseidon stay in `BigInt` in
  both entry points, because no browser offers them.
- **Not reviewed outside.** `docs/SPEC-NOTES.md` and this code were read once by the session that
  wrote the circuit. That is not an audit.
- **The nonce is a convention.** `sign` derives it from the key and the message as the Rust model
  does, so that signatures are reproducible. Any nonce gives a signature the circuit accepts; one
  that repeats across two messages gives away the key.
- `bodyHash` and the indexer's constants hash public bytes with `node:crypto` in both entry points.
- Node's WebCrypto and `node:crypto` are the same OpenSSL, so `npm test` shows that `webcrypto.js`
  follows `index.js`, not that a browser computes the same bytes. `npm run test:browser` shows it for
  the primitives in Chrome; the wallet functions above them are plain JavaScript.
