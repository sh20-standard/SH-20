# Vault releases

Each release is built by `npm run release` from the git objects of one commit, so anyone can
rebuild it and get the same bytes. The package holds exactly the static site: no script from
another domain, no CDN (see the CSP in `vault/index.html`).

## How to release (0.3.1 and later)

From 0.3.1 a release follows the signet profile (`src/profile.js`): the same rules as the test
profile the dev servers and the CI run, with the public signet's activation height. Nothing is built
for others, signed or published from a contributor's own machine, and no step needs an IPFS node.

1. **Fix the activation height `A`.** Pick the signet block from which SH-20 counts: one not yet
   mined when the release is announced, so that nobody holds an early mint. Set
   `SIGNET_ACTIVATION_HEIGHT = A` in `vault/src/profile.js`, the one value a release adds to the
   profile. Every indexer of the signet runs with the same height:
   `node indexer/bin/follow.js --rpc <your signet node> --activation A --deploy-burn 1000 --verifier vault/prover/sh20_circuit.wasm`.
   The vault refuses any indexer that reports another one, and names it.
2. **Default servers.** `vault/src/servers.js`: on signet, the two mirrors the site serves itself
   (`/api/js/` and `/api/rs/`, beside the page) and a public Esplora. An indexer run by someone else goes in only with
   its operator's agreement, and with its host added in `test/signet.test.js` in the same pull
   request. Never a server run by the SH-20 contributors: the standard needs none, and a default of
   ours would make us one, seeing every vault that asks it first.
3. **Version.** `vault/package.json` (0.3.1). A version is released once: `release.js` refuses to
   record other bytes under a version this file already has.
4. **Checks.** The CI is green on the release's commit, `vault-regtest` included (the whole flow
   in the page on Bitcoin Core regtest, every transaction checked by Bitcoin Core: `dev/regtest.js`).
5. **Build and record.** From a clean checkout of that commit: `cd vault && npm run release`. It
   builds from the git objects on the signet profile (and stops while `A` is unset), writes
   `release/sh20-vault-<version>.tar`, its `.car` and its folder, and adds the version's entry
   below. Commit this file alone: it is not part of the site, so the package of the next commit is
   the same bytes.
6. **Rebuild elsewhere.** Run the `release` workflow (Actions → release → Run workflow) on that
   commit: a GitHub runner rebuilds the package, fails unless it is the SHA-256 recorded here, and
   keeps the `.tar` and the `.car` as its artifact. A second person who rebuilds it ("How to verify"
   below) and gets the same SHA-256 and CID is better still.
7. **Publish, never from a machine of yours.** An IPFS node tells the network its IP address for
   every block it provides, so a contributor's machine never pins or serves a release: no `ipfs add`
   without `--only-hash`, no `ipfs dag import` or IPFS Desktop on a node that is online. The CID
   needs no IPFS at all (`release.js` computes it). Have a pinning service, from the project's own
   anonymous account, take the workflow's `.car` (a CAR carries the blocks themselves, so the
   service serves this CID whatever its own chunking). Upload it from a workflow run, with the
   service's token as a repository secret, rather than from your browser, which would show the
   service your address. Then check that two public gateways serve the CID
   (`https://<cid>.ipfs.dweb.link/vault/`) and announce the CID with the SHA-256 of this file.

## How to verify a release

```sh
git clone https://github.com/sh20-standard/SH-20 && cd SH-20
git checkout <commit>
node vault/release.js --check <sha256>        # rebuilds; prints OK only if the bytes match
shasum -a 256 vault/release/sh20-vault-<version>.tar            # same SHA-256 (or sha256sum)
ipfs add -r --cid-version=1 --only-hash -Q vault/release/sh20-vault-<version>   # same CID
```

`release.js --check` prints the CID it computes too, so the last line is only a second opinion.

The CID is the fingerprint of what IPFS serves: open `https://<cid>.ipfs.dweb.link/vault/`, or
better a local IPFS node (`ipfs get <cid>` checks every block against the CID).
A public gateway is trusted to serve the right blocks; a local node or a verifying client is not.

## 0.3.0

- Source commit: `b7e6aacb35bd7b02c540bd848f4c6b32022a3dbe`
- Package: `sh20-vault-0.3.0.tar`, 11244544 bytes, 53 files
- SHA-256: `f69c9b4ff4c023b370cb8e6a3fd1edb9abbc4302de0d604a38b5f6e01c5300cc`
- IPFS CID: `bafybeihmeju6pz4rtqy6jjaoa5dk4skxafnehrftshywwf243xzzmdygue`

## 0.2.0

**Obsolete:** it builds MINTs of wire v0.2 (74-byte envelopes) and has no prover; v0.3 indexers reject what it sends. Use 0.3.0 or later.

- Source commit: `f8122d7dbb154df189ca883c8c35ce4917299a5e`
- Package: `sh20-vault-0.2.0.tar`, 122368 bytes, 24 files
- SHA-256: `392c0fd7e0bb796637e6c6b891e4149fbdbc4e27315fb22e80e8e69369f0e436`
- IPFS CID: `bafybeigfj45xzun5mek5zvqeby6bs76ukwkslx7ifa7ipzdoylfl4pnavi`

## 0.1.0

**Obsolete:** it names tokens by tokenNum (wire v0.1) and has no prover; current indexers reject what it sends. Use 0.3.0 or later.

- Source commit: `cb0dee33c5b118b0da1d09cd4e12c5273d9fdb88`
- Package: `sh20-vault-0.1.0.tar`, 121856 bytes, 24 files
- SHA-256: `fe3231cb3a689aaee32b0cdb2fa57dfb284094dee6287466e202cfc90ed9c8ae`
- IPFS CID: `bafybeig6rbeuo5bo3526gm2w22cpqfwonvrlr473elowg53anaolqleqdu`
