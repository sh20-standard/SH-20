# Vault releases

Each release is built by `npm run release` from the git objects of one commit, so anyone can
rebuild it and get the same bytes. The package holds exactly the static site: no script from
another domain, no CDN (see the CSP in `vault/index.html`).

## How to verify a release

```sh
git clone https://github.com/sh20-standard/SH-20 && cd SH-20
git checkout <commit>
node vault/release.js --check <sha256>        # rebuilds; prints OK only if the bytes match
shasum -a 256 vault/release/sh20-vault-<version>.tar            # same SHA-256 (or sha256sum)
ipfs add -r --cid-version=1 --only-hash -Q vault/release/sh20-vault-<version>   # same CID
```

The CID is the fingerprint of what IPFS serves: open `https://<cid>.ipfs.dweb.link/vault/`, or
better a local IPFS node (`ipfs get <cid>` checks every block against the CID).
A public gateway is trusted to serve the right blocks; a local node or a verifying client is not.

## 0.2.0

- Source commit: `f8122d7dbb154df189ca883c8c35ce4917299a5e`
- Package: `sh20-vault-0.2.0.tar`, 122368 bytes, 24 files
- SHA-256: `392c0fd7e0bb796637e6c6b891e4149fbdbc4e27315fb22e80e8e69369f0e436`
- IPFS CID: `bafybeigfj45xzun5mek5zvqeby6bs76ukwkslx7ifa7ipzdoylfl4pnavi`

## 0.1.0

- Source commit: `cb0dee33c5b118b0da1d09cd4e12c5273d9fdb88`
- Package: `sh20-vault-0.1.0.tar`, 121856 bytes, 24 files
- SHA-256: `fe3231cb3a689aaee32b0cdb2fa57dfb284094dee6287466e202cfc90ed9c8ae`
- IPFS CID: `bafybeig6rbeuo5bo3526gm2w22cpqfwonvrlr473elowg53anaolqleqdu`
