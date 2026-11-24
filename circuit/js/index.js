// What a wallet computes for an SH-20 spend, with no dependency: everything the spend circuit will
// recompute and check. `test/` compares it with vectors written by the circuit's own model
// (vectors.json, from circuit/src/vectors.rs).
//
//   import { tickerT, noteKeys, noteLeaf, nullifier, bodyHash, sign } from 'circuit/js/index.js';
//   const keys = noteKeys(sk, nk);                          // { ak, nkPub, npk }
//   const leaf = noteLeaf(tickerT('GENE'), v, keys.npk, rho);
//   const nf = nullifier(nk, leaf, index);
//   const { r8, s } = sign(sk, bodyHash(body));
//
// and, for docs/SPEC-NOTES.md:
//   const keys = walletKeys(masterSecret(bip39Seed, 'sh20'));  // { ask, nsk, ivk, address }; 'tsh20' on a test network
//   const to = decodeAddress('sh20', string);               // throws on anything a payer must refuse
//   const out = seal(to, 'GENE', 700n, e);                  // { leaf, pkEph, ct } and { secrets, npk }
//   const note = scan(keys.ivk, keys.address, out);         // null unless it is ours and hashes to its leaf
//   const { sk, nk } = spendKeys(keys, note.secrets);
//
// This entry point is synchronous and takes X25519, HKDF, AES-GCM and the hashes from node:crypto:
// it is the one for Node. A browser wallet takes webcrypto.js: the same names, asynchronous, on the
// platform's WebCrypto.

export { P, poseidon } from '../../indexer/src/poseidon.js';
export { noteLeaf, tickerT } from '../../indexer/src/notes.js';
export { A, D, L, BASE8, IDENTITY, add, mul, mulBase8, onCurve } from './babyjub.js';
export { bodyHash, noteKeys, npkOf, nullifier } from './notes.js';
export { NONCE_TAG, hashToScalar, sign, verify } from './eddsa.js';
export { ADDRESS_BYTES, ADDRESS_VERSION, HRP, bech32mDecode, bech32mEncode, decodeAddress, encodeAddress, isKeyPoint, packPoint, unpackPoint, x25519, x25519Public } from './address.js';
export { hr, hs, masterSecret, noteNpk, noteSecrets, publicOpening, scan, seal, selfSecret, spendKeys, walletKeys } from './seal.js';
