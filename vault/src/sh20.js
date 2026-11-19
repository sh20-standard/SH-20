// The SH-20 code the vault reuses, unchanged: the reference indexer (wire format, notes, tree)
// and circuit/js, the wallet reference (note keys, addresses, sealing, nullifiers; docs/SPEC-NOTES.md).
// The Buffer shim must load first: these modules use Buffer at load time.
// In the browser, `node:crypto` is mapped to ./shim/node-crypto.js by the import map.

import './shim/buffer.js';

export { serializeEnvelope, parseEnvelope, CodecError } from '../../indexer/src/codec.js';
export { extractEnvelope } from '../../indexer/src/carrier.js';
export { FR, MAGIC, PAY_MODE, DOMAIN, TREE_DEPTH, PROOF_BYTES, MINT_BATCH_MAX, SPEND_VK_DIGEST } from '../../indexer/src/constants.js';
export { noteLeaf, tickerT, PUBLIC_RHO } from '../../indexer/src/notes.js';
export { poseidon2 } from '../../indexer/src/poseidon.js';
export { NoteTree, rootFromPath } from '../../indexer/src/tree.js';
export { sign as schnorrSign, verify as schnorrVerify, publicKey as schnorrPublicKey, taggedHash } from '../../indexer/src/schnorr.js';
// circuit/js/webcrypto.js: everything that touches a secret (X25519, HKDF, AES-GCM, HMAC-SHA512, the
// EdDSA nonce) is asynchronous and runs in the platform's WebCrypto. BabyJubJub and Poseidon stay in JS.
export {
  available, HRP, encodeAddress, decodeAddress, walletKeys, publicOpening, scan, seal, spendKeys, masterSecret,
  sign as eddsaSign, verify as eddsaVerify, nullifier, noteKeys, bodyHash, L,
} from '../../circuit/js/webcrypto.js';
export { hmacSha512 } from '../../circuit/js/subtle.js';
