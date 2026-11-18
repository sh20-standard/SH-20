// The SH-20 code the vault reuses, unchanged: the reference indexer (wire format, notes, tree)
// and circuit/js, the wallet reference (note keys, addresses, sealing, nullifiers; docs/SPEC-NOTES.md).
// The Buffer shim must load first: these modules use Buffer at load time.
// In the browser, `node:crypto` is mapped to ./shim/node-crypto.js by the import map.

import './shim/buffer.js';

export { serializeEnvelope, parseEnvelope, CodecError } from '../../indexer/src/codec.js';
export { extractEnvelope } from '../../indexer/src/carrier.js';
export { FR, MAGIC, PAY_MODE, DOMAIN, TREE_DEPTH, PROOF_BYTES, MINT_BATCH_MAX } from '../../indexer/src/constants.js';
export { noteLeaf, tickerT, PUBLIC_RHO } from '../../indexer/src/notes.js';
export { poseidon2 } from '../../indexer/src/poseidon.js';
export { rootFromPath } from '../../indexer/src/tree.js';
export { HRP, encodeAddress, decodeAddress } from '../../circuit/js/address.js';
export { walletKeys, publicOpening, scan, seal, spendKeys } from '../../circuit/js/seal.js';
export { nullifier } from '../../circuit/js/notes.js';
export { L } from '../../circuit/js/babyjub.js';
