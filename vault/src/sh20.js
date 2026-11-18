// The SH-20 code the vault reuses from the reference indexer, unchanged.
// The Buffer shim must load first: the indexer modules use Buffer at load time.
// In the browser, `node:crypto` is mapped to ./shim/node-crypto.js by the import map.

import './shim/buffer.js';

export { serializeEnvelope, parseEnvelope, CodecError } from '../../indexer/src/codec.js';
export { extractEnvelope } from '../../indexer/src/carrier.js';
export { FR, MAGIC, PAY_MODE, DOMAIN } from '../../indexer/src/constants.js';
export { noteLeaf } from '../../indexer/src/notes.js';
export { poseidon2 } from '../../indexer/src/poseidon.js';
