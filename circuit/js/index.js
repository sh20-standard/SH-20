// What a wallet computes for an SH-20 spend, with no dependency: everything the spend circuit will
// recompute and check. `test/` compares it with vectors written by the circuit's own model
// (vectors.json, from circuit/src/vectors.rs).
//
//   import { tickerT, noteKeys, noteLeaf, nullifier, bodyHash, sign } from 'circuit/js/index.js';
//   const keys = noteKeys(sk, nk);                          // { ak, nkPub, npk }
//   const leaf = noteLeaf(tickerT('GENE'), v, keys.npk, rho);
//   const nf = nullifier(nk, leaf, index);
//   const { r8, s } = sign(sk, bodyHash(body));

export { P, poseidon } from '../../indexer/src/poseidon.js';
export { noteLeaf, tickerT } from '../../indexer/src/notes.js';
export { A, D, L, BASE8, IDENTITY, add, mul, mulBase8, onCurve } from './babyjub.js';
export { bodyHash, noteKeys, npkOf, nullifier } from './notes.js';
export { NONCE_TAG, hashToScalar, sign, verify } from './eddsa.js';
