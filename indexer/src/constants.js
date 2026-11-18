import { createHash } from 'node:crypto';
import { P } from './poseidon.js';

export const FR = P; // BN254 scalar field

export const MAGIC = Buffer.from('SH20', 'ascii');
export const VERSION = 0x00;

export const TYPE = Object.freeze({
  DEPLOY: 0x01,
  MINT: 0x02,
  TRANSFER: 0x03,
  BURN: 0x04,
  LIST: 0x05,
  TAKE: 0x06,
  CLAIM: 0x07,
});
export const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));

export const PAY_MODE = Object.freeze({ NONE: 0, BURN: 1, PAY: 2 });

export const TREE_DEPTH = 32;
export const N_IN = 2;
export const N_OUT = 3;
export const OUT_BYTES = 32 + 33 + 28; // leaf | pk_eph | ct (v u64, t u32, tag 16)
export const PROOF_MAX = 4096;
export const PAYSCRIPT_MAX = 34;
export const MIN_LOCK_SATS = 330n;
export const MAX_PUSH = 520;

const sha = (s) => createHash('sha256').update(s, 'utf8').digest();
const toFr = (buf) => BigInt('0x' + buf.toString('hex')) % FR;

export const DOMAIN = Object.freeze({
  LEAF: toFr(sha('sh20/v0/leaf')),
  BODY: 'sh20/v0/body',
  CLAIM: 'sh20/v0/claim',
  DIGEST: 'sh20-v0',
});

/** Deployment profile: fixed before activation, identical in every indexer. */
export const DEFAULT_PROFILE = Object.freeze({
  network: 'signet',
  activationHeight: 0,
  anchorWindow: 100, // W
  anchorMinDepth: 1, // K_min
  deployBurn: 1000n, // D: genesis units burned by every non-genesis DEPLOY
  genesisTokenNum: 1,
});
