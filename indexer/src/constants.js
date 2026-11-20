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
  // 0x08-0x0f reserved for extensions (aggregated batches, a BTC entry/exit once
  // Bitcoin can enforce one). A v0 indexer rejects them like any unknown type.
});
export const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));

export const PAY_MODE = Object.freeze({ NONE: 0, BURN: 1, PAY: 2 });

export const TREE_DEPTH = 32;
export const N_IN = 2;
export const N_OUT = 3;
export const OUT_BYTES = 32 + 32 + 28; // leaf | pk_eph (X25519) | ct (v u64, ticker 4, tag 16)
/** A spend proof: PLONK over BN254, 9 G1 points and 6 scalars (docs/SPEC-WIRE.md §4). */
export const PROOF_BYTES = 480;
/** SHA-256("sh20/v0/vk" ‖ verifying key) of the spend circuit on the Hermez setup (draft v0.1). */
export const SPEND_VK_DIGEST = 'f48b551776188b652259ac42ff3d064ea61e9dd0d4b48addb825085ab1237745';
export const PAYSCRIPT_MAX = 34;
export const MIN_LOCK_SATS = 330n;
/** At most this many mints in one MINT envelope (one note of k × lim, paid k × price). */
export const MINT_BATCH_MAX = 10;
export const MAX_PUSH = 520;

const sha = (s) => createHash('sha256').update(s, 'utf8').digest();
const toFr = (buf) => BigInt('0x' + buf.toString('hex')) % FR;

export const DOMAIN = Object.freeze({
  LEAF: toFr(sha('sh20/v0/leaf')),
  BODY: 'sh20/v0/body',
  CLAIM: 'sh20/v0/claim',
  VK: 'sh20/v0/vk',
  DIGEST: 'sh20-v0',
});

/** Deployment profile: fixed before activation, identical in every indexer. */
export const DEFAULT_PROFILE = Object.freeze({
  network: 'signet',
  activationHeight: 0,
  anchorWindow: 100, // W
  anchorMinDepth: 1, // K_min
  deployBurn: 1000n, // D: SH20 units burned by every DEPLOY (0 = no burn, then a DEPLOY carries no spend)
  // N: a DEPLOY is valid only if the output its input 0 spends (the commit, which hides the ticker until the reveal)
  // was confirmed at least N blocks before: a ticker seen in the mempool cannot be copied and confirmed first.
  deployMaturity: 6,
  // The genesis token is part of the profile, not a DEPLOY, so nobody can race for it.
  // Like ORDI: 21,000,000 units, 1,000 per mint, free (network fees only), no team allocation.
  genesis: Object.freeze({ ticker: 'SH20', max: 21000000n, lim: 1000n }),
});
