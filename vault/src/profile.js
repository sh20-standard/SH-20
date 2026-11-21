// The profile the vault follows (docs/SPEC-WIRE.md §5), embedded in the page: the same constants
// as the reference indexer (indexer/src/constants.js DEFAULT_PROFILE), never an indexer's /status.
// An indexer that reports any other value follows another chain of rules: the vault names it and
// acts on nothing (consensus.js profileProblems).
//
// Two profiles, the same rules: they differ by the activation height A alone.
//   test    A of DEFAULT_PROFILE: the dev servers, the tests and the CI, on a chain that starts at A.
//   signet  A of the public signet, fixed at launch (vault/RELEASES.md): the profile of a release.
// profile-name.js says which one this page follows.
//
// The genesis token SH20 is part of the profile, not a DEPLOY: no transaction holds its terms, so
// the vault checks what indexers say against these.

import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { PROFILE_NAME } from './profile-name.js';

// The public signet's activation height: the first block SH-20 counts there. null until the launch
// fixes it; every signet indexer then runs `indexer/bin/follow.js --activation <this height>`.
export const SIGNET_ACTIVATION_HEIGHT = null;

/** DEFAULT_PROFILE with the activation height `A`, its only parameter. */
export function profileAt(A) {
  if (!Number.isInteger(A) || A < 0) throw new Error(`activation height ${A}: not a block height`);
  return Object.freeze({
    network: DEFAULT_PROFILE.network,
    activationHeight: A, // A
    deployBurn: DEFAULT_PROFILE.deployBurn, // D: SH20 units every DEPLOY burns
    deployMaturity: DEFAULT_PROFILE.deployMaturity, // N: a DEPLOY reveals a commit at least N blocks deep
    anchorWindow: DEFAULT_PROFILE.anchorWindow, // W: a spend's anchor is at most W blocks old
    anchorMinDepth: DEFAULT_PROFILE.anchorMinDepth, // K_min: and at least K_min blocks deep
    genesis: DEFAULT_PROFILE.genesis.ticker,
  });
}

export const PROFILES = Object.freeze({
  test: profileAt(DEFAULT_PROFILE.activationHeight),
  signet: SIGNET_ACTIVATION_HEIGHT === null ? null : profileAt(SIGNET_ACTIVATION_HEIGHT),
});

if (!PROFILES[PROFILE_NAME]) throw new Error(`no ${PROFILE_NAME} profile: ${PROFILE_NAME === 'signet' ? 'its activation height is not fixed (profile.js SIGNET_ACTIVATION_HEIGHT)' : 'unknown name'}`);
export { PROFILE_NAME };
export const PROFILE = PROFILES[PROFILE_NAME];

export const GENESIS = Object.freeze({
  ticker: DEFAULT_PROFILE.genesis.ticker,
  max: DEFAULT_PROFILE.genesis.max,
  lim: DEFAULT_PROFILE.genesis.lim,
  pre: 0n, // no team allocation
  price: 0n, // free mint, network fees only
  payMode: 0,
  payScript: '',
  end: 0, // no end; start = the activation height
});

export const ACTIVATION_HEIGHT = PROFILE.activationHeight;
