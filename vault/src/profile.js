// The profile the vault follows (docs/SPEC-WIRE.md §5), embedded in the page: the same constants
// as the reference indexer (indexer/src/constants.js DEFAULT_PROFILE), never an indexer's /status.
// An indexer that reports any other value follows another chain of rules: the vault names it and
// acts on nothing (consensus.js profileProblems).
//
// The genesis token SH20 is part of the profile, not a DEPLOY: no transaction holds its terms, so
// the vault checks what indexers say against these.

import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';

export const PROFILE = Object.freeze({
  network: DEFAULT_PROFILE.network,
  activationHeight: DEFAULT_PROFILE.activationHeight, // A
  deployBurn: DEFAULT_PROFILE.deployBurn, // D: SH20 units every DEPLOY burns
  deployMaturity: DEFAULT_PROFILE.deployMaturity, // N: a DEPLOY reveals a commit at least N blocks deep
  anchorWindow: DEFAULT_PROFILE.anchorWindow, // W: a spend's anchor is at most W blocks old
  anchorMinDepth: DEFAULT_PROFILE.anchorMinDepth, // K_min: and at least K_min blocks deep
  genesis: DEFAULT_PROFILE.genesis.ticker,
});

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
