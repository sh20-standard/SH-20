// The profile the vault follows (docs/SPEC-WIRE.md §5), embedded in the page: the same constants
// as the reference indexer (indexer/src/constants.js DEFAULT_PROFILE), never an indexer's /status.
// An indexer that reports any other value follows another chain of rules: the vault names it and
// acts on nothing (consensus.js profileProblems).
//
// Three profiles, the same rules: they differ by the activation height A and by their network.
//   test     A of DEFAULT_PROFILE: the dev servers, the tests and the CI, on a chain that starts at A.
//   signet   A of the public signet, fixed at its launch (vault/RELEASES.md).
//   mainnet  A of Bitcoin mainnet, fixed at its launch, here or by `build.js --mainnet --activation A`.
// profile-name.js says which one this page follows: 'test' in the source tree, the one of a release in it.
//
// The genesis token SH20 is part of the profile, not a DEPLOY: no transaction holds its terms, so
// the vault checks what indexers say against these.

import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { PROFILE_NAME } from './profile-name.js';

// The activation heights: the first block SH-20 counts on that network. null until its launch fixes
// it; every indexer of the network then runs `indexer/bin/follow.js --activation <this height>
// --deploy-burn 1000` (D, below: follow.js requires it).
export const SIGNET_ACTIVATION_HEIGHT = null;
export const MAINNET_ACTIVATION_HEIGHT = null;

// What an indexer's /status names as its network (docs/API.md): Bitcoin Core's own chain name, or the
// `--network` it was started with. On mainnet that name is "main".
export const MAINNET_NETWORK = 'main';

/** DEFAULT_PROFILE with the activation height `A`, on `network` (signet unless told). */
export function profileAt(A, network = DEFAULT_PROFILE.network) {
  if (!Number.isInteger(A) || A < 0) throw new Error(`activation height ${A}: not a block height`);
  return Object.freeze({
    network,
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
  mainnet: MAINNET_ACTIVATION_HEIGHT === null ? null : profileAt(MAINNET_ACTIVATION_HEIGHT, MAINNET_NETWORK),
});

/**
 * The Bitcoin network of each profile, and what follows from it:
 *   bitcoin    its Bitcoin addresses (btc.js NETWORKS): signet's tb1… or mainnet's bc1…, 1…, 3…
 *   addresses  its SH-20 addresses (docs/SPEC-NOTES.md §2, circuit/js HRP): tsh20… on signet, sh20… on mainnet
 *   label      how the page names it
 * The test profile is signet's: the dev chains (dev/serve.js, dev/regtest.js) use signet addresses.
 */
const SIGNET = Object.freeze({ bitcoin: 'signet', addresses: 'test', label: 'signet' });
export const CHAINS = Object.freeze({
  test: SIGNET,
  signet: SIGNET,
  mainnet: Object.freeze({ bitcoin: 'bitcoin', addresses: 'mainnet', label: 'mainnet' }),
});

if (!(PROFILE_NAME in PROFILES)) throw new Error(`no ${PROFILE_NAME} profile: unknown name`);
if (!PROFILES[PROFILE_NAME]) throw new Error(`no ${PROFILE_NAME} profile: its activation height is not fixed (profile.js ${PROFILE_NAME.toUpperCase()}_ACTIVATION_HEIGHT)`);
export { PROFILE_NAME };
export const PROFILE = PROFILES[PROFILE_NAME];
export const CHAIN = CHAINS[PROFILE_NAME];

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
