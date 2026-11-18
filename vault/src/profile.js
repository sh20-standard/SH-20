// Profile constants the vault knows by itself (docs/SPEC-WIRE.md §5), so it does
// not take an indexer's word for them.
//
// The genesis token SH20 is part of the profile, not a DEPLOY: no transaction
// holds its terms, so the vault checks what indexers say against these.
// test/deploy.test.js checks them against indexer/src/constants.js and the vectors.

export const GENESIS = Object.freeze({
  ticker: 'SH20',
  max: 21000000n,
  lim: 1000n,
  pre: 0n, // no team allocation
  price: 0n, // free mint, network fees only
  payMode: 0,
  payScript: '',
  end: 0, // no end; start = the activation height
});

// Activation height A: not fixed yet (an open decision, CLAUDE.md). While it is
// null the vault takes the indexers' activationHeight and requires them to agree
// on it (consensus.js); once fixed, set it here and every other value is refused.
export const ACTIVATION_HEIGHT = null;
