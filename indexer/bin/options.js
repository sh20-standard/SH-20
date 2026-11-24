// Command-line options of the tools in bin/: `--name value` pairs, every name known in advance. A name the tool does
// not know stops it, so that a profile flag one tool takes and another does not can never be dropped without a word.

export function options(args, known, usage) {
  for (const a of args) {
    if (a.startsWith('--') && !known.includes(a.slice(2))) {
      console.error(`unknown option ${a}\n${usage}`);
      process.exit(1);
    }
  }
  return (name, def) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : def;
  };
}

/** The profile flags every indexer of a network takes, by the names indexer-rs takes them. */
export const PROFILE_FLAGS = [
  ['deploy-burn', 'deployBurn', true],
  ['window', 'anchorWindow'],
  ['min-depth', 'anchorMinDepth'],
  ['maturity', 'deployMaturity'],
];

export function profileFrom(opt, profile) {
  for (const [flag, key, big] of PROFILE_FLAGS) if (opt(flag) !== undefined) profile[key] = big ? BigInt(opt(flag)) : Number(opt(flag));
  return profile;
}
