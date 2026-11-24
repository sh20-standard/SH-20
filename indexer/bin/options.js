// Command-line options of the tools in bin/: `--name value` pairs, every name known in advance and given at most once,
// a fixed number of other arguments, and every number written as a plain decimal integer in its range. Anything else
// stops the tool with its usage. A flag one tool takes and another drops, a flag given twice, `W = NaN` or a height
// rounded by a float would each put two indexers of one network on two chains without a word: replay.js once dropped
// --maturity that way.

const U32 = 2 ** 32 - 1;
const U64 = 2n ** 64n - 1n;

/**
 * @param {string[]} args         process.argv.slice(2)
 * @param {string[]} known        the option names the tool takes, without `--`
 * @param {string} usage          printed under every refusal
 * @param {{positionals?: number}} [shape]  how many arguments that are not options the tool takes (default 0)
 * @returns the reader `opt(name, def)` of string values, with `opt.int`, `opt.u64`, `opt.require`, `opt.fail` and
 *          `opt.positional`
 */
export function options(args, known, usage, { positionals = 0 } = {}) {
  const fail = (why) => {
    console.error(`${why}\n${usage}`);
    process.exit(1);
  };
  const values = new Map();
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('--')) {
      if (positional.length >= positionals) fail(`unexpected argument ${a}`);
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (!known.includes(name)) fail(`unknown option ${a}`);
    if (values.has(name)) fail(`${a} is given twice`);
    const v = args[i + 1];
    if (v === undefined || v.startsWith('--')) fail(`${a} needs a value`);
    values.set(name, v);
    i++;
  }
  const opt = (name, def) => (values.has(name) ? values.get(name) : def);
  const digits = (name) => {
    const v = values.get(name);
    if (!/^[0-9]+$/.test(v)) fail(`--${name}: "${v}" is not a decimal integer`);
    return v;
  };
  /** A whole number from 0 to `max` (a height, a window, a count: u32, as the spec writes them). */
  opt.int = (name, def, max = U32) => {
    if (!values.has(name)) return def;
    const v = digits(name);
    if (Number(v) > max) fail(`--${name}: ${v} is above ${max}`);
    return Number(v);
  };
  /** A whole number from 0 to 2^64 − 1, as a BigInt (an amount: u64). */
  opt.u64 = (name, def) => {
    if (!values.has(name)) return def;
    const v = BigInt(digits(name));
    if (v > U64) fail(`--${name}: ${v} is above ${U64}`);
    return v;
  };
  opt.require = (...names) => {
    for (const n of names) if (!values.has(n)) fail(`--${n} is required`);
  };
  opt.fail = fail;
  opt.positional = positional;
  return opt;
}

/**
 * The profile flags every indexer of a network takes, by the names indexer-rs takes them. `--activation` and
 * `--deploy-burn` are the two the spec gives no value (SPEC-WIRE §7), so the tools ask for them.
 */
export const PROFILE_FLAGS = [
  ['deploy-burn', 'deployBurn', 'u64'],
  ['window', 'anchorWindow', 'int'],
  ['min-depth', 'anchorMinDepth', 'int'],
  ['maturity', 'deployMaturity', 'int'],
];

export function profileFrom(opt, profile) {
  for (const [flag, key, kind] of PROFILE_FLAGS) {
    const v = opt[kind](flag);
    if (v !== undefined) profile[key] = v;
  }
  return profile;
}
