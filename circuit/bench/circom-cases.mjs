// Asks the circom statement of the relation (circom/spend.circom, circomlib's gadgets) the question
// the Rust circuit was asked: is this witness accepted?
//
//   node circom-cases.mjs <spend.wasm> <dir written by `sh20-circuit cases`> [--verbose]
//
// --verbose prints every case with where each side stops: the template and line of circom's failed
// assertion, and the part of the relation the Rust circuit names.
//
// Every honest witness must be accepted by both, every adversarial one refused by both. circom
// refuses by failing an assertion while it computes the witness. Like the Rust test, this runs
// altered inputs through an honest computation of the rest: it shows the two statements make the
// same checks on these cases, not that either is free of missing constraints.

import * as snarkjs from 'snarkjs';
import fs from 'node:fs';

const [wasm, dir] = process.argv.slice(2);
const cases = JSON.parse(fs.readFileSync(`${dir}/cases.json`, 'utf8'));
const verbose = process.argv.includes('--verbose');
const print = console.log.bind(console);
let disagreements = 0;
const count = { valid: 0, adversarial: 0 };
for (const c of cases) {
  const input = JSON.parse(fs.readFileSync(`${dir}/${c.file}`, 'utf8'));
  // the witness calculator reports the failed assertion on the console: keep it instead of printing it
  const said = [];
  console.log = console.error = (...parts) => said.push(parts.join(' '));
  let circom = 'accepted';
  try {
    await snarkjs.wtns.calculate(input, wasm, { type: 'mem' });
  } catch (e) {
    const where = said.join(' ').match(/Error in template (\w+?)(?:_\d+)? line: (\d+)/);
    circom = `refused${where ? ` at ${where[1]}:${where[2]}` : ''}`;
  }
  console.log = console.error = print;
  const expected = c.kind === 'valid' ? 'accepted' : 'refused';
  const ok = circom.startsWith(expected) && c.rust.startsWith(expected);
  if (!ok) disagreements++;
  if (!ok || verbose) print(`   ${ok ? 'same    ' : 'DISAGREE'}  ${c.name}: circom ${circom}; Rust ${c.rust}`);
  count[c.kind]++;
}
print(`   ${count.valid} honest witnesses accepted by both, ${count.adversarial} adversarial witnesses refused by both${disagreements ? `, EXCEPT ${disagreements}` : ''}`);
process.exit(disagreements ? 1 : 0);
