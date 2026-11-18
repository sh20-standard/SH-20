// Checks proofs made by the Rust prover with snarkjs' own PLONK verifier:
//   node cross-verify.mjs <dir> <name> [<name> ...]
// reads <dir>/<name>.{vk,proof,public}.json; a tampered public signal must be rejected.

import * as snarkjs from 'snarkjs';
import fs from 'node:fs';

const [dir, ...names] = process.argv.slice(2);
let failed = false;
for (const name of names) {
  const read = (kind) => JSON.parse(fs.readFileSync(`${dir}/${name}.${kind}.json`, 'utf8'));
  const [vk, proof, publics] = [read('vk'), read('proof'), read('public')];
  const ok = await snarkjs.plonk.verify(vk, publics, proof);
  const bad = publics.slice();
  bad[0] = (BigInt(bad[0]) + 1n).toString();
  const forged = await snarkjs.plonk.verify(vk, bad, proof);
  console.log(`${name}: snarkjs verify = ${ok}, tampered = ${forged}`);
  if (!ok || forged) failed = true;
}
process.exit(failed ? 1 : 0);
