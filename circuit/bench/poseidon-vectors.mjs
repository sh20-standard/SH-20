// Poseidon vectors from circomlibjs, the reference implementation of circomlib's Poseidon, for the
// widths a wallet needs (2 to 5 inputs):
//
//   node poseidon-vectors.mjs            check the indexer's Poseidon and the stored vectors against circomlibjs
//   node poseidon-vectors.mjs --write    rewrite indexer/test/fixtures/poseidon-circomlibjs.json
//
// The indexer (zero dependencies) and the circuit (Rust) both generate their constants with the Grain
// LFSR instead of copying a table; these vectors are what ties them to circomlib.

import fs from 'node:fs';
import { buildPoseidon } from 'circomlibjs';
import { poseidon as indexerPoseidon, P } from '../../indexer/src/poseidon.js';

const out = new URL('../../indexer/test/fixtures/poseidon-circomlibjs.json', import.meta.url);
const circomlib = await buildPoseidon();
const reference = (inputs) => circomlib.F.toObject(circomlib(inputs)).toString();

const cases = [];
for (let n = 2; n <= 5; n++) {
  const counting = Array.from({ length: n }, (_, i) => BigInt(i + 1)); // [1, 2], [1, 2, 3], …
  cases.push(counting, new Array(n).fill(0n), new Array(n).fill(P - 1n));
}
const vectors = cases.map((inputs) => ({ inputs: inputs.map(String), hash: reference(inputs) }));
const doc = { source: 'circomlibjs 0.1.7 (buildPoseidon), written by circuit/bench/poseidon-vectors.mjs', vectors };

let failed = false;
for (const v of vectors) {
  const got = indexerPoseidon(v.inputs.map(BigInt)).toString();
  if (got !== v.hash) {
    failed = true;
    console.log(`MISMATCH poseidon(${v.inputs.length} inputs): indexer ${got}, circomlibjs ${v.hash}`);
  }
}
if (process.argv.includes('--write')) {
  fs.writeFileSync(out, `${JSON.stringify(doc, null, 1)}\n`);
  console.log(`${vectors.length} vectors written`);
} else {
  const stored = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  if (stored !== `${JSON.stringify(doc, null, 1)}\n`) {
    failed = true;
    console.log('the stored vectors differ from circomlibjs: run with --write');
  }
}
console.log(failed ? 'FAILED' : `the indexer's Poseidon agrees with circomlibjs on ${vectors.length} vectors (2 to 5 inputs)`);
process.exit(failed ? 1 : 0);
