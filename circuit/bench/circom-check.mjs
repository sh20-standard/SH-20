// Cross-checks the Rust model against the circom statement of the relation:
//   node circom-check.mjs <spend.wasm> <input.json> <public.json>
// The witness built by the Rust model must satisfy circom/spend.circom (circomlib's Poseidon, EdDSA
// and BabyJubJub), and both must agree on the nine public signals.

import * as snarkjs from 'snarkjs';
import fs from 'node:fs';

const [wasm, inputPath, publicPath] = process.argv.slice(2);
const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const want = JSON.parse(fs.readFileSync(publicPath, 'utf8'));
const wtns = { type: 'mem' };
await snarkjs.wtns.calculate(input, wasm, wtns);
const got = [];
const w = await snarkjs.wtns.exportJson(wtns);
for (let i = 1; i <= want.length; i++) got.push(w[i].toString());
const same = JSON.stringify(got) === JSON.stringify(want);
console.log(`circom accepts the Rust witness; public signals ${same ? 'identical' : 'DIFFER'}`);
process.exit(same ? 0 : 1);
