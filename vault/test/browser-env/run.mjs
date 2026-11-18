// Loads the vault and the indexer's codec the way a browser does: no global
// Buffer, node:crypto replaced by the shim. Prints results for the parent test.
import { register } from 'node:module';
import { readFileSync } from 'node:fs';

register('./hooks.mjs', import.meta.url);
delete globalThis.Buffer;

const vectors = JSON.parse(readFileSync(new URL('../../../indexer/vectors/v0.2.json', import.meta.url), 'utf8'));
const sh20 = await import('../../src/sh20.js');
const { ShimBuffer } = await import('../../src/shim/buffer.js');
const { deriveNpk } = await import('../../src/npk.js');
const { frHex } = await import('../../src/fr.js');

const out = { shim: globalThis.Buffer === ShimBuffer, envelopes: {} };
for (const [name, e] of Object.entries(vectors.envelopes)) {
  const bytes = Buffer.from(e.hex, 'hex');
  const { env } = sh20.parseEnvelope(bytes);
  out.envelopes[name] = sh20.serializeEnvelope(env).toString('hex') === e.hex;
}
const nl = vectors.noteLeaf;
out.noteLeaf = String(sh20.tickerT(nl.ticker)) === nl.t && frHex(sh20.noteLeaf(sh20.tickerT(nl.ticker), BigInt(nl.v), BigInt('0x' + nl.npk), BigInt('0x' + nl.rho))) === nl.leaf;
out.domainLeaf = frHex(sh20.DOMAIN.LEAF) === vectors.domainLeaf;
out.npk7 = frHex(deriveNpk(new Uint8Array(32).fill(7), 3).npk);
let threw = false;
try { sh20.parseEnvelope(Buffer.from(vectors.envelopes.mintGenesis.hex + '00', 'hex')); } catch (e) { threw = e instanceof sh20.CodecError; }
out.rejectsTrailing = threw;
// carrier.js under the shim: finds an envelope in an OP_RETURN, as the deploy check does
const dep = Buffer.from(vectors.envelopes.mintGenesis.hex, 'hex');
const script = Buffer.concat([Buffer.from(dep.length <= 75 ? [0x6a, dep.length] : [0x6a, 0x4c, dep.length]), dep]);
const found = sh20.extractEnvelope({ vin: [{ txid: '00'.repeat(32), vout: 0, witness: [] }], vout: [{ value: 0n, script }] });
out.carrier = found.bytes?.toString('hex') === vectors.envelopes.mintGenesis.hex;
console.log(JSON.stringify(out));
