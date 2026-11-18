// Loads the vault, the indexer's codec and circuit/js the way a browser does: no global Buffer,
// node:crypto replaced by the shim (SHA-512, HMAC, HKDF, X25519 and AES-GCM in plain JavaScript).
// Runs the indexer's vectors and circuit/js/vectors.json through them; prints results for the parent test.
import { register } from 'node:module';
import { readFileSync } from 'node:fs';

register('./hooks.mjs', import.meta.url);
delete globalThis.Buffer;

const json = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const vectors = json('../../../indexer/vectors/v0.3.json');
const cv = json('../../../circuit/js/vectors.json');
const sh20 = await import('../../src/sh20.js');
const { ShimBuffer } = await import('../../src/shim/buffer.js');
const { masterSecret } = await import('../../../circuit/js/seal.js');
const { x25519, x25519Public } = await import('../../../circuit/js/address.js');
const { wallet, publicNote, scanOutput, nullifierOf } = await import('../../src/notekeys.js');
const { frHex } = await import('../../src/fr.js');

const hex = (s) => Buffer.from(s, 'hex');
const out = { shim: globalThis.Buffer === ShimBuffer, envelopes: {} };
for (const [name, e] of Object.entries(vectors.envelopes)) {
  const { env } = sh20.parseEnvelope(hex(e.hex));
  out.envelopes[name] = sh20.serializeEnvelope(env).toString('hex') === e.hex;
}
const nl = vectors.noteLeaf;
out.noteLeaf = String(sh20.tickerT(nl.ticker)) === nl.t && frHex(sh20.noteLeaf(sh20.tickerT(nl.ticker), BigInt(nl.v), BigInt('0x' + nl.npk), BigInt('0x' + nl.rho))) === nl.leaf;
out.domainLeaf = frHex(sh20.DOMAIN.LEAF) === vectors.domainLeaf;
let threw = false;
try { sh20.parseEnvelope(hex(vectors.envelopes.mintGenesis.hex + '00')); } catch (e) { threw = e instanceof sh20.CodecError; }
out.rejectsTrailing = threw;
// carrier.js under the shim: finds an envelope in an OP_RETURN, as the deploy check does
const dep = hex(vectors.envelopes.mintGenesis.hex);
const script = Buffer.concat([Buffer.from(dep.length <= 75 ? [0x6a, dep.length] : [0x6a, 0x4c, dep.length]), dep]);
const found = sh20.extractEnvelope({ vin: [{ txid: '00'.repeat(32), vout: 0, witness: [] }], vout: [{ value: 0n, script }] });
out.carrier = found.bytes?.toString('hex') === vectors.envelopes.mintGenesis.hex;

// ── circuit/js/vectors.json, through the shim ──
// RFC 7748 §6.1
const a = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const b = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
out.rfc7748 = x25519Public(a).toString('hex') === '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
  && x25519(a, x25519Public(b)).toString('hex') === '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
  && x25519(a, Buffer.alloc(32)).every((x) => x === 0);
const wallets = Object.fromEntries(cv.wallets.map((w) => [w.name, wallet(hex(w.m))]));
out.wallets = cv.wallets.map((w) => masterSecret(hex(w.bip39Seed)).toString('hex') === w.m
  && wallets[w.name].ask.toString() === w.ask && wallets[w.name].nsk.toString() === w.nsk
  && Buffer.from(wallets[w.name].ivk).toString('hex') === w.ivk && Buffer.from(wallets[w.name].address.ivkPub).toString('hex') === w.IVK
  && sh20.encodeAddress('sh20', wallets[w.name].address) === w.address && wallets[w.name].addressString === w.addressTest
  && sh20.decodeAddress('tsh20', w.addressTest).ivkPub.toString('hex') === w.IVK);
out.invalidAddresses = cv.invalidAddresses.map(({ address }) => {
  try { sh20.decodeAddress('sh20', address); return false; } catch (e) { return /address:/.test(e.message); }
});
out.sealed = cv.sealed.map((s) => {
  const to = wallets[s.to];
  const o = sh20.seal(to.address, s.ticker, BigInt(s.v), hex(s.e));
  const sealedOk = o.pkEph.toString('hex') === s.pkEph && o.ct.toString('hex') === s.ct && o.leaf.toString() === s.leaf && o.npk.toString() === s.npk
    && o.secrets.rho.toString() === s.rho && o.secrets.tauA.toString() === s.tauA;
  const output = { leaf: BigInt(s.leaf), pkEph: hex(s.pkEph), ct: hex(s.ct) };
  const mine = scanOutput(to, output);
  const others = Object.entries(wallets).filter(([n]) => n !== s.to).every(([, w]) => scanOutput(w, output) === null);
  return sealedOk && mine?.v.toString() === s.v && mine.ticker === s.ticker && others;
});
out.publicNotes = cv.publicNotes.map((p) => publicNote(wallets[p.wallet], p.i).npk.toString() === p.npk);
const sp = cv.spend;
out.spendNullifiers = sp.inputs.map((inp, k) => {
  const w = wallets[inp.wallet];
  const o = publicNote(w, inp.publicNote);
  const leaf = sh20.noteLeaf(sh20.tickerT(sp.ticker), BigInt(inp.v), o.npk, 0n);
  return nullifierOf(w, o.secrets, leaf, Number(inp.index)).toString() === sp.nf[k];
});
out.spendOutputs = sp.outputs.map((o, j) => scanOutput(wallets[o.to], { leaf: BigInt(sp.outLeaf[j]), pkEph: hex(o.pkEph), ct: hex(o.ct) })?.v.toString() === o.v);
console.log(JSON.stringify(out));
