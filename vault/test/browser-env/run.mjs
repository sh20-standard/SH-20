// Loads the vault, the indexer's codec and circuit/js/webcrypto.js the way a browser does: no global
// Buffer, node:crypto replaced by the shim (SHA-256 only), X25519, HKDF, AES-GCM and HMAC from the
// platform's WebCrypto (crypto.subtle). Runs the indexer's vectors and circuit/js/vectors.json
// through them; prints results for the parent test.
import { register } from 'node:module';
import { readFileSync } from 'node:fs';

register('./hooks.mjs', import.meta.url);
delete globalThis.Buffer;

const json = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const vectors = json('../../../indexer/vectors/v0.3.json');
const cv = json('../../../circuit/js/vectors.json');
const sh20 = await import('../../src/sh20.js');
const { ShimBuffer } = await import('../../src/shim/buffer.js');
const { masterSecret, x25519, x25519Public, available } = await import('../../../circuit/js/webcrypto.js');
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
const h = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
out.available = await available();
out.rfc7748 = h(await x25519Public(a)) === '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
  && h(await x25519(a, await x25519Public(b))) === '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
  && (await x25519(a, new Uint8Array(32))).every((x) => x === 0);
const wallets = {};
for (const w of cv.wallets) wallets[w.name] = await wallet(hex(w.m));
out.wallets = [];
for (const w of cv.wallets) {
  const k = wallets[w.name];
  out.wallets.push(h(await masterSecret(hex(w.bip39Seed))) === w.m && k.ask.toString() === w.ask && k.nsk.toString() === w.nsk
    && h(k.ivk) === w.ivk && h(k.address.ivkPub) === w.IVK
    && sh20.encodeAddress('sh20', k.address) === w.address && k.addressString === w.addressTest
    && h((await sh20.decodeAddress('tsh20', w.addressTest)).ivkPub) === w.IVK);
}
out.invalidAddresses = [];
for (const { address } of cv.invalidAddresses) {
  try { await sh20.decodeAddress('sh20', address); out.invalidAddresses.push(false); } catch (e) { out.invalidAddresses.push(/address:/.test(e.message)); }
}
out.sealed = [];
for (const s of cv.sealed) {
  const to = wallets[s.to];
  const o = await sh20.seal(to.address, s.ticker, BigInt(s.v), hex(s.e));
  const sealedOk = h(o.pkEph) === s.pkEph && h(o.ct) === s.ct && o.leaf.toString() === s.leaf && o.npk.toString() === s.npk
    && o.secrets.rho.toString() === s.rho && o.secrets.tauA.toString() === s.tauA;
  const output = { leaf: BigInt(s.leaf), pkEph: hex(s.pkEph), ct: hex(s.ct) };
  const mine = await scanOutput(to, output);
  let others = true;
  for (const [n, w] of Object.entries(wallets)) if (n !== s.to && (await scanOutput(w, output)) !== null) others = false;
  out.sealed.push(sealedOk && mine?.v.toString() === s.v && mine.ticker === s.ticker && others);
}
out.publicNotes = [];
for (const p of cv.publicNotes) out.publicNotes.push((await publicNote(wallets[p.wallet], p.i)).npk.toString() === p.npk);
const sp = cv.spend;
out.spendNullifiers = [];
for (const [k, inp] of sp.inputs.entries()) {
  const w = wallets[inp.wallet];
  const o = await publicNote(w, inp.publicNote);
  const leaf = sh20.noteLeaf(sh20.tickerT(sp.ticker), BigInt(inp.v), o.npk, 0n);
  out.spendNullifiers.push(nullifierOf(w, o.secrets, leaf, Number(inp.index)).toString() === sp.nf[k]);
}
out.spendOutputs = [];
for (const [j, o] of sp.outputs.entries()) out.spendOutputs.push((await scanOutput(wallets[o.to], { leaf: BigInt(sp.outLeaf[j]), pkEph: hex(o.pkEph), ct: hex(o.ct) }))?.v.toString() === o.v);
console.log(JSON.stringify(out));
