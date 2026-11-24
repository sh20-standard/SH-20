// Tests written by the audit of the part `sealing` (docs/audit/2026-11-24-sealing.md): keys, addresses,
// sealing and scanning, on both entry points (index.js on node:crypto, webcrypto.js on WebCrypto).
// Each test holds a property of that report, or shows one of its findings as the code stands.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DOMAIN, FR } from '../../../indexer/src/constants.js';
import * as node from '../index.js';
import * as web from '../webcrypto.js';
import { TAG } from '../seal.js';
import { canonicalU, isLowOrder } from '../subtle.js';

const vectors = JSON.parse(readFileSync(new URL('../vectors.json', import.meta.url), 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Buffer.from(s, 'hex');
const both = [['index.js', node], ['webcrypto.js', web]];
/** Deterministic bytes for a name. */
const bytes = (name, n = 32) => createHash('sha512').update(`audit-sealing/${name}`).digest().subarray(0, n);
const wallet = async (lib, name) => lib.walletKeys(Uint8Array.from(bytes(`wallet/${name}`)));

// ── X25519, written again from RFC 7748 §5: the Montgomery ladder over BigInt ──

const P = 2n ** 255n - 19n;
const le = (b) => BigInt(`0x${Buffer.from(b).reverse().toString('hex') || '0'}`);
const toLe = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
const mod = (x) => ((x % P) + P) % P;
function power(b, e) {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P;
  return r;
}
function rfc7748(k, u) {
  const scalar = Buffer.from(k);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  const point = Buffer.from(u);
  point[31] &= 127; // "implementations MUST mask the most significant bit"; a value of p and above is taken modulo p
  const [kk, x1] = [le(scalar), le(point) % P];
  let [x2, z2, x3, z3, swap] = [1n, 0n, x1, 1n, 0n];
  for (let t = 254n; t >= 0n; t--) {
    const bit = (kk >> t) & 1n;
    if (swap ^ bit) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = bit;
    const [a, b, c, d] = [mod(x2 + z2), mod(x2 - z2), mod(x3 + z3), mod(x3 - z3)];
    const [aa, bb, da, cb] = [(a * a) % P, (b * b) % P, (d * a) % P, (c * b) % P];
    const e = mod(aa - bb);
    [x3, z3, x2, z2] = [mod(da + cb) ** 2n % P, (x1 * (mod(da - cb) ** 2n % P)) % P, (aa * bb) % P, (e * mod(aa + 121665n * e)) % P];
  }
  if (swap) [x2, z2] = [x3, z3];
  return toLe((x2 * power(z2, P - 2n)) % P);
}

const LOW = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map(unhex);
const topBit = (u) => Buffer.from(u).fill(u[31] | 0x80, 31);
/** Every encoding a sender or an address may hold that is not an ordinary key. */
function oddEncodings() {
  const odd = [...LOW, ...LOW.map(topBit)];
  for (let k = 2n; k <= 18n; k++) odd.push(toLe(P + k), topBit(toLe(P + k))); // p + k: the second encoding of k
  for (const u of [2n, 3n, 9n, P - 2n, P - 3n, (1n << 255n) - 1n]) odd.push(toLe(u), topBit(toLe(u)));
  odd.push(Buffer.alloc(32, 0xff));
  return odd;
}

// Property 3. X25519 is the function of the RFC on every encoding: bit 255 ignored, a value of p and above taken
// modulo p, zeros for the seven points of low order and for no other. The two entry points run on OpenSSL here, so
// they are held to arithmetic and not only to each other.
test('X25519 is the function of RFC 7748 on every encoding, in both entry points', async () => {
  assert.equal(hex(rfc7748(unhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), unhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'))), 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552', 'RFC 7748 §5.2');
  const cases = oddEncodings().map((u, i) => [bytes(`k/${i}`), u]);
  for (let i = 0; i < 200; i++) cases.push([bytes(`k/random/${i}`), bytes(`u/random/${i}`)]); // about half of them on the twist
  let zeros = 0;
  for (const [k, u] of cases) {
    const want = rfc7748(k, u);
    const isZero = want.every((b) => b === 0);
    zeros += isZero;
    assert.equal(isZero, isLowOrder(Uint8Array.from(u)), `low order, by its bytes: ${hex(u)}`);
    assert.equal(hex(node.x25519(k, u)), hex(want), `index.js, u = ${hex(u)}`);
    assert.equal(hex(await web.x25519(Uint8Array.from(k), Uint8Array.from(u))), hex(want), `webcrypto.js, u = ${hex(u)}`);
    // what the platform is handed: the same point, below p, bit 255 clear, and that is all canonicalU changes
    const c = canonicalU(Uint8Array.from(u));
    assert.ok(le(c) < P && hex(canonicalU(c)) === hex(c), `canonical: ${hex(u)}`);
    assert.equal(le(c), (le(u) & ((1n << 255n) - 1n)) % P);
    assert.equal(hex(rfc7748(k, c)), hex(want));
  }
  assert.equal(zeros, 14);
});

const sealedTo = async (lib, to, ticker = 'GENE', v = 700n, name = 'e') => {
  const out = await lib.seal(to.address, ticker, v, Uint8Array.from(bytes(name)));
  return { leaf: out.leaf, pkEph: Uint8Array.from(out.pkEph), ct: Uint8Array.from(out.ct) };
};

// Properties 6 and 9. No output makes a scan throw: an ephemeral key of low order is skipped, every other odd
// encoding, a random output and a malformed one are "not for this wallet". A throw would be read by the vault as a
// scan to try again at every sync.
test('no output makes a scan throw, on either entry point', async () => {
  for (const [name, lib] of both) {
    const me = await wallet(lib, 'scanner');
    const good = await sealedTo(lib, me);
    assert.equal((await lib.scan(me.ivk, me.address, good)).v, 700n, name);
    for (const u of oddEncodings()) {
      assert.equal(await lib.scan(me.ivk, me.address, { ...good, pkEph: Uint8Array.from(u) }), null, `${name}: pk_eph ${hex(u)}`);
    }
    for (let i = 0; i < 300; i++) {
      const out = { leaf: BigInt(`0x${randomBytes(32).toString('hex')}`) % FR, pkEph: Uint8Array.from(randomBytes(32)), ct: Uint8Array.from(randomBytes(28)) };
      assert.equal(await lib.scan(me.ivk, me.address, out), null, name);
    }
    for (const bad of [
      { ...good, ct: good.ct.subarray(0, 27) }, { ...good, ct: Uint8Array.from([...good.ct, 0]) }, { ...good, ct: new Uint8Array(0) },
      { ...good, pkEph: good.pkEph.subarray(0, 31) }, { ...good, pkEph: new Uint8Array(33) },
      { ...good, leaf: FR }, { ...good, leaf: -1n }, { ...good, leaf: 5 }, { ...good, leaf: null }, { ...good, ct: 'ab'.repeat(28) },
    ]) assert.equal(await lib.scan(me.ivk, me.address, bad), null, name);
  }
});

// Property 5. Every bit of an output is bound to the note: with one bit of pk_eph, of ct or of the leaf flipped,
// the recipient finds nothing. And the 28 bytes sealed for one leaf do not open under another leaf of the same sender
// to the same recipient.
test('every bit of an output is bound: 736 flips, and a ciphertext moved to another leaf', async () => {
  for (const [name, lib] of both) {
    const me = await wallet(lib, 'bound');
    const good = await sealedTo(lib, me);
    assert.ok(await lib.scan(me.ivk, me.address, good));
    for (let bit = 0; bit < 256; bit++) {
      const pkEph = Uint8Array.from(good.pkEph);
      pkEph[bit >> 3] ^= 1 << (bit & 7);
      // bit 255 is masked by X25519, but it is in the 64 bytes the note's secret is derived from
      assert.equal(await lib.scan(me.ivk, me.address, { ...good, pkEph }), null, `${name}: pk_eph bit ${bit}`);
    }
    for (let bit = 0; bit < 224; bit++) {
      const ct = Uint8Array.from(good.ct);
      ct[bit >> 3] ^= 1 << (bit & 7);
      assert.equal(await lib.scan(me.ivk, me.address, { ...good, ct }), null, `${name}: ct bit ${bit}`);
    }
    for (let bit = 0; bit < 256; bit++) {
      assert.equal(await lib.scan(me.ivk, me.address, { ...good, leaf: good.leaf ^ (1n << BigInt(bit)) }), null, `${name}: leaf bit ${bit}`);
    }
    // the same sender, recipient and ephemeral key, another amount: its ct under the first leaf, and the reverse
    const other = await sealedTo(lib, me, 'GENE', 701n);
    assert.equal(hex(other.pkEph), hex(good.pkEph));
    assert.equal(await lib.scan(me.ivk, me.address, { ...good, ct: other.ct }), null, name);
    assert.equal(await lib.scan(me.ivk, me.address, { ...other, ct: good.ct }), null, name);
    // and nobody else opens it
    const stranger = await wallet(lib, 'stranger');
    assert.equal(await lib.scan(stranger.ivk, stranger.address, good), null, name);
    assert.equal(await lib.scan(stranger.ivk, me.address, good), null, name);
  }
});

// Property 4. A (key, nonce) pair of AES-GCM never serves two plaintexts: with the ephemeral key used again, which a
// wallet must not do, another amount, another ticker or another recipient is another leaf, and so another key and
// nonce. Shown on the keystream, which is ct ⊕ plaintext for the first 12 bytes. The same note sealed twice with one
// ephemeral key is the same 92 bytes.
test('an ephemeral key used again never uses a keystream again', async () => {
  const plaintext = (ticker, v) => {
    const p = Buffer.alloc(12);
    p.writeBigUInt64LE(v);
    p.write(ticker, 8, 'latin1');
    return p;
  };
  const xor = (a, b) => Buffer.from(a.map((x, i) => x ^ b[i]));
  for (const [name, lib] of both) {
    const [me, other] = [await wallet(lib, 'reuse'), await wallet(lib, 'reuse/other')];
    const notes = [[me, 'GENE', 5n], [me, 'GENE', 6n], [me, 'SH20', 5n], [other, 'GENE', 5n], [me, 'GENE', 5n + (1n << 63n)]];
    const streams = new Set();
    for (const [to, ticker, v] of notes) {
      const out = await sealedTo(lib, to, ticker, v, 'one-e');
      assert.equal((await lib.scan(to.ivk, to.address, out)).v, v, name);
      streams.add(hex(xor(Buffer.from(out.ct.subarray(0, 12)), plaintext(ticker, v))));
    }
    assert.equal(streams.size, notes.length, `${name}: a keystream served two notes`);
    const [a, b] = [await sealedTo(lib, me, 'GENE', 5n, 'one-e'), await sealedTo(lib, me, 'GENE', 5n, 'one-e')];
    assert.deepEqual([a.leaf, hex(a.pkEph), hex(a.ct)], [b.leaf, hex(b.pkEph), hex(b.ct)]);
  }
});

// Property 1. Nothing derived serves twice: the secrets of a wallet and of its notes are all different values, and
// the strings they are hashed under are all different, none the start of another one's input.
test('the derived secrets of a wallet are all different, and so are their tags', async () => {
  const tags = [...Object.values(TAG), node.NONCE_TAG, ...Object.values(DOMAIN).filter((x) => typeof x === 'string'), 'sh20/vault/lock'];
  assert.equal(new Set(tags).size, tags.length, 'a tag is used for two things');
  // hs and hr hash tag ‖ 32 bytes ‖ one byte: two of them hash one string only if the tags are equal
  const hashed = [TAG.ask, TAG.nsk, TAG.tweakA, TAG.tweakN, TAG.rho];
  for (const a of hashed) for (const b of hashed) assert.ok(a === b || !(a.length === b.length && a === b));
  // ivk is SHA256(tag ‖ m), 47 bytes, where hs hashes 48 and the signature's nonce 84
  assert.equal(Buffer.byteLength(TAG.ivk) + 32, 47);
  assert.ok(hashed.every((t) => Buffer.byteLength(t) + 33 !== 47));

  for (const [name, lib] of both) {
    const w = await wallet(lib, 'separate');
    const out = await lib.seal(w.address, 'GENE', 1n, Uint8Array.from(bytes('separate/e')));
    const note = await lib.scan(w.ivk, w.address, { leaf: out.leaf, pkEph: Uint8Array.from(out.pkEph), ct: Uint8Array.from(out.ct) });
    const pub = [await lib.publicOpening(w.ivk, w.address, 0), await lib.publicOpening(w.ivk, w.address, 1)];
    const self = [await lib.selfSecret(w.ivk, 0), await lib.selfSecret(w.ivk, 1)];
    const keys = lib.spendKeys(w, note.secrets);
    const sig = await lib.sign(keys.sk, 7n);
    const values = [
      w.ask, w.nsk, le(Buffer.from(w.ivk).reverse()), le(Buffer.from(w.address.ivkPub).reverse()),
      note.secrets.tauA, note.secrets.tauN, note.secrets.rho, keys.sk, keys.nk, note.npk, out.leaf,
      pub[0].secrets.tauA, pub[0].secrets.tauN, pub[0].npk, pub[1].secrets.tauA, pub[1].secrets.tauN, pub[1].npk,
      le(Buffer.from(self[0]).reverse()), le(Buffer.from(self[1]).reverse()), sig.s, sig.r8[0],
    ];
    assert.equal(new Set(values).size, values.length, `${name}: two derived values are equal`);
    // the keys that spend a note are the wallet's keys moved by the note's tweaks, never the wallet's own
    assert.equal(keys.sk, (w.ask + note.secrets.tauA) % node.L);
    assert.equal(keys.nk, (w.nsk + note.secrets.tauN) % node.L);
    // a signature's nonce follows from the key and the message, and from nothing else
    assert.deepEqual(await lib.sign(keys.sk, 7n), sig);
    assert.notEqual((await lib.sign(keys.sk, 8n)).r8[0], sig.r8[0]);
    assert.notEqual((await lib.sign((keys.sk % (node.L - 2n)) + 1n, 7n)).r8[0], sig.r8[0]);
  }
});

// The small subgroup of BabyJubJub, from any point of the curve: l·Q has an order that divides 8.
function smallOrderPoints() {
  const found = new Map(); // order → point
  for (let i = 0; found.size < 3 && i < 200; i++) {
    const q = node.unpackPoint(Uint8Array.from(bytes(`curve/${i}`).fill(0, 31)));
    if (!q) continue;
    const t = node.mul(q, node.L);
    for (const order of [2n, 4n, 8n]) {
      if (!found.has(order) && node.mul(t, order)[0] === 0n && node.mul(t, order)[1] === 1n && !(node.mul(t, order / 2n)[0] === 0n && node.mul(t, order / 2n)[1] === 1n)) found.set(order, t);
    }
  }
  return found;
}

// Property 2. What a payer must refuse, beyond the fifteen addresses of the vectors: an IVK that is any of the
// fourteen encodings of a point of low order, A or N of order 2, 4 or 8 or with such a part, one bit of padding,
// one byte more or less, another network, spaces. Each is a well-formed bech32m string with a valid checksum.
test('addresses a payer must refuse, beyond the vectors', async () => {
  const good = node.walletKeys(Uint8Array.from(bytes('wallet/address'))).address;
  const payload = (a) => Buffer.concat([Buffer.from([0]), Buffer.from(a.ivkPub), node.packPoint(a.a), node.packPoint(a.n)]);
  const refused = async (s, why) => {
    for (const [name, lib] of both) {
      await assert.rejects(async () => lib.decodeAddress('tsh20', s), /address/, `${name}: ${why}`);
    }
  };
  const ok = node.bech32mEncode('tsh20', payload(good));
  for (const [, lib] of both) assert.equal(hex((await lib.decodeAddress('tsh20', ok)).ivkPub), hex(good.ivkPub));
  for (const [, lib] of both) assert.equal(hex((await lib.decodeAddress('tsh20', ok.toUpperCase())).ivkPub), hex(good.ivkPub));

  for (const u of [...LOW, ...LOW.map(topBit)]) await refused(node.bech32mEncode('tsh20', payload({ ...good, ivkPub: u })), `IVK ${hex(u)}`);
  const small = smallOrderPoints();
  assert.deepEqual([...small.keys()].sort(), [2n, 4n, 8n]);
  for (const [order, t] of small) {
    await refused(node.bech32mEncode('tsh20', payload({ ...good, a: t })), `A of order ${order}`);
    await refused(node.bech32mEncode('tsh20', payload({ ...good, n: t })), `N of order ${order}`);
    await refused(node.bech32mEncode('tsh20', payload({ ...good, a: node.add(good.a, t) })), `A with a part of order ${order}`);
    await refused(node.bech32mEncode('tsh20', payload({ ...good, n: node.add(good.n, t) })), `N with a part of order ${order}`);
  }
  await refused(node.bech32mEncode('tsh20', payload({ ...good, n: [0n, 1n] })), 'N is the identity');
  await refused(node.bech32mEncode('tsh20', payload(good).subarray(0, 96)), '96 bytes');
  await refused(node.bech32mEncode('tsh20', Buffer.concat([payload(good), Buffer.from([0])])), '98 bytes');
  await refused(node.bech32mEncode('sh20', payload(good)), 'the mainnet prefix on the test network');
  await refused(` ${ok}`, 'a space before');
  await refused(`${ok}\n`, 'a line end after');
  await refused(ok.slice(0, 40) + ok.slice(40, 41).toUpperCase() + ok.slice(41), 'one capital');
  // a payload whose last character holds a padding bit that is not zero, with the checksum made for it
  const data = ok.slice(ok.lastIndexOf('1') + 1, -6);
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const last = CHARSET.indexOf(data.at(-1));
  assert.equal(last & 0b1111, 0, '97 bytes leave four padding bits in the last character');
  const withChecksum = (body) => {
    // the checksum of bech32mEncode, for a body given in 5-bit characters
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const polymod = (values) => {
      let chk = 1;
      for (const v of values) {
        const top = chk >>> 25;
        chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
        for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
      }
      return chk;
    };
    const hrp = 'tsh20';
    const fives = [...body].map((c) => CHARSET.indexOf(c));
    const pm = (polymod([...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31), ...fives, 0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3) >>> 0;
    return `${hrp}1${body}${[0, 1, 2, 3, 4, 5].map((i) => CHARSET[(pm >>> (5 * (5 - i))) & 31]).join('')}`;
  };
  assert.equal(withChecksum(data), ok, 'the checksum written here is the reference\'s');
  await refused(withChecksum(data.slice(0, -1) + CHARSET[last | 1]), 'a padding bit set');
});

// Finding sealing-4, fixed. Nothing of the network entered a wallet's keys: the same words gave the same IVK, A and N,
// the same public openings and, in the vault, the same lock keys on signet and on mainnet, and whoever used a set of
// words on signet was recognised on mainnet at its first MINT or LIST. The address prefix of the network is now in the
// derivation of the master secret (SPEC-NOTES §1), so everything that follows from it differs.
test('sealing-4: one seed gives other keys, addresses and public openings on mainnet than on the test networks', async () => {
  for (const [name, lib] of both) {
    for (const w of vectors.wallets) {
      const seed = Uint8Array.from(unhex(w.bip39Seed));
      const [m, mTest] = [await lib.masterSecret(seed, 'sh20'), await lib.masterSecret(seed, 'tsh20')];
      assert.deepEqual([hex(m), hex(mTest)], [w.mainnet.m, w.m], `${name}: the vectors`);
      assert.notEqual(hex(m), hex(mTest), 'the same master secret on both networks: the report says this is fixed');
      const [main, testnet] = [await lib.walletKeys(m), await lib.walletKeys(mTest)];
      assert.notEqual(hex(main.address.ivkPub), hex(testnet.address.ivkPub));
      assert.notDeepEqual(main.address.a, testnet.address.a);
      assert.notDeepEqual(main.address.n, testnet.address.n);
      assert.ok(main.ask !== testnet.ask && main.nsk !== testnet.nsk && hex(main.ivk) !== hex(testnet.ivk));
      // what a MINT, a TAKE and a CLAIM write on the chain in the clear
      for (const i of [0, 1, 2]) assert.notEqual((await lib.publicOpening(main.ivk, main.address, i)).npk, (await lib.publicOpening(testnet.ivk, testnet.address, i)).npk);
      // each address is read on its own network only, and they are two payloads
      const [a, aTest] = [await lib.decodeAddress('sh20', w.mainnet.address), await lib.decodeAddress('tsh20', w.addressTest)];
      assert.notEqual(hex(a.ivkPub), hex(aTest.ivkPub));
      await assert.rejects(async () => lib.decodeAddress('tsh20', w.mainnet.address), /another network/);
    }
    // the network is named, by its address prefix and by nothing else
    const seed = Uint8Array.from(unhex(vectors.wallets[0].bip39Seed));
    for (const hrp of [undefined, null, '', 'bc', 'SH20', 'mainnet', 'sh20\0']) await assert.rejects(async () => lib.masterSecret(seed, hrp), RangeError, `${name}: ${hrp}`);
  }
  assert.equal(node.masterSecret.length, 2);
});

// Property 7, measured: what scanning one output that is not for the wallet costs.
test('what one scan costs', async () => {
  const outs = Array.from({ length: 400 }, (_, i) => ({ leaf: le(bytes(`cost/leaf/${i}`)) % FR, pkEph: Uint8Array.from(bytes(`cost/pk/${i}`)), ct: Uint8Array.from(bytes(`cost/ct/${i}`, 28)) }));
  for (const [name, lib] of both) {
    const me = await wallet(lib, 'cost');
    const started = process.hrtime.bigint();
    for (const o of outs) assert.equal(await lib.scan(me.ivk, me.address, o), null);
    const each = Number(process.hrtime.bigint() - started) / outs.length / 1e6;
    assert.ok(each < 50, `${name}: ${each.toFixed(3)} ms for each output`);
    console.log(`# ${name}: ${each.toFixed(3)} ms for each output that is not for the wallet`);
    // an output whose tag verifies costs two scalar multiplications on BabyJubJub and the leaf: whoever knows the
    // wallet's address can make it pay that, for the price of an output on the chain
    const mine = [];
    for (let i = 0; i < 20; i++) mine.push(await sealedTo(lib, me, 'GENE', BigInt(i), `cost/e/${i}`));
    const opened = process.hrtime.bigint();
    for (const o of mine) assert.ok(await lib.scan(me.ivk, me.address, o));
    const eachMine = Number(process.hrtime.bigint() - opened) / mine.length / 1e6;
    assert.ok(eachMine < 2000, `${name}: ${eachMine.toFixed(1)} ms for each output that opens`);
    console.log(`# ${name}: ${eachMine.toFixed(1)} ms for each output that opens`);
  }
});

// ── the findings that came from the second reading (report, §6), reproduced here ──

// p + each point of order 8, 2p − 1, 2p and 2p + 1, as 256-bit integers. Read as RFC 7748 says, with bit 255
// masked first, they are ordinary points. Read without the mask they are points of low order, and that is how
// Firefox's library reads them: it refuses to import them.
const FIVE = [
  'cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
  '4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
  'd9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
].map(unhex);

/** Runs `fn` on a WebCrypto that refuses the five as Firefox 160 does (measured there: a DataError from importKey). */
async function asFirefox(fn) {
  const proto = Object.getPrototypeOf(globalThis.crypto.subtle);
  const original = proto.importKey;
  const refused = new Set(FIVE.map(hex));
  proto.importKey = function (format, data, algorithm, ...rest) {
    if (format === 'raw' && (algorithm?.name ?? algorithm) === 'X25519' && refused.has(hex(data))) {
      return Promise.reject(new DOMException('Data provided to an operation does not meet requirements', 'DataError'));
    }
    return original.call(this, format, data, algorithm, ...rest);
  };
  try {
    return await fn();
  } finally {
    proto.importKey = original;
  }
}

// Finding sealing-2, fixed. Five values of pk_eph are not of low order for RFC 7748, for OpenSSL, for Chrome and for
// the Rust model, and Firefox refuses them. subtle.js handed them to the platform as they were, so in Firefox the scan
// of an output that carried one threw, at every sync. Both entry points now hand the platform the canonical encoding
// (bit 255 cleared, reduced modulo p), which Firefox takes: the scan answers "not for this wallet" there too.
test('sealing-2: five pk_eph that Firefox refuses are scanned like any other, there too', async () => {
  const k = bytes('five/k');
  for (const u of FIVE) {
    assert.equal(isLowOrder(Uint8Array.from(u)), false, 'not one of the seven: the platform is asked');
    const want = rfc7748(k, u);
    assert.ok(want.some((b) => b !== 0));
    assert.equal(hex(node.x25519(k, u)), hex(want));
    assert.equal(hex(await web.x25519(Uint8Array.from(k), Uint8Array.from(u))), hex(want));
    // the same point, written the one way every library takes
    const canonical = toLe(le(Buffer.from(u).fill(u[31] & 0x7f, 31)) % P);
    assert.equal(hex(rfc7748(k, canonical)), hex(want));
    assert.ok(!FIVE.some((x) => hex(x) === hex(canonical)));
  }
  const me = await wallet(web, 'firefox');
  const good = await sealedTo(web, me);
  for (const u of FIVE) assert.equal(await web.scan(me.ivk, me.address, { ...good, pkEph: Uint8Array.from(u) }), null, 'here: not for this wallet');
  await asFirefox(async () => {
    assert.equal((await web.scan(me.ivk, me.address, good)).v, 700n);
    for (const u of FIVE) {
      assert.equal(await web.scan(me.ivk, me.address, { ...good, pkEph: Uint8Array.from(u) }), null, 'the platform is handed the canonical encoding, which it takes');
      assert.equal(hex(await web.x25519(Uint8Array.from(k), Uint8Array.from(u))), hex(rfc7748(k, u)));
    }
    // the refusal is still an error for whoever hands the platform the bytes as they are
    await assert.rejects(globalThis.crypto.subtle.importKey('raw', FIVE[0], { name: 'X25519' }, true, []), { name: 'DataError' });
  });
});

/** What an indexer can serve beside any leaf, knowing an address and nothing else: a pk_eph and a ct whose tag verifies for it. */
function craftedFor(address, leaf, i) {
  const e = bytes(`crafted/e/${i}`);
  const pkEph = node.x25519Public(e);
  const leafBytes = toLe(leaf);
  const s = Buffer.from(hkdfSync('sha256', node.x25519(e, address.ivkPub), TAG.note, Buffer.concat([pkEph, Buffer.from(address.ivkPub)]), 32));
  const okm = Buffer.from(hkdfSync('sha256', s, TAG.aead, leafBytes, 44));
  const cipher = createCipheriv('aes-256-gcm', okm.subarray(0, 32), okm.subarray(32)).setAAD(leafBytes);
  const ct = Buffer.concat([cipher.update(Buffer.concat([Buffer.alloc(8), Buffer.from('GENE')])), cipher.final(), cipher.getAuthTag()]);
  return { leaf, pkEph: Uint8Array.from(pkEph), ct: Uint8Array.from(ct) };
}

// Finding sealing-1. A scan costs a fraction of a millisecond when the tag fails and about 0.2 s when it verifies,
// and the pk_eph and ct of a leaf are the indexer's word, under no root. So an indexer that knows an address serves a
// client leaves of the tree with bytes made for that address: the client that holds it scans for seconds, any other
// for milliseconds, and nothing is found or shown either way. The vault's next request to that indexer comes after
// the scan, so the indexer reads the answer on its own clock.
test('sealing-1: how long a scan takes tells whoever served the outputs whether the wallet holds an address', async () => {
  for (const [name, lib] of both) {
    const [owner, other] = [await wallet(lib, 'oracle'), await wallet(lib, 'oracle/other')];
    const served = Array.from({ length: 8 }, (_, i) => craftedFor(owner.address, le(bytes(`oracle/leaf/${i}`)) % FR, i));
    const scanAll = async (w) => {
      const started = process.hrtime.bigint();
      for (const o of served) assert.equal(await lib.scan(w.ivk, w.address, o), null, `${name}: nothing is found`);
      return Number(process.hrtime.bigint() - started) / 1e6;
    };
    await scanAll(other); // once, to warm up
    const [notMine, mine] = [await scanAll(other), await scanAll(owner)];
    console.log(`# ${name}: 8 outputs served for one address: ${mine.toFixed(0)} ms for its owner, ${notMine.toFixed(1)} ms for another wallet`);
    assert.ok(mine > 20 * notMine, `${name}: the two scans now take the same time: update the report`);
  }
});

// Finding sealing-6, fixed. An address whose IVK was written with bit 255 set, or with p added, was accepted by every
// decoder: X25519 reads it as the same key. But the 32 bytes of IVK are also hashed into the note's secret as the
// address writes them, and the owner scans with its own writing: what was sealed to that second address was never
// found. An address now has one encoding of IVK (SPEC-NOTES §2): the other is refused where an address is read, and
// by `seal` for an address built by hand.
test('sealing-6: a second encoding of IVK is refused wherever an address is read', async () => {
  for (const [name, lib] of both) {
    const me = await wallet(lib, 'twin');
    const seconds = [topBit(Buffer.from(me.address.ivkPub))];
    for (let k = 0n; k <= 18n; k++) seconds.push(toLe(P + k), topBit(toLe(P + k)));
    for (const u of seconds) {
      const twin = { ...me.address, ivkPub: Uint8Array.from(u) };
      const address = lib.encodeAddress('tsh20', twin);
      await assert.rejects(async () => lib.decodeAddress('tsh20', address), /one encoding/, `${name}: ${hex(u)} is read as an address`);
      await assert.rejects(async () => lib.seal(twin, 'GENE', 700n, Uint8Array.from(bytes('twin/e'))), /one encoding/, `${name}: sealed to ${hex(u)}`);
    }
    // the first writing is read, and what is sealed to it is found
    const decoded = await lib.decodeAddress('tsh20', lib.encodeAddress('tsh20', me.address));
    assert.equal(hex(decoded.ivkPub), hex(me.address.ivkPub));
    assert.equal(hex(await lib.x25519(Uint8Array.from(bytes('twin/k')), Uint8Array.from(seconds[0]))), hex(await lib.x25519(Uint8Array.from(bytes('twin/k')), me.address.ivkPub)), 'one key for X25519');
    const out = await sealedTo(lib, { address: decoded }, 'GENE', 700n, 'twin/e');
    assert.equal((await lib.scan(me.ivk, me.address, out)).v, 700n);
  }
});
