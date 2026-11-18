// docs/SPEC-NOTES.md in JavaScript against the vectors written by the Rust model (circuit/src/notes.rs,
// through circuit/src/vectors.rs): keys, addresses, sealing, scanning with the leaf check, public notes.
// The two sides share no cryptographic code: X25519, HKDF and AES-GCM are Node's here, RustCrypto's there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  bech32mDecode, bech32mEncode, decodeAddress, encodeAddress, isKeyPoint, masterSecret, mulBase8, noteKeys, noteLeaf, nullifier,
  packPoint, publicOpening, scan, seal, selfSecret, spendKeys, tickerT, unpackPoint, walletKeys, x25519, x25519Public, L, P,
} from '../index.js';

const v = JSON.parse(readFileSync(new URL('../vectors.json', import.meta.url), 'utf8'));
const n = BigInt;
const hex = (s) => Buffer.from(s, 'hex');
const str = (p) => p.map(String);
const wallets = Object.fromEntries(v.wallets.map((w) => [w.name, { vector: w, keys: walletKeys(hex(w.m)) }]));
const output = (o) => ({ leaf: n(o.leaf), pkEph: hex(o.pkEph), ct: hex(o.ct) });

test('X25519 is RFC 7748 (section 6.1)', () => {
  const a = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const b = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  assert.equal(x25519Public(a).toString('hex'), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  assert.equal(x25519Public(b).toString('hex'), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  assert.equal(x25519(a, x25519Public(b)).toString('hex'), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
  // low-order points give the zero secret
  for (const low of [Buffer.alloc(32), Buffer.concat([Buffer.from([1]), Buffer.alloc(31)])]) assert.ok(x25519(a, low).every((x) => x === 0));
});

test('bech32m is BIP-350', () => {
  for (const s of ['A1LQFN3A', 'a1lqfn3a', 'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx', '?1v759aa']) assert.doesNotThrow(() => bech32mDecode(s), s);
  // a bech32 (not bech32m) checksum, a bad character, mixed case, no separator, a short checksum
  for (const s of ['A12UEL5L', 'a1b2qfn3a', 'A1lqfn3a', 'qyrz8wqd2c9m', '1p2gdwpf', 'a1qfn3a']) assert.throws(() => bech32mDecode(s), s);
  const data = Buffer.from('00112233445566778899aabbccddeeff0102', 'hex');
  assert.deepEqual(bech32mDecode(bech32mEncode('sh20', data)), { hrp: 'sh20', data });
  assert.deepEqual(bech32mDecode(bech32mEncode('sh20', data).toUpperCase()).data, data);
});

test('wallet keys from the master secret', () => {
  for (const { vector: w, keys } of Object.values(wallets)) {
    assert.equal(masterSecret(hex(w.bip39Seed)).toString('hex'), w.m);
    assert.equal(keys.ask.toString(), w.ask);
    assert.equal(keys.nsk.toString(), w.nsk);
    assert.equal(keys.ivk.toString('hex'), w.ivk);
    assert.equal(keys.address.ivkPub.toString('hex'), w.IVK);
    assert.deepEqual(str(keys.address.a), w.A);
    assert.deepEqual(str(keys.address.n), w.N);
  }
});

test('points pack and unpack one way only', () => {
  for (const { vector: w, keys } of Object.values(wallets)) {
    assert.equal(packPoint(keys.address.a).toString('hex'), w.packA);
    assert.equal(packPoint(keys.address.n).toString('hex'), w.packN);
    assert.deepEqual(unpackPoint(hex(w.packA)), keys.address.a);
    assert.ok(isKeyPoint(keys.address.a) && isKeyPoint(keys.address.n));
  }
  // both signs of x
  const p = mulBase8(12345n);
  const minus = [P - p[0], p[1]];
  assert.notDeepEqual(packPoint(p), packPoint(minus));
  assert.deepEqual(unpackPoint(packPoint(p)), p);
  assert.deepEqual(unpackPoint(packPoint(minus)), minus);
  assert.equal(unpackPoint(Buffer.alloc(31)), null);
});

test('addresses: encoding, decoding, and what a payer refuses', () => {
  for (const { vector: w, keys } of Object.values(wallets)) {
    assert.equal(encodeAddress('sh20', keys.address), w.address);
    assert.equal(encodeAddress('tsh20', keys.address), w.addressTest);
    assert.equal(w.address.length, 167);
    assert.deepEqual(decodeAddress('sh20', w.address), keys.address);
    assert.deepEqual(decodeAddress('sh20', w.address.toUpperCase()), keys.address);
    assert.deepEqual(decodeAddress('tsh20', w.addressTest), keys.address);
    assert.throws(() => decodeAddress('sh20', w.addressTest), /another network/);
  }
  assert.ok(v.invalidAddresses.length >= 13);
  for (const { address, why } of v.invalidAddresses) assert.throws(() => decodeAddress('sh20', address), /address:/, why);
});

test('sealing: the same bytes as the Rust model, and only the recipient opens them', () => {
  assert.ok(v.sealed.some((x) => x.v === '0') && v.sealed.some((x) => x.v === String(2n ** 64n - 1n)));
  for (const x of v.sealed) {
    const to = wallets[x.to].keys;
    const out = seal(to.address, x.ticker, n(x.v), hex(x.e));
    assert.equal(out.pkEph.toString('hex'), x.pkEph);
    assert.equal(out.leaf.toString(), x.leaf);
    assert.equal(out.ct.toString('hex'), x.ct);
    assert.equal(out.ct.length, 28);
    assert.deepEqual([out.secrets.tauA, out.secrets.tauN, out.secrets.rho, out.npk].map(String), [x.tauA, x.tauN, x.rho, x.npk]);

    const found = scan(to.ivk, to.address, output(x));
    assert.deepEqual([found.ticker, found.v, found.npk.toString()], [x.ticker, n(x.v), x.npk]);
    assert.deepEqual(found.secrets, out.secrets);
    for (const [name, other] of Object.entries(wallets)) if (name !== x.to) assert.equal(scan(other.keys.ivk, other.keys.address, output(x)), null);

    // the note is spendable with the tweaked keys: they give the npk inside the leaf
    assert.equal(spendKeys(to, found.secrets).npk.toString(), x.npk);
  }
});

test('scanning refuses anything altered', () => {
  const x = v.sealed[0];
  const to = wallets[x.to].keys;
  const good = output(x);
  assert.ok(scan(to.ivk, to.address, good));
  const flip = (buf, i) => {
    const b = Buffer.from(buf);
    b[i] ^= 1;
    return b;
  };
  for (let i = 0; i < 28; i++) assert.equal(scan(to.ivk, to.address, { ...good, ct: flip(good.ct, i) }), null, `ct byte ${i}`);
  assert.equal(scan(to.ivk, to.address, { ...good, pkEph: flip(good.pkEph, 0) }), null);
  assert.equal(scan(to.ivk, to.address, { ...good, leaf: good.leaf + 1n }), null);
  assert.equal(scan(to.ivk, to.address, { ...good, ct: good.ct.subarray(0, 27) }), null);
  assert.equal(scan(to.ivk, to.address, { ...good, pkEph: Buffer.alloc(32) }), null, 'a low-order pk_eph');
  // the right ivk with another wallet's A and N: the tag verifies, the leaf does not
  const other = wallets.payer.keys;
  assert.equal(scan(to.ivk, { ...to.address, a: other.address.a }, good), null);
});

test('a note whose plaintext lies about its leaf is ignored', () => {
  // A sender who follows every step except the leaf: it publishes the leaf of 1 unit and seals
  // "1,000,000 units" under the key that this leaf gives. The tag verifies; the leaf check does not.
  const to = wallets.recipient.keys;
  const e = Buffer.alloc(32, 7);
  const honest = seal(to.address, 'GENE', 1n, e);
  const leafBytes = Buffer.from(honest.leaf.toString(16).padStart(64, '0'), 'hex').reverse();
  const z = x25519(e, to.address.ivkPub);
  const s = Buffer.from(hkdfSync('sha256', z, 'sh20/v0/note', Buffer.concat([honest.pkEph, to.address.ivkPub]), 32));
  const okm = Buffer.from(hkdfSync('sha256', s, 'sh20/v0/note/aead', leafBytes, 44));
  const plaintext = Buffer.alloc(12);
  plaintext.writeBigUInt64LE(1000000n);
  plaintext.write('GENE', 8);
  const cipher = createCipheriv('aes-256-gcm', okm.subarray(0, 32), okm.subarray(32)).setAAD(leafBytes);
  const lying = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  assert.deepEqual(scan(to.ivk, to.address, { leaf: honest.leaf, pkEph: honest.pkEph, ct: honest.ct }).v, 1n);
  assert.equal(scan(to.ivk, to.address, { leaf: honest.leaf, pkEph: honest.pkEph, ct: lying }), null);
  // and a plaintext that does not name a ticker
  plaintext.write('gene', 8);
  const c2 = createCipheriv('aes-256-gcm', okm.subarray(0, 32), okm.subarray(32)).setAAD(leafBytes);
  assert.equal(scan(to.ivk, to.address, { leaf: honest.leaf, pkEph: honest.pkEph, ct: Buffer.concat([c2.update(plaintext), c2.final(), c2.getAuthTag()]) }), null);
});

test('sealing refuses what it must', () => {
  const to = wallets.recipient.keys;
  const e = Buffer.alloc(32, 9);
  assert.throws(() => seal(to.address, 'gene', 1n, e), RangeError);
  assert.throws(() => seal(to.address, 'GENE', 2n ** 64n, e), RangeError);
  assert.throws(() => seal(to.address, 'GENE', 1, e), RangeError);
  assert.throws(() => seal({ ...to.address, ivkPub: Buffer.alloc(32) }, 'GENE', 1n, e), /low-order/);
  // two outputs with the same e and the same contents are the same bytes; any difference changes everything
  const a = seal(to.address, 'GENE', 5n, e);
  assert.deepEqual(seal(to.address, 'GENE', 5n, e), a);
  const b = seal(to.address, 'GENE', 6n, e);
  assert.notEqual(b.leaf, a.leaf);
  assert.notDeepEqual(b.ct.subarray(8), a.ct.subarray(8));
});

test('public notes: a viewing key finds them, the spend keys open them', () => {
  for (const x of v.publicNotes) {
    const { keys } = wallets[x.wallet];
    assert.equal(selfSecret(keys.ivk, x.i).toString('hex'), x.s);
    const o = publicOpening(keys.ivk, keys.address, x.i);
    assert.deepEqual([o.secrets.tauA, o.secrets.tauN, o.rho, o.npk].map(String), [x.tauA, x.tauN, x.rho, x.npk]);
    assert.equal(spendKeys(keys, o.secrets).npk.toString(), x.npk);
  }
  const { keys } = wallets.payer;
  assert.notEqual(publicOpening(keys.ivk, keys.address, 0).npk, publicOpening(keys.ivk, keys.address, 1).npk);
  assert.throws(() => selfSecret(keys.ivk, -1), RangeError);
});

test('the whole transfer, wallet by wallet', () => {
  const s = v.spend;
  const t = tickerT(s.ticker);
  // the payer spends its public notes 0 and 1
  const payer = wallets.payer.keys;
  s.inputs.forEach((input, i) => {
    const o = publicOpening(payer.ivk, payer.address, input.publicNote);
    const keys = spendKeys(payer, o.secrets);
    assert.deepEqual([keys.sk, keys.nk, o.rho].map(String), [input.sk, input.nk, input.rho]);
    const leaf = noteLeaf(t, n(input.v), o.npk, o.rho);
    assert.equal(s.treeLeaves[Number(input.index)], leaf.toString());
    assert.equal(nullifier(keys.nk, leaf, n(input.index)).toString(), s.nf[i]);
  });
  // each output is sealed as the vector says, and found by its recipient only
  s.outputs.forEach((o, k) => {
    const to = wallets[o.to].keys;
    const out = seal(to.address, s.ticker, n(o.v), hex(o.e));
    assert.deepEqual([out.leaf.toString(), out.pkEph.toString('hex'), out.ct.toString('hex')], [s.outLeaf[k], o.pkEph, o.ct]);
    for (const [name, w] of Object.entries(wallets)) {
      const found = scan(w.keys.ivk, w.keys.address, { leaf: n(s.outLeaf[k]), pkEph: hex(o.pkEph), ct: hex(o.ct) });
      assert.equal(found ? found.v : null, name === o.to ? n(o.v) : null);
    }
  });
  // the body carries the three outputs as leaf ‖ pk_eph ‖ ct
  const tail = s.outputs.map((o, k) => Buffer.concat([Buffer.from(n(s.outLeaf[k]).toString(16).padStart(64, '0'), 'hex').reverse(), hex(o.pkEph), hex(o.ct)]));
  assert.ok(hex(s.body).subarray(-3 * 92).equals(Buffer.concat(tail)));
  assert.equal(hex(s.body).length + 480, 830);
});

test('per-note keys are tweaks of the wallet keys, and what that implies', () => {
  const { keys } = wallets.recipient;
  const x = v.sealed[0];
  const note = spendKeys(keys, { tauA: n(x.tauA), tauN: n(x.tauN) });
  assert.deepEqual(noteKeys((keys.ask + n(x.tauA)) % L, (keys.nsk + n(x.tauN)) % L), note);
  // SPEC-NOTES §6: a per-note secret together with its tweak gives the wallet secret back
  assert.equal((note.sk - n(x.tauA) + L) % L, keys.ask);
  assert.equal((note.nk - n(x.tauN) + L) % L, keys.nsk);
});
