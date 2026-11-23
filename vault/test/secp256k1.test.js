// docs/AUDIT.md §8.7: the vault's secret keys sign with constant-time code (src/secp256k1.js). The
// same bytes as before, to the bit: BIP340 vectors, the indexer's reference signer on random keys,
// the lock keys and key-path outputs of existing vaults; then what makes it constant-time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { bip340Sign as sign, bip340PublicKey as publicKey, pointOf, tweakSecret, keyFromBytes, isSecretKey, arithmetic as ar } from '../src/secp256k1.js';
import * as ref from '../../indexer/src/schnorr.js';
import { keyPathOutput, oneTimeSecret } from '../src/taproot.js';
import { Vault } from '../src/keys.js';
import { toHex, fromHex } from '../src/bytes.js';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const b32 = (x) => fromHex(x.toString(16).padStart(64, '0'));
const big = (b) => BigInt('0x' + toHex(b));
const rnd = () => Uint8Array.from(randomBytes(32));
const mod = (a, m) => ((a % m) + m) % m;

test('8.7 BIP340 vectors 0 and 1: public key and signature', () => {
  const vectors = [
    ['0000000000000000000000000000000000000000000000000000000000000003', 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9', '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'],
    ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', '0000000000000000000000000000000000000000000000000000000000000001', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'],
  ];
  for (const [sk, pk, aux, msg, sig] of vectors) {
    const H = (x) => fromHex(x.toLowerCase());
    assert.equal(toHex(publicKey(H(sk))), pk.toLowerCase());
    assert.equal(toHex(sign(H(sk), H(msg), H(aux))), sig.toLowerCase());
  }
});

test('8.7 the same keys and signatures as the reference signer, on random and extreme keys', () => {
  const keys = [1n, 2n, 3n, N - 1n, N - 2n, (N - 1n) / 2n, 1n << 255n, P - 1n].map(b32);
  for (let i = 0; i < 120; i++) keys.push(rnd());
  for (const sk of keys) {
    if (!isSecretKey(sk)) continue; // a random 32 bytes at or above n: probability 2^-128
    const msg = rnd();
    const aux = rnd();
    assert.equal(toHex(publicKey(sk)), ref.publicKey(sk).toString('hex'));
    assert.equal(toHex(sign(sk, msg, aux)), ref.sign(sk, msg, aux).toString('hex'));
    // the BIP341 tweak: the key with an even y, plus t
    const t = mod(big(rnd()), N);
    const y = pointOf(sk).odd;
    const even = y ? N - big(sk) : big(sk);
    assert.equal(toHex(tweakSecret(sk, b32(t))), toHex(b32((even + t) % N)));
  }
  for (const bad of [0n, N, N + 1n, (1n << 256n) - 1n].map(b32)) {
    assert.equal(isSecretKey(bad), false);
    assert.throws(() => publicKey(bad), /bad secret key/);
    assert.throws(() => sign(bad, rnd(), rnd()), /bad secret key/);
  }
  assert.throws(() => tweakSecret(b32(5n), b32(N)), /tweak out of range/);
  assert.throws(() => sign(b32(5n), rnd(), new Uint8Array(31)), /aux/);
  // without aux, fresh randomness: two signatures of one message differ, and both verify
  const sk = rnd();
  const msg = rnd();
  const [s1, s2] = [sign(sk, msg), sign(sk, msg)];
  assert.notEqual(toHex(s1), toHex(s2));
  for (const s of [s1, s2]) assert.ok(ref.verify(publicKey(sk), msg, s));
});

test('8.7 lock keys: (x mod (n − 1)) + 1, as the BigInt code computed it', () => {
  const xs = [0n, 1n, N - 3n, N - 2n, N - 1n, N, N + 5n, (1n << 256n) - 1n].map(b32);
  for (let i = 0; i < 50; i++) xs.push(rnd());
  for (const x of xs) assert.equal(toHex(keyFromBytes(x)), toHex(b32((big(x) % (N - 1n)) + 1n)));
});

test('8.7 the field and scalar arithmetic at its edges, against BigInt', () => {
  const vals = [0n, 1n, 2n, 977n, P - 1n, P, P + 1n, (1n << 256n) - 1n, (1n << 255n), N - 1n, N, (1n << 32n) + 977n];
  for (let i = 0; i < 30; i++) vals.push(big(rnd()));
  const f = (x) => toHex(b32(mod(x, P)));
  const s = (x) => toHex(b32(mod(x, N)));
  for (const a of vals) {
    assert.equal(toHex(ar.freeze(b32(a))), f(a), `freeze ${a}`);
    if (mod(a, P) !== 0n) assert.equal(toHex(ar.fmul(ar.finv(b32(a)), b32(a))), f(1n), `inverse ${a}`);
    for (const b of [0n, 1n, P - 1n, (1n << 256n) - 1n, vals[vals.length - 1]]) {
      assert.equal(toHex(ar.fmul(b32(a), b32(b))), f(a * b), `${a} × ${b}`);
      assert.equal(toHex(ar.fadd(b32(a), b32(b))), f(a + b), `${a} + ${b}`);
      assert.equal(toHex(ar.fsub(b32(a), b32(b))), f(a - b), `${a} − ${b}`);
      assert.equal(toHex(ar.smul(b32(a), b32(b))), s(a * b), `${a} × ${b} mod n`);
      assert.equal(toHex(ar.sadd(b32(a), b32(b))), s(a + b), `${a} + ${b} mod n`);
    }
  }
});

test('8.7 the keys of existing vaults do not change: lock outputs and key-path outputs', async () => {
  // recorded with the BigInt code of main before this change
  const m = new Map();
  const storage = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
  const v = await Vault.fromWords(storage, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const locks = {
    0: ['512023e878bacbfb3d55f9b456768ebd5790877bff864242b148ee65087f59c71aba', 'c0966873d92ee3eb38d57c8650368ae98cd7686fec67cceb48dd6380a849a941'],
    1: ['51201d3dbbb98ffe91d48a7cad06586c2fc7d98fadd7f6110ac8b987f2407032383a', 'ff62ad12450a7de8668d6c7371fa0bb96c4222528db173c6a171ad0596120294'],
    7: ['51207c5a681e5278f3e0007bcf593c8703d36ed7f418d8e244641ba73b0aaedcee20', '2bfba516237d6f0a6ff53b9c0201df460f3a1957a91fdc4388fa785f2f416993'],
  };
  for (const [i, [script, secret]] of Object.entries(locks)) {
    const o = await v.lockOutput(Number(i));
    assert.equal(toHex(o.script), script);
    assert.equal(toHex(o.secret), secret);
  }
  for (const d of [1n, N - 1n].map(b32)) { // the same point, one with an odd y: the same output
    const o = keyPathOutput(d);
    assert.equal(toHex(o.script), '5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21');
    assert.equal(toHex(o.secret), '3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e8');
    assert.equal(toHex(keyPathOutput(d, fromHex('11'.repeat(32))).secret), 'be0eb8ec229123694c594b9d80ef3553facadd2334dabf9440dd56720b622102');
  }
  assert.ok(isSecretKey(oneTimeSecret()));
});

test('8.7 no BigInt in the code that handles secret keys', () => {
  const src = readFileSync(new URL('../src/secp256k1.js', import.meta.url), 'utf8').replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /BigInt|\b\d+n\b|0x[0-9a-f]+n\b/i);
  // and the vault's paths to a secret key go through it
  const taproot = readFileSync(new URL('../src/taproot.js', import.meta.url), 'utf8');
  for (const call of ['pointOf(d)', 'tweakSecret(d,', 'bip340PublicKey(secret)', 'isSecretKey(k)']) assert.ok(taproot.includes(call), call);
  assert.doesNotMatch(taproot, /schnorrSign|mul\(G, x\)/);
  const keys = readFileSync(new URL('../src/keys.js', import.meta.url), 'utf8');
  assert.match(keys, /keyPathOutput\(keyFromBytes\(wide\.subarray\(0, 32\)\)\)/);
  assert.match(readFileSync(new URL('../src/sh20.js', import.meta.url), 'utf8'), /bip340Sign as schnorrSign, bip340PublicKey as schnorrPublicKey \} from '\.\/secp256k1\.js'/);
});

test('8.7 k·G takes the same time for a key of one bit and a key of 256 (the BigInt code does not)', () => {
  const one = b32(1n);
  const full = b32(N - 2n);
  const median = (xs) => xs.sort((a, b) => a - b)[xs.length >> 1];
  const time = (f, k) => {
    const t = performance.now();
    for (let i = 0; i < 4; i++) f(k);
    return performance.now() - t;
  };
  const ratio = (f) => {
    for (let i = 0; i < 5; i++) f(one), f(full); // warm the engine up
    const a = [];
    const b = [];
    for (let i = 0; i < 15; i++) {
      a.push(time(f, one));
      b.push(time(f, full));
    }
    return median(b) / median(a);
  };
  const before = ratio((k) => ref.publicKey(k));
  const now = ratio((k) => publicKey(k));
  assert.ok(before > 5, `the measurement sees the BigInt code's leak (${before.toFixed(1)}×)`);
  console.log(`k·G: BigInt ${before.toFixed(1)}×, constant-time ${now.toFixed(2)}×`);
  assert.ok(now > 0.67 && now < 1.5, `the constant-time code: ${now.toFixed(2)}× between the two keys`);
});
