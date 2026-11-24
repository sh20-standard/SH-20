// docs/AUDIT.md §8.7: the vault's secret keys sign with constant-time code (src/secp256k1.js). The
// same bytes as before, to the bit: BIP340 vectors, the indexer's reference signer on random keys,
// the lock keys and key-path outputs of existing vaults; then what makes it constant-time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac, randomBytes } from 'node:crypto';
import { bip340Sign as sign, bip340PublicKey as publicKey, pointOf, tweakSecret, keyFromBytes, isSecretKey, arithmetic as ar } from '../src/secp256k1.js';
import * as ref from '../../indexer/src/schnorr.js';
import { keyPathOutput, oneTimeSecret } from '../src/taproot.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { NOTE_SCHEME } from '../src/notekeys.js';
import { mnemonicToSeed } from '../src/bip39.js';
import { toHex, fromHex } from '../src/bytes.js';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const b32 = (x) => fromHex(x.toString(16).padStart(64, '0'));
const big = (b) => BigInt('0x' + toHex(b));
const rnd = () => Uint8Array.from(randomBytes(32));
const mod = (a, m) => ((a % m) + m) % m;

test('8.7 the eight signing vectors of BIP340: public key and signature (0 to 3, and 15 to 18 with messages of 0, 1, 17 and 100 bytes)', () => {
  const vectors = [
    ['0000000000000000000000000000000000000000000000000000000000000003', 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9', '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'],
    ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', '0000000000000000000000000000000000000000000000000000000000000001', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'],
    ['C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9', 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8', 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906', '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C', '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7'],
    ['0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710', '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3'],
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '', '71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63'],
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '11', '08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF'],
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '0102030405060708090A0B0C0D0E0F1011', '5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5'],
    ['0340034003400340034003400340034003400340034003400340034003400340', '778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117', '0000000000000000000000000000000000000000000000000000000000000000', '99'.repeat(100), '403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367'],
  ];
  assert.equal(vectors.length, 8);
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
  // a message that is not bytes would be signed as other bytes (a string as zeros, a number as nothing)
  for (const notBytes of ['00'.repeat(32), 32, [1, 2, 3], null]) assert.throws(() => sign(b32(5n), notBytes, rnd()), /the message must be bytes/);
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
  // recorded with the BigInt code of main before this change, for the vault these words gave then: its master secret
  // had no network in it (SPEC-NOTES §8, sealing-4). A vault keeps its master secret in its record, so one made
  // before that change still opens with the keys it had.
  const m = new Map();
  const storage = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
  const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const before = createHmac('sha512', 'sh20/v0/seed').update(await mnemonicToSeed(words)).digest().subarray(0, 32);
  storage.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: toHex(before) } }));
  const v = await Vault.open(storage);
  // the same words today, on the same network: another vault
  const now = await Vault.fromWords({ getItem: () => null, setItem: () => {}, removeItem: () => {} }, words);
  assert.notEqual(now.address, v.address);
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

// The affine law in BigInt, null for the point at infinity: what the complete formulas must agree with.
const inv = (a) => { let [r, b, e] = [1n, mod(a, P), P - 2n]; for (; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P; return r; };
function affineAdd(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a[0] === b[0] && mod(a[1] + b[1], P) === 0n) return null;
  const l = a[0] === b[0] ? mod(3n * a[0] * a[0] * inv(2n * a[1]), P) : mod((b[1] - a[1]) * inv(b[0] - a[0]), P);
  const x = mod(l * l - a[0] - b[0], P);
  return [x, mod(l * (a[0] - x) - a[1], P)];
}
const GEN = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const opposite = (p) => [p[0], mod(-p[1], P)];
const xy = (p) => p && fromHex(p[0].toString(16).padStart(64, '0') + p[1].toString(16).padStart(64, '0'));

test('8.7 the complete addition: doubling, opposite points and the point at infinity, as the affine law', () => {
  const double = (p) => affineAdd(p, p);
  const pts = [GEN, double(GEN), affineAdd(double(GEN), GEN)];
  for (let i = 0; i < 12; i++) pts.push(affineAdd(double(pts[pts.length - 1]), pts[i])); // other points of the curve
  const check = (list) => assert.deepEqual(ar.sum(list.map(xy)), xy(list.reduce(affineAdd, null)), `${list.length} points`);
  for (let i = 0; i < pts.length; i++) {
    const [a, b, c] = [pts[i], pts[(i + 1) % pts.length], pts[(i + 5) % pts.length]];
    check([a]); // ∞ + P
    check([a, null]); // P + ∞
    check([null, null, a]);
    check([a, b]);
    check([a, a]); // doubling, Z = 1
    check([a, b, a, b]); // doubling of a sum: Z is no longer 1
    check([a, opposite(a)]); // the point at infinity
    check([a, b, opposite(b), opposite(a)]); // again, from points whose Z is not 1
    check([a, opposite(a), c]); // an infinity the formulas made, then a point
    check([a, opposite(a), null, c, c]);
    check([a, b, c, opposite(a), b, opposite(c), a]);
  }
  assert.equal(ar.sum([]), null);
  assert.equal(ar.sum([null, null]), null);
});

test('8.7 every entry of the table: k·G for each digit of each window', () => {
  // k·G is read from a table with the digits of k − 0x11…11: k = 0x11…11 + j·16^w reads entry j of window w
  const ones = BigInt('0x' + '1'.repeat(64));
  let entry0 = null; // 0x11…11·G
  for (let w = 0, b = GEN; w < 64; w++) {
    entry0 = affineAdd(entry0, b);
    for (let i = 0; i < 4; i++) b = affineAdd(b, b);
  }
  let seen = 0;
  for (let w = 0, base = GEN; w < 64; w++) {
    let want = entry0;
    for (let j = 0; j < 16; j++) {
      const k = (ones + (BigInt(j) << BigInt(4 * w))) % N;
      const got = pointOf(b32(k));
      assert.equal(toHex(got.x), want[0].toString(16).padStart(64, '0'), `window ${w}, digit ${j}`);
      assert.equal(got.odd, Number(want[1] & 1n), `window ${w}, digit ${j}: parity`);
      want = affineAdd(want, base);
      seen++;
    }
    for (let i = 0; i < 4; i++) base = affineAdd(base, base);
  }
  assert.equal(seen, 1024);
});

test('8.7 no BigInt and no division in the code that handles secret keys', () => {
  const src = readFileSync(new URL('../src/secp256k1.js', import.meta.url), 'utf8').replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /BigInt|\b\d+n\b|0x[0-9a-f]+n\b/i);
  // a division's time follows its operands on common processors: carries are taken with a multiplication
  assert.doesNotMatch(src.replace(/'[^'\n]*'/g, "''"), /[/%]/);
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
