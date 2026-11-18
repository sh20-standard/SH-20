// The witness carrier of docs/SPEC-WIRE.md §3: a proof-carrying envelope (TRANSFER, DEPLOY with a
// burn) is revealed in the tapscript of input 0 of a transaction that spends a taproot output
// committing to that script. Two transactions:
//
//   commit   paid and signed by the user's Bitcoin wallet (an ordinary PSBT): one P2TR output
//            whose script tree is the single leaf below, worth the reveal's fee plus a dust output
//   reveal   spends it by the script path, signed here with a one-time key; its witness is
//            [sig, <E> OP_CHECKSIG OP_0 OP_IF "SH20" <pushes ≤ 520> OP_ENDIF, control], and its one
//            output returns the dust to the user
//
// The one-time key E is both the internal key and the key in the leaf, so the commit output can
// also be taken back by the key path if a reveal is never sent. BIP341 (tweak, leaf hash, control
// block, signature message) is written here and checked against the BIP341 vectors
// (test/taproot.test.js); the BIP340 signature is the indexer's (indexer/src/schnorr.js).

import { MAGIC, schnorrSign, schnorrPublicKey, taggedHash } from './sh20.js';
import { sha256 } from './hash.js';
import { concat, fromHex, toHex, u32le, u64le } from './bytes.js';
import { compactSize, pushData, serializeTx, txid as txidOf, dustLimit } from './btc.js';

// ---- secp256k1, only what the taproot tweak needs ----------------------------------------------

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => ((a % m) + m) % m;
function pow(b, e) {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
}
const inv = (a) => pow(a, P - 2n);
function add(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
  const l = a[0] === b[0] ? mod(3n * a[0] * a[0] * inv(2n * a[1])) : mod((b[1] - a[1]) * inv(b[0] - a[0]));
  const x = mod(l * l - a[0] - b[0]);
  return [x, mod(l * (a[0] - x) - a[1])];
}
function mul(p, k) {
  let r = null;
  for (let q = p; k > 0n; k >>= 1n, q = add(q, q)) if (k & 1n) r = add(r, q);
  return r;
}
const big = (b) => BigInt('0x' + (toHex(b) || '0'));
const be32 = (x) => fromHex(x.toString(16).padStart(64, '0'));
function liftX(xb) {
  const x = big(xb);
  if (x >= P) throw new Error('not an x coordinate');
  const c = mod(x ** 3n + 7n);
  const y = pow(c, (P + 1n) / 4n);
  if ((y * y) % P !== c) throw new Error('not on the curve');
  return [x, y & 1n ? P - y : y];
}

// ---- BIP341 --------------------------------------------------------------------------------------

export const LEAF_VERSION = 0xc0;

export const leafHash = (script) => new Uint8Array(taggedHash('TapLeaf', Uint8Array.of(LEAF_VERSION), compactSize(script.length), script));

/** Output key of `internal` (32-byte x-only) committing to `merkleRoot`: { key (x-only), parity }. */
export function tweakKey(internal, merkleRoot) {
  const t = big(taggedHash('TapTweak', internal, merkleRoot ?? new Uint8Array(0)));
  if (t >= N) throw new Error('tweak out of range');
  const q = add(liftX(internal), mul(G, t));
  return { key: be32(q[0]), parity: Number(q[1] & 1n), tweak: t };
}

/** The reveal's leaf: <E> OP_CHECKSIG OP_0 OP_IF "SH20" <rest in pushes of at most 520 bytes> OP_ENDIF. */
export function envelopeScript(e, envelope) {
  const rest = envelope.subarray(MAGIC.length);
  const parts = [pushData(e), Uint8Array.of(0xac, 0x00, 0x63), pushData(Uint8Array.from(MAGIC))];
  for (let i = 0; i < rest.length; i += 520) parts.push(pushData(rest.subarray(i, i + 520)));
  parts.push(Uint8Array.of(0x68));
  return concat(...parts);
}

/**
 * BIP341 signature message, SIGHASH_DEFAULT, for input `index` of `tx`. `prevouts` are the spent
 * outputs ({ value, script }) of every input; `leaf` is the leaf hash for a script-path spend.
 */
export function sigMsg(tx, index, prevouts, leaf = null) {
  const sha = (...p) => sha256(concat(...p));
  const parts = [
    Uint8Array.of(0x00, 0x00), // epoch, hash type SIGHASH_DEFAULT
    u32le(tx.version), u32le(tx.locktime),
    sha(...tx.vin.map((i) => concat(fromHex(i.txid).reverse(), u32le(i.vout)))),
    sha(...prevouts.map((o) => u64le(o.value))),
    sha(...prevouts.map((o) => concat(compactSize(o.script.length), o.script))),
    sha(...tx.vin.map((i) => u32le(i.sequence))),
    sha(...tx.vout.map((o) => concat(u64le(o.value), compactSize(o.script.length), o.script))),
    Uint8Array.of(leaf ? 2 : 0), // spend type: ext_flag 1 for a script path, no annex
    u32le(index),
  ];
  if (leaf) parts.push(leaf, Uint8Array.of(0x00), u32le(0xffffffff)); // key version 0, no OP_CODESEPARATOR
  return concat(...parts);
}

export const sigHash = (msg) => new Uint8Array(taggedHash('TapSighash', msg));

// ---- commit and reveal -------------------------------------------------------------------------

const SEQUENCE = 0xfffffffd;
const REVEAL_FRAME = 4 + 1 + 1 + 4; // version, input count, output count, locktime

/** A fresh one-time secp256k1 secret (32 bytes) in [1, n). */
export function oneTimeSecret(random = (n) => crypto.getRandomValues(new Uint8Array(n))) {
  for (;;) {
    const k = random(32);
    const x = big(k);
    if (x > 0n && x < N) return k;
  }
}

/**
 * Everything about the commit output of `envelope` for the one-time secret `secret`:
 * { e, script, leaf, scriptPubKey, control }.
 */
export function commitment(secret, envelope) {
  const e = new Uint8Array(schnorrPublicKey(secret));
  const script = envelopeScript(e, envelope);
  const leaf = leafHash(script);
  const q = tweakKey(e, leaf); // one leaf: the merkle root is the leaf hash
  return { e, script, leaf, scriptPubKey: concat(Uint8Array.of(0x51, 0x20), q.key), control: concat(Uint8Array.of(LEAF_VERSION | q.parity), e) };
}

/** Exact virtual size of the reveal: one script-path input, one output to `returnScript`. */
export function revealVsize(c, returnScript) {
  const base = REVEAL_FRAME + 41 + 8 + compactSize(returnScript.length).length + returnScript.length;
  const stack = [new Uint8Array(64), c.script, c.control];
  const witness = 2 + 1 + stack.reduce((s, x) => s + compactSize(x.length).length + x.length, 0);
  return Math.ceil((4 * base + witness) / 4);
}

/** The commit output's value: the reveal's fee at `feeRate` plus the dust it returns. */
export function commitValue(c, returnScript, feeRate) {
  return BigInt(Math.ceil(revealVsize(c, returnScript) * feeRate)) + dustLimit(returnScript);
}

/**
 * The signed reveal spending output `vout` of the commit transaction `commitTxid` (worth `value`):
 * returns { tx, hex, txid, vsize }.
 */
export function signReveal({ secret, c, commitTxid, vout = 0, value, returnScript, feeRate, aux }) {
  const fee = BigInt(Math.ceil(revealVsize(c, returnScript) * feeRate));
  const back = value - fee;
  if (back < dustLimit(returnScript)) throw new Error('the commit output does not pay the reveal');
  const tx = {
    version: 2, locktime: 0,
    vin: [{ txid: commitTxid, vout, sequence: SEQUENCE, scriptSig: new Uint8Array(0), witness: [] }],
    vout: [{ value: back, script: returnScript }],
  };
  const msg = sigHash(sigMsg(tx, 0, [{ value, script: c.scriptPubKey }], c.leaf));
  const sig = new Uint8Array(schnorrSign(secret, msg, aux ?? crypto.getRandomValues(new Uint8Array(32))));
  tx.vin[0].witness = [sig, c.script, c.control];
  const raw = serializeTx(tx);
  return { tx, hex: toHex(raw), txid: txidOf(tx), vsize: revealVsize(c, returnScript), fee };
}
