// Reference model of the SH-20 spend relation, used to build witnesses for the measurements.
//
// Keys, nullifier and EdDSA-Poseidon follow Tacit's Bitcoin shielded pool (dapp/btc-pool-zk.js),
// MIT License, Copyright (c) 2026 ross. The note leaf and the tree are the indexer's own code, so a
// witness built here is checked against the formula the indexer uses.

import { createHash, randomBytes } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { noteLeaf } from '../../indexer/src/notes.js';
import { NoteTree } from '../../indexer/src/tree.js';
import { FR, TREE_DEPTH } from '../../indexer/src/constants.js';

export const P = FR;
/** Prime subgroup order of BabyJubJub. */
export const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const A = 168700n;
const D = 168696n;
export const BASE8 = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];

const mod = (x) => ((x % P) + P) % P;
function pow(b, e) {
  let r = 1n;
  b = mod(b);
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
}
const inv = (x) => pow(x, P - 2n);

/** circomlib BabyAdd. */
export function add(p, q) {
  const tau = mod(p[0] * q[0] * p[1] * q[1]);
  return [
    mod((p[0] * q[1] + p[1] * q[0]) * inv(1n + D * tau)),
    mod((p[1] * q[1] - A * p[0] * q[0]) * inv(1n - D * tau)),
  ];
}
export function mul(p, k) {
  let r = [0n, 1n];
  let acc = p;
  for (; k > 0n; k >>= 1n) {
    if (k & 1n) r = add(r, acc);
    acc = add(acc, acc);
  }
  return r;
}
export const mulB8 = (k) => mul(BASE8, ((k % L) + L) % L);

let poseidonImpl;
export async function init() {
  poseidonImpl ||= await buildPoseidon();
}
/** circomlib Poseidon over 2..5 field elements. */
export function poseidon(inputs) {
  const F = poseidonImpl.F;
  return F.toObject(poseidonImpl(inputs.map((x) => F.e(x))));
}

export const randFr = () => BigInt('0x' + randomBytes(40).toString('hex')) % P;
export const randScalar = () => (BigInt('0x' + randomBytes(40).toString('hex')) % (L - 1n)) + 1n;

/** bodyHash = SHA256("sh20/v0/body" ‖ body) mod r   (docs/SPEC-WIRE.md §4). */
export function bodyHash(body) {
  const h = createHash('sha256').update('sh20/v0/body', 'utf8').update(body).digest('hex');
  return BigInt('0x' + h) % P;
}

/** A note's keys: sk signs, nk derives nullifiers; npk = Poseidon(Ak, NK). */
export function noteKeys(sk = randScalar(), nk = randScalar()) {
  const ak = mulB8(sk);
  const nkPub = mulB8(nk);
  return { sk, nk, ak, nkPub, npk: poseidon([ak[0], ak[1], nkPub[0], nkPub[1]]) };
}

export const nullifier = (nk, leaf, index) => poseidon([nk, leaf, BigInt(index)]);

/** EdDSA-Poseidon: S·B8 = R8 + h·8·A, h = Poseidon(R8, A, m). */
export function sign(sk, m) {
  const a = mulB8(sk);
  const r = randScalar();
  const r8 = mulB8(r);
  const h = poseidon([r8[0], r8[1], a[0], a[1], m]);
  return { r8, s: (r + 8n * h * sk) % L };
}

/**
 * Builds a spend: `inputs` = [{ t?, v, real }] (2), `outputs` = [v, v, v], `vPub`, `tPub`.
 * Real inputs are appended to a tree that already holds `filler` unrelated leaves.
 * Returns { input (circom signals), publics (decimal strings, verifier order) }.
 */
export function buildSpend({ t = 7n, inV = [600n, 400n], outV = [700n, 250n, 50n], vPub = 0n, tPub = 0n, filler = 5, body = randomBytes(64) } = {}) {
  const tree = new NoteTree();
  for (let i = 0; i < filler; i++) tree.append(randFr());

  const ins = inV.map((v) => {
    const keys = noteKeys();
    const rho = randFr();
    const leaf = noteLeaf(t, v, keys.npk, rho);
    // a dummy (v = 0) is not in the tree: any index and path will do
    const index = v === 0n ? 0 : tree.append(leaf);
    return { v, keys, rho, leaf, index };
  });
  for (let i = 0; i < filler; i++) tree.append(randFr());

  const outs = outV.map((v) => {
    const npk = noteKeys().npk;
    const rho = randFr();
    return { v, npk, rho, leaf: noteLeaf(t, v, npk, rho) };
  });

  const m = bodyHash(body);
  const sigs = ins.map((n) => sign(n.keys.sk, m));
  const paths = ins.map((n) => (n.v === 0n ? new Array(TREE_DEPTH).fill(0n) : tree.path(n.index)));
  const nf = ins.map((n) => nullifier(n.keys.nk, n.leaf, n.index));

  const s = (x) => x.toString();
  const input = {
    root: s(tree.root),
    nf: nf.map(s),
    outLeaf: outs.map((o) => s(o.leaf)),
    bodyHash: s(m),
    vPub: s(vPub),
    tPub: s(tPub),
    t: s(t),
    inV: ins.map((n) => s(n.v)),
    inRho: ins.map((n) => s(n.rho)),
    inNk: ins.map((n) => s(n.keys.nk)),
    inAk: ins.map((n) => n.keys.ak.map(s)),
    inIndex: ins.map((n) => s(n.index)),
    inPath: paths.map((p) => p.map(s)),
    sigR8: sigs.map((g) => g.r8.map(s)),
    sigS: sigs.map((g) => s(g.s)),
    outV: outs.map((o) => s(o.v)),
    outNpk: outs.map((o) => s(o.npk)),
    outRho: outs.map((o) => s(o.rho)),
  };
  const publics = [input.root, ...input.nf, ...input.outLeaf, input.bodyHash, input.vPub, input.tPub];
  return { input, publics };
}
