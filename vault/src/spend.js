// A spend (docs/SPEC-WIRE.md §4, SPEC-NOTES §3–§4): two inputs, three sealed outputs, and the
// witness the prover takes. Every value a proof depends on is computed by circuit/js (note keys,
// nullifiers, sealing, the body hash, EdDSA-Poseidon signatures); this file only chooses the notes,
// lays the envelope out with the indexer's codec, and packs the witness the way
// circuit/src/model.rs `SpendWitness::to_bytes` reads it (101 field elements, 32 bytes LE each):
//
//   root nf0 nf1 leaf0 leaf1 leaf2 bodyHash vPub tPub      the 9 public inputs, in the verifier's order
//   t  inV[2] inRho[2] inNk[2] inAk[2](x,y) inIndex[2]  inPath[2][32]  sigR8[2](x,y) sigS[2]
//   outV[3] outNpk[3] outRho[3]

import {
  serializeEnvelope, noteLeaf, tickerT, PROOF_BYTES, TREE_DEPTH, L, FR,
  spendKeys, noteKeys, nullifier, seal, bodyHash, eddsaSign, eddsaVerify,
} from './sh20.js';
import { bytesToBig } from './bytes.js';

export const WITNESS_BYTES = 3232;
export const PUBLIC_BYTES = 9 * 32;

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
/** Uniform enough in [1, l): 40 random bytes reduced, as the circuit's own fixtures do. */
const randomScalar = () => (bytesToBig(rand(40)) % (L - 1n)) + 1n;
const randomField = () => bytesToBig(rand(40)) % FR;

/**
 * Up to two unspent notes of `ticker` that pay `need`: the smallest single note that does, else
 * the two largest. Returns null when the vault holds too little in two notes.
 */
export function pickInputs(notes, ticker, need) {
  const usable = notes
    .filter((n) => n.ticker === ticker && n.status === 'in tree' && n.spent === 'no' && n.pos !== null && BigInt(n.v) > 0n)
    .sort((a, b) => (BigInt(a.v) < BigInt(b.v) ? -1 : BigInt(a.v) > BigInt(b.v) ? 1 : 0));
  const one = usable.find((n) => BigInt(n.v) >= need);
  if (one) return [one];
  const two = usable.slice(-2);
  return two.length === 2 && BigInt(two[0].v) + BigInt(two[1].v) >= need ? two : null;
}

/** An unused input: a note of 0 that is not in the tree, with fresh keys (SPEC-NOTES §3). */
function dummyInput(t) {
  const keys = noteKeys(randomScalar(), randomScalar());
  const rho = randomField();
  const leaf = noteLeaf(t, 0n, keys.npk, rho);
  return { keys, v: 0n, rho, leaf, index: 0, path: Array(TREE_DEPTH).fill(0n) };
}

const le32 = (x) => {
  const out = new Uint8Array(32);
  for (let i = 0, y = BigInt(x); i < 32; i++, y >>= 8n) out[i] = Number(y & 0xffn);
  return out;
};

/** The witness bytes, in the order circuit/src/model.rs reads them. */
export function packWitness(w) {
  const xs = [
    w.root, ...w.nf, ...w.outLeaf, w.bodyHash, w.vPub, w.tPub,
    w.t, ...w.inV, ...w.inRho, ...w.inNk, ...w.inAk.flat(), ...w.inIndex,
    ...w.inPath.flat(), ...w.sigR8.flat(), ...w.sigS,
    ...w.outV, ...w.outNpk, ...w.outRho,
  ];
  if (xs.length * 32 !== WITNESS_BYTES) throw new Error('witness layout');
  const out = new Uint8Array(WITNESS_BYTES);
  xs.forEach((x, i) => out.set(le32(x), 32 * i));
  return out;
}

/**
 * Builds a spend of `ticker`, ready to prove.
 *   wallet     the vault's keys (notekeys.js wallet)
 *   inputs     one or two owned notes { v, leaf, pos, tauA, tauN, rho? } with their Merkle paths
 *              (`paths[i]`, 32 siblings from the local tree whose root is `root`)
 *   outputs    three { address, v } (an address as decodeAddress returns it); v may be 0
 *   vPub, tPub value leaving the pool (0 for a TRANSFER) and its asset id
 *   envelope   (spend) => the envelope object around the spend section (TRANSFER, DEPLOY, BURN…)
 * Asynchronous (sealing and signing go through WebCrypto). Returns { env, witness, publics, body, outputs } where env.spend.proof is still zeros and
 * outputs are the sealed notes with their secrets (the vault finds its own again by scanning).
 */
export async function buildSpend({ wallet, ticker, inputs, paths, root, anchorHeight, outputs, vPub = 0n, tPub = 0n, envelope }) {
  const t = tickerT(ticker);
  if (inputs.length < 1 || inputs.length > 2 || outputs.length !== 3) throw new Error('a spend has one or two inputs and three outputs');
  const ins = inputs.map((n, i) => {
    const keys = spendKeys(wallet, { tauA: BigInt(n.tauA), tauN: BigInt(n.tauN) });
    const rho = n.rho ? BigInt('0x' + n.rho) : 0n; // public notes have rho = 0
    const leaf = BigInt('0x' + n.leaf);
    if (noteLeaf(t, BigInt(n.v), keys.npk, rho) !== leaf) throw new Error(`note at ${n.pos} does not open with this vault's keys`);
    return { keys, v: BigInt(n.v), rho, leaf, index: n.pos, path: paths[i] };
  });
  while (ins.length < 2) ins.push(dummyInput(t));

  const sumIn = ins.reduce((s, x) => s + x.v, 0n);
  const sumOut = outputs.reduce((s, o) => s + BigInt(o.v), 0n) + BigInt(vPub);
  if (sumIn !== sumOut) throw new Error(`inputs (${sumIn}) and outputs + vPub (${sumOut}) differ`);

  const nf = ins.map((x) => nullifier(x.keys.nk, x.leaf, x.index));
  const sealed = [];
  for (const o of outputs) {
    for (;;) {
      try {
        sealed.push({ to: o, ...(await seal(o.address, ticker, BigInt(o.v), rand(32))) });
        break;
      } catch (e) {
        if (!/zero tweak/.test(e.message)) throw e; // a new e only helps a zero tweak (p < 2^-250)
      }
    }
  }
  const spend = {
    anchorHeight,
    nf,
    outs: sealed.map((s) => ({ leaf: s.leaf, pkEph: s.pkEph, ct: s.ct })),
    proof: new Uint8Array(PROOF_BYTES),
  };
  const env = envelope(spend);
  const bytes = serializeEnvelope(env);
  const body = bytes.subarray(0, bytes.length - PROOF_BYTES); // every byte before the proof
  const bh = bodyHash(body);
  const sigs = await Promise.all(ins.map((x) => eddsaSign(x.keys.sk, bh)));
  ins.forEach((x, i) => { if (!eddsaVerify(x.keys.ak, bh, sigs[i])) throw new Error('signature'); });

  const w = {
    root, nf, outLeaf: sealed.map((s) => s.leaf), bodyHash: bh, vPub: BigInt(vPub), tPub: BigInt(tPub),
    t,
    inV: ins.map((x) => x.v), inRho: ins.map((x) => x.rho), inNk: ins.map((x) => x.keys.nk), inAk: ins.map((x) => x.keys.ak),
    inIndex: ins.map((x) => BigInt(x.index)), inPath: ins.map((x) => x.path),
    sigR8: sigs.map((s) => s.r8), sigS: sigs.map((s) => s.s),
    outV: sealed.map((s) => BigInt(s.to.v)), outNpk: sealed.map((s) => s.npk), outRho: sealed.map((s) => s.secrets.rho),
  };
  const witness = packWitness(w);
  return { env, witness, publics: witness.slice(0, PUBLIC_BYTES), body, outputs: sealed };
}

/** The finished envelope bytes once the proof is in. */
export function withProof(env, proof) {
  if (proof.length !== PROOF_BYTES) throw new Error('proof size');
  return serializeEnvelope({ ...env, spend: { ...env.spend, proof } });
}

/** The 9 public inputs of an envelope's spend, as the indexer derives them (for checking a proof). */
export function publicInputs({ root, env, body, vPub = 0n, tPub = 0n }) {
  const xs = [root, ...env.spend.nf, ...env.spend.outs.map((o) => o.leaf), bodyHash(body), BigInt(vPub), BigInt(tPub)];
  const out = new Uint8Array(PUBLIC_BYTES);
  xs.forEach((x, i) => out.set(le32(x), 32 * i));
  return out;
}
