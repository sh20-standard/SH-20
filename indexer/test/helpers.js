import { createHash, randomBytes } from 'node:crypto';
import { serializeEnvelope } from '../src/codec.js';
import { FR, MAGIC, PROOF_BYTES } from '../src/constants.js';

let counter = 0;
export const txid = () => createHash('sha256').update(`tx-${counter++}`).digest('hex');

export const fr = () => BigInt('0x' + randomBytes(32).toString('hex')) % FR || 1n;

export const opening = () => ({ npk: fr(), rho: fr() });

export function pushData(data) {
  const n = data.length;
  if (n <= 75) return Buffer.concat([Buffer.from([n]), data]);
  if (n <= 255) return Buffer.concat([Buffer.from([0x4c, n]), data]);
  const len = Buffer.alloc(2);
  len.writeUInt16LE(n);
  return Buffer.concat([Buffer.from([0x4d]), len, data]);
}

export const opReturn = (data) => Buffer.concat([Buffer.from([0x6a]), pushData(data)]);

/** Tapscript reveal witness carrying an envelope in OP_0 OP_IF ... OP_ENDIF. */
export function witnessFor(envBytes) {
  const rest = envBytes.subarray(MAGIC.length);
  const parts = [Buffer.alloc(32, 7), Buffer.from([0xac]), Buffer.from([0x00, 0x63]), pushData(MAGIC)];
  for (let i = 0; i < rest.length; i += 520) parts.push(pushData(rest.subarray(i, i + 520)));
  parts.push(Buffer.from([0x68]));
  const script = Buffer.concat([Buffer.from([0x20]), ...parts]);
  const control = Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(32, 9)]);
  return [Buffer.alloc(64, 1), script, control];
}

export const p2tr = (key = randomBytes(32)) => Buffer.concat([Buffer.from([0x51, 0x20]), key]);
export const p2wpkh = () => Buffer.concat([Buffer.from([0x00, 0x14]), randomBytes(20)]);

/** A 480-byte test proof: a tag padded with zeros (the mock verifier accepts the tag "valid-proof"). */
export const testProof = (tag = 'valid-proof') => Buffer.concat([Buffer.from(tag), Buffer.alloc(PROOF_BYTES - Buffer.byteLength(tag))]);

export function spend(anchorHeight, proof = 'valid-proof') {
  return {
    anchorHeight,
    nf: [fr(), fr()],
    outs: [0, 1, 2].map(() => ({ leaf: fr(), pkEph: randomBytes(32), ct: randomBytes(28) })),
    proof: testProof(proof),
  };
}

/** Transaction carrying an envelope. carrier: 'opreturn' | 'witness'. */
export function tx({ env, carrier = 'opreturn', vin = [], vout = [], burnSats = 0n, id = txid() }) {
  const outs = [...vout];
  const inputs = [...vin];
  if (env) {
    const bytes = serializeEnvelope(env);
    if (carrier === 'opreturn') outs.unshift({ value: burnSats, script: opReturn(bytes) });
    else inputs.unshift({ txid: txid(), vout: 0, witness: witnessFor(bytes) });
  }
  if (inputs.length === 0) inputs.push({ txid: txid(), vout: 0, witness: [] });
  return { txid: id, vin: inputs, vout: outs };
}

/** Mock verifier: accepts proofs equal to "valid-proof" and records every call. */
export function mockVerifier() {
  const calls = [];
  return {
    calls,
    name: 'mock',
    verifySpend(args) {
      calls.push(args);
      return Buffer.from(args.proof).equals(testProof());
    },
  };
}

export const deployEnv = (over = {}) => ({
  type: 'DEPLOY', ticker: 'GENE', max: 21000000n, lim: 1000n, pre: 0n, start: 2, end: 0, unlock: 2,
  price: 1000n, payMode: 1, payScript: Buffer.alloc(0), team: null, spend: null, ...over,
});

/** Chain driver: feeds blocks one by one starting at height 1. */
export function chain(indexer) {
  let h = 1;
  return {
    block(...txs) {
      return indexer.applyBlock({ height: h++, hash: `h${h}`, txs });
    },
    get next() {
      return h;
    },
  };
}
