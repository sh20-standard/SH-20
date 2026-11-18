#!/usr/bin/env node
// Writes vectors/v0.1.json: deterministic test vectors for a second, independent
// SH-20 implementation (hashes, leaves, envelopes, and a full block scenario
// with the digest after every block). Run: npm run vectors

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { poseidon2 } from '../src/poseidon.js';
import { FR, DOMAIN } from '../src/constants.js';
import { NoteTree } from '../src/tree.js';
import { noteLeaf } from '../src/notes.js';
import { serializeEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { publicKey } from '../src/schnorr.js';

const h = (s) => createHash('sha256').update(s).digest();
const fr = (seed) => BigInt('0x' + h(seed).toString('hex')) % FR;
const bytes = (seed, n) => Buffer.concat([h(seed), h(seed + '/2')]).subarray(0, n);
const txid = (seed) => h('txid/' + seed).toString('hex');
const op = (seed) => ({ npk: fr(seed + '/npk'), rho: fr(seed + '/rho') });

const push = (d) => {
  if (d.length <= 75) return Buffer.concat([Buffer.from([d.length]), d]);
  if (d.length <= 255) return Buffer.concat([Buffer.from([0x4c, d.length]), d]);
  const l = Buffer.alloc(2);
  l.writeUInt16LE(d.length);
  return Buffer.concat([Buffer.from([0x4d]), l, d]);
};
const opReturn = (d) => Buffer.concat([Buffer.from([0x6a]), push(d)]);
const witness = (env) => {
  const rest = env.subarray(4);
  const parts = [Buffer.from([0x20]), Buffer.alloc(32, 7), Buffer.from([0xac, 0x00, 0x63]), push(Buffer.from('SH20'))];
  for (let i = 0; i < rest.length; i += 520) parts.push(push(rest.subarray(i, i + 520)));
  parts.push(Buffer.from([0x68]));
  return [Buffer.alloc(64, 1), Buffer.concat(parts), Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(32, 9)])];
};
const spend = (seed, anchorHeight) => ({
  anchorHeight,
  nf: [fr(seed + '/nf0'), fr(seed + '/nf1')],
  outs: [0, 1, 2].map((j) => ({ leaf: fr(`${seed}/leaf${j}`), pkEph: Buffer.concat([Buffer.from([2]), bytes(`${seed}/epk${j}`, 32)]), ct: bytes(`${seed}/ct${j}`, 28) })),
  proof: Buffer.from('valid-proof'),
});

const genesis = {
  type: 'DEPLOY', ticker: 'GENE', max: 21000000n, lim: 1000n, pre: 1000000n, start: 2, end: 0, unlock: 4,
  price: 1000n, payMode: 1, payScript: Buffer.alloc(0), team: op('team'), spend: null,
};
const pay = Buffer.concat([Buffer.from([0x00, 0x14]), bytes('pay', 20)]);
const lockKey = publicKey(h('lock-secret'));
const lockScript = Buffer.concat([Buffer.from([0x51, 0x20]), lockKey]);
const envs = {
  deployGenesis: genesis,
  mint: { type: 'MINT', tokenNum: 1, ...op('mint1') },
  transfer: { type: 'TRANSFER', spend: spend('transfer', 2) },
  list: { type: 'LIST', tokenNum: 1, amount: 1000n, price: 5000n, lockVout: 0, payScript: pay, spend: spend('list', 2) },
  take: { type: 'TAKE', ...op('buyer') },
  deploySecond: { ...genesis, ticker: 'SEC2', pre: 0n, team: null, start: 7, unlock: 7, spend: spend('deploy2', 4) },
  burn: { type: 'BURN', tokenNum: 1, vPub: 10n, spend: spend('burn', 5) },
};
const ser = Object.fromEntries(Object.entries(envs).map(([k, v]) => [k, serializeEnvelope(v)]));

const input = (seed) => ({ txid: txid(seed), vout: 0, witness: [] });
const listTxid = txid('list-tx');
const txs = [
  [{ txid: txid('deploy'), vin: [input('f0')], vout: [{ value: 0n, script: opReturn(ser.deployGenesis) }] }],
  [{ txid: txid('mint1'), vin: [input('f1')], vout: [{ value: 1000n, script: opReturn(ser.mint) }] }],
  [
    { txid: listTxid, vin: [{ txid: txid('f2'), vout: 0, witness: witness(ser.list) }], vout: [{ value: 330n, script: lockScript }] },
    { txid: txid('transfer-tx'), vin: [{ txid: txid('f3'), vout: 0, witness: witness(ser.transfer) }], vout: [] },
  ],
  [{ txid: txid('take-tx'), vin: [{ txid: listTxid, vout: 0, witness: [] }, input('f4')], vout: [{ value: 0n, script: opReturn(ser.take) }, { value: 5000n, script: pay }] }],
  [{ txid: txid('deploy2-tx'), vin: [{ txid: txid('f5'), vout: 0, witness: witness(ser.deploySecond) }], vout: [] }],
  [{ txid: txid('burn-tx'), vin: [{ txid: txid('f6'), vout: 0, witness: witness(ser.burn) }], vout: [] }],
];
const blocks = txs.map((t, i) => ({ height: i + 1, hash: `b${i + 1}`, txs: t }));

const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).toString() === 'valid-proof' };
const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 1000n }, verifier });
const results = blocks.map((b) => ix.applyBlock(b));
for (const r of results) if (r.rejected.length) throw new Error(`unexpected rejection at ${r.height}: ${JSON.stringify(r.rejected)}`);

const hexFr = (x) => x.toString(16).padStart(64, '0');
const txJson = (t) => ({
  txid: t.txid,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => w.toString('hex')) })),
  vout: t.vout.map((o) => ({ value: o.value.toString(), script: o.script.toString('hex') })),
});

const out = {
  version: 'SH-20 draft v0.1',
  notes: 'Field elements are hex, big-endian here for readability; on the wire they are 32-byte little-endian. The scenario uses a test verifier that accepts exactly the proof bytes "valid-proof".',
  poseidon2: [
    { in: ['1', '2'], out: poseidon2(1n, 2n).toString() },
    { in: ['0', '0'], out: poseidon2(0n, 0n).toString() },
  ],
  domainLeaf: hexFr(DOMAIN.LEAF),
  emptyRootDepth32: hexFr(new NoteTree().root),
  noteLeaf: { t: 1, v: '1000', npk: hexFr(envs.mint.npk), rho: hexFr(envs.mint.rho), leaf: hexFr(noteLeaf(1, 1000n, envs.mint.npk, envs.mint.rho)) },
  envelopes: Object.fromEntries(Object.entries(ser).map(([k, v]) => [k, { bytes: v.length, hex: v.toString('hex') }])),
  scenario: {
    profile: { activationHeight: 1, deployBurn: '1000', anchorWindow: 100, anchorMinDepth: 1 },
    blocks: blocks.map((b) => ({ height: b.height, txs: b.txs.map(txJson) })),
    after: results.map((r) => ({ height: r.height, root: hexFr(r.root), digest: r.digest, events: r.events.map((e) => e.type) })),
    final: {
      treeSize: ix.tree.size,
      gene: { mints: ix.token('GENE').mints.toString(), burned: ix.token('GENE').burned.toString() },
      listing: ix.listings.get(listTxid).state,
    },
  },
};
mkdirSync(new URL('../vectors/', import.meta.url), { recursive: true });
writeFileSync(new URL('../vectors/v0.1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote vectors/v0.1.json: ${Object.keys(ser).length} envelopes, ${blocks.length} blocks, final digest ${results.at(-1).digest}`);
