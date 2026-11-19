#!/usr/bin/env node
// Writes vectors/v0.3.json: deterministic test vectors for a second, independent
// SH-20 implementation (hashes, leaves, envelopes, and a full block scenario
// with the digest after every block). Run: npm run vectors

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { poseidon2 } from '../src/poseidon.js';
import { FR, DOMAIN } from '../src/constants.js';
import { NoteTree } from '../src/tree.js';
import { noteLeaf, tickerT } from '../src/notes.js';
import { serializeEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { encodeEvents } from '../src/events.js';
import { publicKey } from '../src/schnorr.js';

const h = (s) => createHash('sha256').update(s).digest();
const fr = (seed) => BigInt('0x' + h(seed).toString('hex')) % FR;
const bytes = (seed, n) => Buffer.concat([h(seed), h(seed + '/2')]).subarray(0, n);
const txid = (seed) => h('txid/' + seed).toString('hex');
const op = (seed) => ({ npk: fr(seed + '/npk') });
const PROOF = Buffer.concat([Buffer.from('valid-proof'), Buffer.alloc(480 - 11)]);

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
  outs: [0, 1, 2].map((j) => ({ leaf: fr(`${seed}/leaf${j}`), pkEph: bytes(`${seed}/epk${j}`, 32), ct: bytes(`${seed}/ct${j}`, 28) })),
  proof: PROOF,
});

const gene = {
  type: 'DEPLOY', ticker: 'GENE', max: 21000000n, lim: 1000n, pre: 1000000n, start: 5, end: 0, unlock: 6,
  price: 1000n, payMode: 1, payScript: Buffer.alloc(0), team: op('team'), spend: spend('deploy-gene', 3),
};
const pay = Buffer.concat([Buffer.from([0x00, 0x14]), bytes('pay', 20)]);
const lockKey = publicKey(h('lock-secret'));
const lockScript = Buffer.concat([Buffer.from([0x51, 0x20]), lockKey]);
const envs = {
  mintGenesis: { type: 'MINT', ticker: 'SH20', ...op('mint1') },
  mintGenesisBatch: { type: 'MINT', ticker: 'SH20', ...op('mint0'), k: 2 },
  transfer: { type: 'TRANSFER', spend: spend('transfer', 1) },
  list: { type: 'LIST', ticker: 'SH20', amount: 1000n, price: 5000n, lockVout: 0, lockKey, payScript: pay, spend: spend('list', 1) },
  take: { type: 'TAKE', ...op('buyer') },
  deployWithTeam: gene,
  deployNoTeam: { ...gene, ticker: 'SEC2', pre: 0n, team: null, start: 7, unlock: 7, spend: spend('deploy2', 4) },
  burn: { type: 'BURN', ticker: 'SH20', vPub: 10n, spend: spend('burn', 5) },
  mintPaid: { type: 'MINT', ticker: 'GENE', ...op('mint2') },
  mintBatch: { type: 'MINT', ticker: 'GENE', ...op('mint3'), k: 3 },
  // SH20 in the pool by then: 3,000 minted − 1,000 listed + 1,000 taken − 2 × 1,000 deploy burns − 10 burned = 990.
  overBurn: { type: 'BURN', ticker: 'SH20', vPub: 991n, spend: spend('overburn', 7) },
};
const ser = Object.fromEntries(Object.entries(envs).map(([k, v]) => [k, serializeEnvelope(v)]));

const input = (seed) => ({ txid: txid(seed), vout: 0, witness: [] });
const listTxid = txid('list-tx');
const txs = [
  [
    { txid: txid('mint1'), vin: [input('f1')], vout: [{ value: 0n, script: opReturn(ser.mintGenesis) }] },
    { txid: txid('mint0'), vin: [input('f0')], vout: [{ value: 0n, script: opReturn(ser.mintGenesisBatch) }] },
  ],
  [
    // A copy of the seller's LIST, first in the block, with its lock output paying another key: refused.
    { txid: txid('list-copy-tx'), vin: [{ txid: txid('fc'), vout: 0, witness: witness(ser.list) }], vout: [{ value: 330n, script: Buffer.concat([Buffer.from([0x51, 0x20]), publicKey(h('copier-secret'))]) }] },
    { txid: listTxid, vin: [{ txid: txid('f2'), vout: 0, witness: witness(ser.list) }], vout: [{ value: 330n, script: lockScript }] },
    { txid: txid('transfer-tx'), vin: [{ txid: txid('f3'), vout: 0, witness: witness(ser.transfer) }], vout: [] },
  ],
  [{ txid: txid('take-tx'), vin: [{ txid: listTxid, vout: 0, witness: [] }, input('f4')], vout: [{ value: 0n, script: opReturn(ser.take) }, { value: 5000n, script: pay }] }],
  [{ txid: txid('deploy-gene-tx'), vin: [{ txid: txid('f5'), vout: 0, witness: witness(ser.deployWithTeam) }], vout: [] }],
  [{ txid: txid('deploy2-tx'), vin: [{ txid: txid('f6'), vout: 0, witness: witness(ser.deployNoTeam) }], vout: [] }],
  [{ txid: txid('burn-tx'), vin: [{ txid: txid('f7'), vout: 0, witness: witness(ser.burn) }], vout: [] }],
  [
    { txid: txid('mint2'), vin: [input('f8')], vout: [{ value: 1000n, script: opReturn(ser.mintPaid) }] },
    { txid: txid('mint3'), vin: [input('f9')], vout: [{ value: 3000n, script: opReturn(ser.mintBatch) }] },
  ],
  [{ txid: txid('overburn-tx'), vin: [{ txid: txid('fa'), vout: 0, witness: witness(ser.overBurn) }], vout: [] }],
];
const blocks = txs.map((t, i) => ({ height: i + 1, hash: `b${i + 1}`, txs: t }));

const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) };
const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 1000n }, verifier });
const results = blocks.map((b) => ix.applyBlock(b));
// The expected rejections: a copied LIST whose lock pays the copier, and a BURN beyond the turnstile.
const expected = [
  { height: 2, txid: txid('list-copy-tx'), reason: 'lock output must be P2TR to lockKey' },
  { height: 8, txid: txid('overburn-tx'), reason: 'more than the pool holds of this ticker' },
];
const rejected = results.flatMap((r) => r.rejected.map((x) => ({ height: r.height, txid: x.txid, reason: x.reason })));
if (JSON.stringify(rejected) !== JSON.stringify(expected)) throw new Error(`unexpected rejections: ${JSON.stringify(rejected)}`);

const hexFr = (x) => x.toString(16).padStart(64, '0');
const txJson = (t) => ({
  txid: t.txid,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => w.toString('hex')) })),
  vout: t.vout.map((o) => ({ value: o.value.toString(), script: o.script.toString('hex') })),
});

const out = {
  version: 'SH-20 draft v0.3',
  notes: 'Field elements are hex, big-endian here for readability; on the wire they are 32-byte little-endian. The scenario uses a test verifier that accepts exactly one 480-byte proof: \"valid-proof\" padded with zeros. eventsH is the byte string of SPEC-WIRE §6 whose SHA-256 enters the digest. rejected lists the envelopes an indexer must refuse; the reason is informative, only the refusal is normative.',
  poseidon2: [
    { in: ['1', '2'], out: poseidon2(1n, 2n).toString() },
    { in: ['0', '0'], out: poseidon2(0n, 0n).toString() },
  ],
  domainLeaf: hexFr(DOMAIN.LEAF),
  emptyRootDepth32: hexFr(new NoteTree().root),
  tickerT: { ticker: 'GENE', t: tickerT('GENE').toString() },
  genesis: { ticker: 'SH20', max: '21000000', lim: '1000', pre: '0', price: '0', payMode: 0, mintsFrom: 'activation height' },
  noteLeaf: { ticker: 'SH20', t: tickerT('SH20').toString(), v: '1000', npk: hexFr(envs.mintGenesis.npk), rho: '0', leaf: hexFr(noteLeaf(tickerT('SH20'), 1000n, envs.mintGenesis.npk, 0n)) },
  envelopes: Object.fromEntries(Object.entries(ser).map(([k, v]) => [k, { bytes: v.length, hex: v.toString('hex') }])),
  scenario: {
    profile: { activationHeight: 1, deployBurn: '1000', anchorWindow: 100, anchorMinDepth: 1 },
    blocks: blocks.map((b) => ({ height: b.height, txs: b.txs.map(txJson) })),
    rejected,
    after: results.map((r) => ({ height: r.height, root: hexFr(r.root), events: r.events.map((e) => e.type), eventsH: encodeEvents(r.events).toString('hex'), digest: r.digest })),
    final: {
      treeSize: ix.tree.size,
      sh20: { mints: ix.token('SH20').mints.toString(), burned: ix.token('SH20').burned.toString(), pool: ix.token('SH20').pool.toString() },
      gene: { mints: ix.token('GENE').mints.toString(), pool: ix.token('GENE').pool.toString(), teamUnlocked: ix.notes.some((x) => x.kind === 'TEAM' && x.ticker === 'GENE') },
      listing: ix.listings.get(listTxid).state,
    },
  },
};
mkdirSync(new URL('../vectors/', import.meta.url), { recursive: true });
writeFileSync(new URL('../vectors/v0.3.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote vectors/v0.3.json: ${Object.keys(ser).length} envelopes, ${blocks.length} blocks, final digest ${results.at(-1).digest}`);
