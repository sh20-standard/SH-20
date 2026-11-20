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
import { parseEnvelope, serializeEnvelope } from '../src/codec.js';
import { extractEnvelope } from '../src/carrier.js';
import { Indexer } from '../src/indexer.js';
import { encodeEvents } from '../src/events.js';
import { publicKey, sign } from '../src/schnorr.js';

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
const p2tr = (key) => Buffer.concat([Buffer.from([0x51, 0x20]), key]);
const lockKey2 = publicKey(h('lock2-secret'));
const lockKey3 = publicKey(h('lock3-secret'));
const list2Txid = txid('list2-tx');
const list3Txid = txid('list3-tx');
const lockKeyN = (n) => publicKey(h(`lock${n}-secret`));
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
  // Blocks 9 to 11: a listing closed without a TAKE and then claimed, a listing cancelled by an unpaid TAKE.
  list2: { type: 'LIST', ticker: 'GENE', amount: 1000n, price: 7000n, lockVout: 0, lockKey: lockKey2, payScript: pay, spend: spend('list2', 8) },
  list3: { type: 'LIST', ticker: 'GENE', amount: 500n, price: 3000n, lockVout: 0, lockKey: lockKey3, payScript: pay, spend: spend('list3', 8) },
  cancel3: { type: 'TAKE', ...op('seller3') },
  claim2: { type: 'CLAIM', listTxid: list2Txid, ...op('claim2'), sig: sign(h('lock2-secret'), Indexer.claimMessage(list2Txid, op('claim2').npk)) },
  claimForged: { type: 'CLAIM', listTxid: list2Txid, ...op('forged'), sig: sign(h('not-the-lock'), Indexer.claimMessage(list2Txid, op('forged').npk)) },
  // Blocks 12 and 13: four listings (one anchored below A, on the empty root), then a transaction with two envelopes
  // that spends a lock, a CLAIM in the transaction that spends its own lock, and a TAKE that spends two locks.
  list4: { type: 'LIST', ticker: 'GENE', amount: 100n, price: 1000n, lockVout: 0, lockKey: lockKeyN(4), payScript: pay, spend: spend('list4', 0) },
  list5: { type: 'LIST', ticker: 'GENE', amount: 100n, price: 1000n, lockVout: 0, lockKey: lockKeyN(5), payScript: pay, spend: spend('list5', 11) },
  list6: { type: 'LIST', ticker: 'GENE', amount: 100n, price: 1000n, lockVout: 0, lockKey: lockKeyN(6), payScript: pay, spend: spend('list6', 11) },
  list7: { type: 'LIST', ticker: 'GENE', amount: 100n, price: 1000n, lockVout: 0, lockKey: lockKeyN(7), payScript: pay, spend: spend('list7', 11) },
  claimTooEarly: { type: 'CLAIM', listTxid: txid('list5-tx'), ...op('claim5'), sig: sign(h('lock5-secret'), Indexer.claimMessage(txid('list5-tx'), op('claim5').npk)) },
  take6: { type: 'TAKE', ...op('buyer6') },
  // Blocks 14 to 17, with W = 12 and K_min = 1: the anchor window at both ends, nullifiers spent before, earlier in the
  // block and twice in one spend, a payMode 2 token, and two team notes unlocked in one block.
  mintSH20x10: { type: 'MINT', ticker: 'SH20', ...op('mint-sh20-10'), k: 10 },
  anchorOldest: { type: 'TRANSFER', spend: spend('anchor-oldest', 2) }, // H − W = 14 − 12
  anchorTooOld: { type: 'TRANSFER', spend: spend('anchor-too-old', 1) },
  anchorNewest: { type: 'TRANSFER', spend: spend('anchor-newest', 13) }, // H − K_min = 14 − 1
  anchorTooNew: { type: 'TRANSFER', spend: spend('anchor-too-new', 14) },
  nfSpentBefore: { type: 'TRANSFER', spend: { ...spend('nf-spent-before', 13), nf: [spend('transfer', 1).nf[0], fr('nf-spent-before/x')] } },
  nfSpentInBlock: { type: 'TRANSFER', spend: { ...spend('nf-spent-in-block', 13), nf: [fr('nf-spent-in-block/x'), spend('anchor-oldest', 2).nf[1]] } },
  nfTwice: { type: 'TRANSFER', spend: { ...spend('nf-twice', 13), nf: [fr('nf-twice/x'), fr('nf-twice/x')] } },
  deployPay2: {
    type: 'DEPLOY', ticker: 'PAY2', max: 100000n, lim: 1000n, pre: 10000n, start: 16, end: 0, unlock: 17,
    price: 2000n, payMode: 2, payScript: pay, team: op('team-pay2'), spend: spend('deploy-pay2', 14),
  },
  deployBeta: {
    type: 'DEPLOY', ticker: 'BETA', max: 50000n, lim: 500n, pre: 5000n, start: 16, end: 0, unlock: 17,
    price: 0n, payMode: 0, payScript: Buffer.alloc(0), team: op('team-beta'), spend: spend('deploy-beta', 14),
  },
  mintPay2: { type: 'MINT', ticker: 'PAY2', ...op('mint-pay2') },
  mintPay2OpReturn: { type: 'MINT', ticker: 'PAY2', ...op('mint-pay2-opreturn') },
  mintPay2Short: { type: 'MINT', ticker: 'PAY2', ...op('mint-pay2-short') },
  mintPay2Split: { type: 'MINT', ticker: 'PAY2', ...op('mint-pay2-split'), k: 2 },
  mintBeta: { type: 'MINT', ticker: 'BETA', ...op('mint-beta') },
  transferR: { type: 'TRANSFER', spend: spend('transfer-r', 15) },
  // The reorg: blocks 16 and 17 replaced. 16' spends the nullifiers of transferR again, which only a rollback allows.
  transferR2: { type: 'TRANSFER', spend: { ...spend('transfer-r2', 15), nf: spend('transfer-r', 15).nf } },
  mintBeta2: { type: 'MINT', ticker: 'BETA', ...op('mint-beta-2') },
};
const ser = Object.fromEntries(Object.entries(envs).map(([k, v]) => [k, serializeEnvelope(v)]));

const input = (seed) => ({ txid: txid(seed), vout: 0, witness: [] });
const wit = (k) => ({ txid: txid(k + '-tx'), vin: [{ txid: txid('fund-' + k), vout: 0, witness: witness(ser[k]) }], vout: [] });
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
  [
    // N = 3 here. A copy of GENE's DEPLOY seen in the mempool, its commit confirmed in block 3: refused (too young).
    // The same DEPLOY in an OP_RETURN: refused (a DEPLOY uses the witness carrier). The original, committed in block 1.
    { txid: txid('deploy-gene-copy-tx'), vin: [{ txid: txid('f5c'), vout: 0, witness: witness(ser.deployWithTeam), prevHeight: 3 }], vout: [] },
    { txid: txid('deploy-gene-opreturn-tx'), vin: [input('f5o')], vout: [{ value: 0n, script: opReturn(ser.deployWithTeam) }] },
    { txid: txid('deploy-gene-tx'), vin: [{ txid: txid('f5'), vout: 0, witness: witness(ser.deployWithTeam), prevHeight: 1 }], vout: [] },
  ],
  [{ txid: txid('deploy2-tx'), vin: [{ txid: txid('f6'), vout: 0, witness: witness(ser.deployNoTeam), prevHeight: 2 }], vout: [] }],
  [{ txid: txid('burn-tx'), vin: [{ txid: txid('f7'), vout: 0, witness: witness(ser.burn) }], vout: [] }],
  [
    { txid: txid('mint2'), vin: [input('f8')], vout: [{ value: 1000n, script: opReturn(ser.mintPaid) }] },
    { txid: txid('mint3'), vin: [input('f9')], vout: [{ value: 3000n, script: opReturn(ser.mintBatch) }] },
  ],
  [{ txid: txid('overburn-tx'), vin: [{ txid: txid('fa'), vout: 0, witness: witness(ser.overBurn) }], vout: [] }],
  [
    { txid: list2Txid, vin: [{ txid: txid('fb'), vout: 0, witness: witness(ser.list2) }], vout: [{ value: 330n, script: p2tr(lockKey2) }] },
    { txid: list3Txid, vin: [{ txid: txid('fd'), vout: 0, witness: witness(ser.list3) }], vout: [{ value: 330n, script: p2tr(lockKey3) }] },
  ],
  [
    // The lock of list2 spent with no envelope: CLOSED. The lock of list3 spent by an unpaid TAKE: CANCELLED.
    { txid: txid('close2-tx'), vin: [{ txid: list2Txid, vout: 0, witness: [] }], vout: [{ value: 300n, script: pay }] },
    { txid: txid('cancel3-tx'), vin: [{ txid: list3Txid, vout: 0, witness: [] }, input('fe')], vout: [{ value: 0n, script: opReturn(ser.cancel3) }] },
  ],
  [
    { txid: txid('claim-forged-tx'), vin: [input('ff')], vout: [{ value: 0n, script: opReturn(ser.claimForged) }] },
    { txid: txid('claim2-tx'), vin: [input('fg')], vout: [{ value: 0n, script: opReturn(ser.claim2) }] },
  ],
  [4, 5, 6, 7].map((n) => ({ txid: txid(`list${n}-tx`), vin: [{ txid: txid(`fh${n}`), vout: 0, witness: witness(ser[`list${n}`]) }], vout: [{ value: 330n, script: p2tr(lockKeyN(n)) }] })),
  [
    // Two envelopes: refused, nothing applied, and the lock it spends is still CLOSED.
    { txid: txid('two-envelopes-tx'), vin: [{ txid: txid('list4-tx'), vout: 0, witness: [] }], vout: [{ value: 0n, script: opReturn(ser.mintGenesis) }, { value: 0n, script: opReturn(ser.take) }] },
    // A CLAIM in the transaction that spends its own lock: refused (the listing is ACTIVE when it applies), then CLOSED.
    { txid: txid('claim-too-early-tx'), vin: [{ txid: txid('list5-tx'), vout: 0, witness: [] }], vout: [{ value: 0n, script: opReturn(ser.claimTooEarly) }] },
    // A paid TAKE spending the locks of list6 then list7: list6 SOLD, then list7 CLOSED.
    { txid: txid('take6-tx'), vin: [{ txid: txid('list6-tx'), vout: 0, witness: [] }, { txid: txid('list7-tx'), vout: 0, witness: [] }], vout: [{ value: 0n, script: opReturn(ser.take6) }, { value: 1000n, script: pay }] },
  ],
  [
    { txid: txid('mint-sh20-10'), vin: [input('fi')], vout: [{ value: 0n, script: opReturn(ser.mintSH20x10) }] },
    ...['anchorOldest', 'anchorTooOld', 'anchorNewest', 'anchorTooNew', 'nfSpentBefore', 'nfSpentInBlock', 'nfTwice'].map((k) => wit(k)),
  ],
  [
    // PAY2 first, its commit exactly N = 3 blocks old; BETA second: their team notes still unlock in ticker order.
    { txid: txid('deploy-pay2-tx'), vin: [{ txid: txid('fj'), vout: 0, witness: witness(ser.deployPay2), prevHeight: 12 }], vout: [] },
    { txid: txid('deploy-beta-tx'), vin: [{ txid: txid('fk'), vout: 0, witness: witness(ser.deployBeta), prevHeight: 5 }], vout: [] },
  ],
  [
    // payMode 2 counts the outputs to payScript only: paid, paid in an OP_RETURN (refused), one sat short (refused),
    // k = 2 paid by two outputs. Then a free mint and a transfer that the reorg below takes back.
    { txid: txid('mint-pay2'), vin: [input('fl')], vout: [{ value: 0n, script: opReturn(ser.mintPay2) }, { value: 2000n, script: pay }] },
    { txid: txid('mint-pay2-opreturn'), vin: [input('fm')], vout: [{ value: 2000n, script: opReturn(ser.mintPay2OpReturn) }] },
    { txid: txid('mint-pay2-short'), vin: [input('fn')], vout: [{ value: 0n, script: opReturn(ser.mintPay2Short) }, { value: 1999n, script: pay }] },
    { txid: txid('mint-pay2-split'), vin: [input('fo')], vout: [{ value: 0n, script: opReturn(ser.mintPay2Split) }, { value: 2000n, script: pay }, { value: 2000n, script: pay }] },
    { txid: txid('mint-beta'), vin: [input('fp')], vout: [{ value: 0n, script: opReturn(ser.mintBeta) }] },
    wit('transferR'),
  ],
  [], // block 17: the team notes of BETA and PAY2, in that order
];
const blocks = txs.map((t, i) => ({ height: i + 1, hash: `b${i + 1}`, txs: t }));

// The test verifier accepts one proof; every call records the nine public inputs it was given (SPEC-WIRE §4),
// so that a second implementation can check what it would hand to the real PLONK verifier.
const verifierCalls = [];
const verifier = {
  name: 'test',
  verifySpend: (a) => {
    verifierCalls.push({
      height: ix._ctx.height,
      txid: ix._ctx.txid,
      publicInputs: [a.root, ...a.nullifiers, ...a.outLeaves, a.bodyHash, a.vPub, a.tPub].map((x) => hexFr(x)),
    });
    return Buffer.from(a.proof).equals(PROOF);
  },
};
const hexFr = (x) => x.toString(16).padStart(64, '0');
const PROFILE = { activationHeight: 1, deployBurn: 1000n, deployMaturity: 3, anchorWindow: 12 };
const ix = new Indexer({ profile: PROFILE, verifier });
const results = blocks.map((b) => ix.applyBlock(b));
const tok = (t) => ({ mints: ix.token(t).mints.toString(), pool: ix.token(t).pool.toString(), teamUnlocked: ix.notes.some((x) => x.kind === 'TEAM' && x.ticker === t) });
const finalState = {
  treeSize: ix.tree.size,
  sh20: { mints: ix.token('SH20').mints.toString(), burned: ix.token('SH20').burned.toString(), pool: ix.token('SH20').pool.toString() },
  gene: tok('GENE'),
  pay2: tok('PAY2'),
  beta: tok('BETA'),
  listings: Object.fromEntries([listTxid, list2Txid, list3Txid, ...[4, 5, 6, 7].map((n) => txid(`list${n}-tx`))].map((id) => [id, ix.listings.get(id).state])),
};

// The reorg: blocks 16 and 17 give way to 16' and 17'. An indexer rolls back to block 15 and applies them; every root and
// digest must be those of a chain that never had the first 16 and 17, which a fresh indexer checks here.
const reorgFrom = 15;
const reorgBlocks = [
  { height: 16, hash: "b16'", txs: [wit('transferR2'), { txid: txid('mint-beta-2'), vin: [input('fq')], vout: [{ value: 0n, script: opReturn(ser.mintBeta2) }] }] },
  { height: 17, hash: "b17'", txs: [] },
];
const callsBeforeReorg = verifierCalls.length;
ix.rollback(reorgFrom);
const reorgResults = reorgBlocks.map((b) => ix.applyBlock(b));
const reorgCalls = verifierCalls.splice(callsBeforeReorg);
const fresh = new Indexer({ profile: PROFILE, verifier: { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) } });
for (const b of [...blocks.slice(0, reorgFrom), ...reorgBlocks]) fresh.applyBlock(b);
if (fresh.digest.toString('hex') !== ix.digest.toString('hex')) throw new Error('the reorg does not end where a fresh chain does');
if (reorgResults.some((r) => r.rejected.length)) throw new Error('a block of the reorg refused something');
// The expected rejections: a copied LIST whose lock pays the copier, and a BURN beyond the turnstile.
const expected = [
  { height: 2, txid: txid('list-copy-tx'), reason: 'lock output must be P2TR to lockKey' },
  { height: 4, txid: txid('deploy-gene-copy-tx'), reason: 'DEPLOY commit confirmed less than 3 blocks before' },
  { height: 4, txid: txid('deploy-gene-opreturn-tx'), reason: 'DEPLOY must use the witness carrier' },
  { height: 8, txid: txid('overburn-tx'), reason: 'more than the pool holds of this ticker' },
  { height: 11, txid: txid('claim-forged-tx'), reason: 'bad CLAIM signature' },
  { height: 13, txid: txid('two-envelopes-tx'), reason: 'more than one SH-20 envelope in the transaction' },
  { height: 13, txid: txid('claim-too-early-tx'), reason: 'listing is not CLOSED' },
  { height: 14, txid: txid('anchorTooOld-tx'), reason: 'anchor outside the window' },
  { height: 14, txid: txid('anchorTooNew-tx'), reason: 'anchor outside the window' },
  { height: 14, txid: txid('nfSpentBefore-tx'), reason: 'nullifier already spent' },
  { height: 14, txid: txid('nfSpentInBlock-tx'), reason: 'nullifier already spent' },
  { height: 14, txid: txid('nfTwice-tx'), reason: 'duplicate nullifier' },
  { height: 16, txid: txid('mint-pay2-opreturn'), reason: 'mint not paid' },
  { height: 16, txid: txid('mint-pay2-short'), reason: 'mint not paid' },
];
const rejected = results.flatMap((r) => r.rejected.map((x) => ({ height: r.height, txid: x.txid, reason: x.reason })));
if (JSON.stringify(rejected) !== JSON.stringify(expected)) throw new Error(`unexpected rejections: ${JSON.stringify(rejected)}`);

const txJson = (t) => ({
  txid: t.txid,
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => w.toString('hex')), ...(i.prevHeight !== undefined ? { prevHeight: i.prevHeight } : {}) })),
  vout: t.vout.map((o) => ({ value: o.value.toString(), script: o.script.toString('hex') })),
});

const bodyHash = (bytes) => {
  const { body } = parseEnvelope(bytes);
  return body ? hexFr(BigInt('0x' + createHash('sha256').update(DOMAIN.BODY).update(body).digest('hex')) % FR) : undefined;
};

// Carrier cases (SPEC-WIRE §3): a transaction, and what an indexer must find in it: no envelope ("none"), more than
// one counted envelope ("many": the transaction is refused), or the bytes of the one envelope.
const M = ser.mintGenesis;
const KEY = Buffer.concat([Buffer.from([0x20]), Buffer.alloc(32, 7), Buffer.from([0xac])]); // <key> OP_CHECKSIG
const SIG = Buffer.alloc(64, 1);
const CONTROL = Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(32, 9)]);
const env0 = (...parts) => Buffer.concat([KEY, Buffer.from([0x00, 0x63, 0x04]), Buffer.from('SH20'), ...parts, Buffer.from([0x68])]);
const body = M.subarray(4); // the 38 bytes after "SH20"
const plain = env0(push(body));
const wtx = (script, extra = {}) => ({
  vin: [{ witness: [SIG, script, extra.control ?? CONTROL, ...(extra.annex ? [extra.annex] : [])] }, ...(extra.vin ?? [])],
  vout: extra.vout ?? [],
});
const otx = (...scripts) => ({ vin: [{ witness: [] }], vout: scripts.map((script) => ({ value: 0n, script })) });
const v1 = Buffer.concat([Buffer.from('SH20'), Buffer.from([0x01, 0x02]), Buffer.alloc(36, 3)]);
const carrierCases = [
  ['opreturn', otx(opReturn(M)), M],
  ['opreturn: a 42-byte push written with OP_PUSHDATA1 is not minimal', otx(Buffer.concat([Buffer.from([0x6a, 0x4c, M.length]), M])), 'none'],
  ['opreturn: a second push after the envelope', otx(Buffer.concat([opReturn(M), push(Buffer.from('extra'))])), 'none'],
  ['opreturn: data that does not start with SH20', otx(opReturn(Buffer.concat([Buffer.from('x'), M]))), 'none'],
  ['opreturn: two outputs', otx(opReturn(M), opReturn(M)), 'many'],
  ['opreturn: SH20 alone is an envelope (that decoding refuses)', otx(opReturn(Buffer.from('SH20'))), Buffer.from('SH20')],
  ['opreturn and witness', { ...wtx(plain), vout: [{ value: 0n, script: opReturn(M) }] }, 'many'],
  ['witness', wtx(plain), M],
  ['witness: with an annex', wtx(plain, { annex: Buffer.from([0x50, 0x01]) }), M],
  ['witness: a control block of 65 bytes', wtx(plain, { control: Buffer.concat([CONTROL, Buffer.alloc(32, 8)]) }), M],
  ['witness: leaf version 0xc2 is not a tapscript', wtx(plain, { control: Buffer.concat([Buffer.from([0xc2]), Buffer.alloc(32, 9)]) }), 'none'],
  ['witness: on input 1 only', { vin: [{ witness: [SIG] }, { witness: [SIG, plain, CONTROL] }], vout: [] }, 'none'],
  ['witness: the tag pushed with OP_PUSHDATA1', wtx(Buffer.concat([KEY, Buffer.from([0x00, 0x63, 0x4c, 0x04]), Buffer.from('SH20'), push(body), Buffer.from([0x68])])), 'none'],
  ['witness: a last byte 0x05 written OP_5 (minimal): a MINT with k = 5', wtx(env0(push(body), Buffer.from([0x55]))), Buffer.concat([M, Buffer.from([0x05])])],
  ['witness: a last byte 0x05 written 01 05 (not minimal)', wtx(env0(push(body), Buffer.from([0x01, 0x05]))), 'none'],
  ['witness: an empty chunk written OP_0', wtx(env0(Buffer.from([0x00]), push(body))), M],
  ['witness: a pattern broken by OP_DROP, then a whole envelope', wtx(Buffer.concat([env0(push(body)).subarray(0, KEY.length + 7), push(body), Buffer.from([0x75]), env0(push(body)).subarray(KEY.length)])), M],
  ['witness: two whole envelopes', wtx(Buffer.concat([plain, env0(push(body)).subarray(KEY.length)])), 'many'],
  ['witness: a push of 521 bytes', wtx(env0(push(Buffer.concat([body, Buffer.alloc(483)])))), 'none'],
  ['witness: a script that does not split (a push past its end)', wtx(Buffer.concat([KEY, Buffer.from([0x00, 0x63, 0x04]), Buffer.from('SH20'), Buffer.from([0x4c, 0xff])])), 'none'],
  ['an envelope of version 1 beside a v0 envelope: the v0 one alone counts', { ...wtx(plain), vout: [{ value: 0n, script: opReturn(v1) }] }, M],
  ['an envelope of version 1 alone', otx(opReturn(v1)), 'none'],
  ['coinbase: its OP_RETURN outputs are read', { vin: [{ coinbase: true }], vout: [{ value: 0n, script: opReturn(M) }] }, M],
  ['coinbase: the witness of its input is not read', { vin: [{ coinbase: true, witness: [SIG, plain, CONTROL] }], vout: [] }, 'none'],
  ['opreturn: a push of 65,536 bytes is minimal only with OP_PUSHDATA4, so it counts beside a second envelope', otx(opReturn(M), Buffer.concat([Buffer.from([0x6a, 0x4e, 0x00, 0x00, 0x01, 0x00]), Buffer.from('SH20'), Buffer.alloc(65532)])), 'many'],
];
const carriers = carrierCases.map(([name, tx, expect]) => {
  const t = { txid: txid('carrier/' + name), ...tx };
  const found = extractEnvelope(t);
  const got = found.none ? 'none' : found.error ? 'many' : found.bytes.toString('hex');
  const want = Buffer.isBuffer(expect) ? expect.toString('hex') : expect;
  if (got !== want) throw new Error(`carrier case "${name}": expected ${want}, got ${got}`);
  return {
    name,
    tx: {
      vin: t.vin.map((i) => (i.coinbase ? { coinbase: true, ...(i.witness ? { witness: i.witness.map((w) => w.toString('hex')) } : {}) } : { witness: i.witness.map((w) => w.toString('hex')) })),
      vout: t.vout.map((o) => ({ value: o.value.toString(), script: o.script.toString('hex') })),
    },
    expect: want,
  };
});

const out = {
  version: 'SH-20 draft v0.3',
  notes: 'Field elements are hex, big-endian here for readability; on the wire they are 32-byte little-endian. The scenario uses a test verifier that accepts exactly one 480-byte proof: \"valid-proof\" padded with zeros. eventsH is the byte string of SPEC-WIRE §6 whose SHA-256 enters the digest. rejected lists the envelopes an indexer must refuse; the reason is informative, only the refusal is normative.',
  sections: {
    envelopes: 'Each envelope of the scenario and of the reorg: its bytes, and for a spend its bodyHash (SPEC-WIRE §4: SHA256("sh20/v0/body" ‖ body) mod r, body from "SH20" up to the proof).',
    claim: 'One CLAIM: the message SHA256("sh20/v0/claim" ‖ listTxid ‖ npk) and its BIP340 signature by lockKey, with 32 zero bytes of auxiliary randomness.',
    preActivation: 'digest_{A-1}: the digest an indexer starts from at block A.',
    carriers: 'One transaction each, and what SPEC-WIRE §3 finds in it. expect is the hex of the one counted envelope, "none" when no envelope is counted (an envelope of another version alone is "none"), or "many" when two or more are counted (the transaction is refused). Inputs give their witness only; their outpoints play no part. {"coinbase": true} is the input of a coinbase; its witness, when given, is not read.',
    'scenario.verifierCalls': 'Every call to the verifier, in order, with its nine public inputs in the order of SPEC-WIRE §4: R[anchorHeight], nf0, nf1, leaf0, leaf1, leaf2, bodyHash, vPub, tPub. The proof is checked last (§5), so a spend refused for another reason is not in the list. An anchor below A is checked against the empty root.',
    'scenario.after': 'For each block: root R[H], the event types, eventsH, and digest_H.',
    'scenario.blocks': 'The transactions of each block. vin[].prevHeight is the height of the block that confirmed the output an input spends, given where a DEPLOY needs it (SPEC-WIRE §5: its commit must be N = deployMaturity blocks old; here N = 3). The window is W = 12 here (anchorWindow), so blocks 12 and 14 reach its lower end.',
    reorg: 'After the scenario, blocks 16 and 17 give way to the two blocks given here: roll back to rollbackTo, then apply them. 16\' spends the nullifiers of the TRANSFER of the first 16 again, which only a rollback allows. after is what an indexer that never saw the first 16 and 17 computes.',
  },
  poseidon2: [
    { in: ['1', '2'], out: poseidon2(1n, 2n).toString() },
    { in: ['0', '0'], out: poseidon2(0n, 0n).toString() },
  ],
  domainLeaf: hexFr(DOMAIN.LEAF),
  emptyRootDepth32: hexFr(new NoteTree().root),
  tickerT: { ticker: 'GENE', t: tickerT('GENE').toString() },
  genesis: { ticker: 'SH20', max: '21000000', lim: '1000', pre: '0', price: '0', payMode: 0, mintsFrom: 'activation height' },
  noteLeaf: { ticker: 'SH20', t: tickerT('SH20').toString(), v: '1000', npk: hexFr(envs.mintGenesis.npk), rho: '0', leaf: hexFr(noteLeaf(tickerT('SH20'), 1000n, envs.mintGenesis.npk, 0n)) },
  envelopes: Object.fromEntries(Object.entries(ser).map(([k, v]) => [k, { bytes: v.length, hex: v.toString('hex'), ...(bodyHash(v) ? { bodyHash: bodyHash(v) } : {}) }])),
  claim: {
    note: 'BIP340 signature with 32 zero bytes of auxiliary randomness, by the key whose secret is SHA256("lock2-secret")',
    listTxid: list2Txid, npk: hexFr(envs.claim2.npk), lockKey: lockKey2.toString('hex'),
    message: Indexer.claimMessage(list2Txid, envs.claim2.npk).toString('hex'), sig: envs.claim2.sig.toString('hex'),
  },
  preActivation: {
    note: 'Blocks below A have no root and no digest. digest_{A-1} = SHA256("sh20-v0"), whatever an indexer read before A.',
    digestStart: createHash('sha256').update(DOMAIN.DIGEST).digest('hex'),
  },
  carriers,
  scenario: {
    profile: { activationHeight: PROFILE.activationHeight, deployBurn: String(PROFILE.deployBurn), anchorWindow: PROFILE.anchorWindow, anchorMinDepth: 1, deployMaturity: PROFILE.deployMaturity },
    blocks: blocks.map((b) => ({ height: b.height, txs: b.txs.map(txJson) })),
    rejected,
    verifierCalls,
    after: results.map((r) => ({ height: r.height, root: hexFr(r.root), events: r.events.map((e) => e.type), eventsH: encodeEvents(r.events).toString('hex'), digest: r.digest })),
    final: finalState,
  },
  reorg: {
    rollbackTo: reorgFrom,
    blocks: reorgBlocks.map((b) => ({ height: b.height, txs: b.txs.map(txJson) })),
    verifierCalls: reorgCalls,
    after: reorgResults.map((r) => ({ height: r.height, root: hexFr(r.root), events: r.events.map((e) => e.type), eventsH: encodeEvents(r.events).toString('hex'), digest: r.digest })),
    final: { treeSize: ix.tree.size, pay2: { mints: ix.token('PAY2').mints.toString() }, beta: { mints: ix.token('BETA').mints.toString() } },
  },
};
mkdirSync(new URL('../vectors/', import.meta.url), { recursive: true });
writeFileSync(new URL('../vectors/v0.3.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote vectors/v0.3.json: ${Object.keys(ser).length} envelopes, ${blocks.length} blocks, final digest ${results.at(-1).digest}`);
