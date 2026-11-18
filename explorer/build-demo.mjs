#!/usr/bin/env node
// Builds the explorer's demo data and inlines it into index.html.
//
// The data is real indexer output: a scripted test chain is replayed through the
// reference indexer (../indexer/src) and every API route the explorer reads is
// captured from the real HTTP API. Only the proofs are fake (a demo verifier
// accepts any 480-byte proof), so the page is clearly marked as demo data.
// Deterministic: two runs give the same index.html.
//
// Run: node explorer/build-demo.mjs

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { FR } from '../indexer/src/constants.js';
import { serializeEnvelope } from '../indexer/src/codec.js';
import { Indexer } from '../indexer/src/indexer.js';
import { listen } from '../indexer/src/api.js';
import { publicKey, sign } from '../indexer/src/schnorr.js';

const A = 270000; // activation height of the demo chain
const h = (s) => createHash('sha256').update(s).digest();
const fr = (seed) => BigInt('0x' + h(seed).toString('hex')) % FR || 1n;
const bytes = (seed, n) => Buffer.concat([h(seed), h(seed + '/2'), h(seed + '/3'), h(seed + '/4'), h(seed + '/5'), h(seed + '/6'), h(seed + '/7'), h(seed + '/8'), h(seed + '/9'), h(seed + '/10'), h(seed + '/11'), h(seed + '/12'), h(seed + '/13'), h(seed + '/14'), h(seed + '/15')]).subarray(0, n);
const txid = (seed) => h('demo-txid/' + seed).toString('hex');
const op = (seed) => ({ npk: fr(seed + '/npk') });

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
const p2wpkh = (seed) => Buffer.concat([Buffer.from([0x00, 0x14]), bytes('pkh/' + seed, 20)]);
const p2tr = (key) => Buffer.concat([Buffer.from([0x51, 0x20]), key]);
const fee = (seed) => ({ txid: txid('funding/' + seed), vout: 0, witness: [] });

const spend = (seed, anchorHeight) => ({
  anchorHeight,
  nf: [fr(seed + '/nf0'), fr(seed + '/nf1')],
  outs: [0, 1, 2].map((j) => ({
    leaf: fr(`${seed}/leaf${j}`),
    pkEph: bytes(`${seed}/epk${j}`, 32),
    ct: bytes(`${seed}/ct${j}`, 28),
  })),
  proof: bytes(`${seed}/proof`, 480),
});

// ---- the scripted chain ---------------------------------------------------

const novaPay = p2wpkh('nova-deployer');
const seller = h('demo-lock-secret');
const sellerKey = publicKey(seller);

const blocks = new Map(); // height -> txs
const at = (height, ...txs) => blocks.set(height, [...(blocks.get(height) || []), ...txs]);

const deploy = (seed, env) => ({ txid: txid(seed), env, carrier: env.spend ? 'witness' : 'opreturn' });
const mintTx = (seed, ticker, payOut) => ({ txid: txid(seed), env: { type: 'MINT', ticker, ...op(seed) }, ...payOut });
const spendTx = (seed, env) => ({ txid: txid(seed), env, carrier: 'witness' });

// SH20, the genesis token, exists from block A (activation profile): free mints, network fees only.
for (let i = 0; i < 6; i++) at(A + 1, mintTx(`sh20-mint-${i}`, 'SH20', { burnSats: 0n }));
for (let i = 6; i < 11; i++) at(A + 3, mintTx(`sh20-mint-${i}`, 'SH20', { burnSats: 0n }));
for (let i = 11; i < 14; i++) at(A + 4, mintTx(`sh20-mint-${i}`, 'SH20', { burnSats: 0n }));
at(A + 6, spendTx('transfer-1', { type: 'TRANSFER', spend: spend('transfer-1', A + 4) }), spendTx('transfer-2', { type: 'TRANSFER', spend: spend('transfer-2', A + 5) }));
at(A + 7, deploy('deploy-nova', {
  type: 'DEPLOY', ticker: 'NOVA', max: 10000000n, lim: 500n, pre: 500000n, start: A + 10, end: 0, unlock: A + 4320,
  price: 2500n, payMode: 2, payScript: novaPay, team: op('nova-team'), spend: spend('deploy-nova', A + 6),
}));
for (let i = 0; i < 8; i++) at(A + 10, mintTx(`nova-mint-${i}`, 'NOVA', { vout: [{ value: 2500n, script: novaPay }] }));
at(A + 10, mintTx('nova-mint-unpaid', 'NOVA', { vout: [{ value: 1000n, script: novaPay }] }));
at(A + 10, mintTx('kiln-mint-too-early', 'KILN', { burnSats: 0n }));
const listGene = spendTx('list-sh20', {
  type: 'LIST', ticker: 'SH20', amount: 2000n, price: 60000n, lockVout: 0, payScript: p2wpkh('sh20-seller'), spend: spend('list-sh20', A + 10),
});
listGene.lock = [{ value: 330n, script: p2tr(sellerKey) }];
at(A + 11, spendTx('transfer-3', { type: 'TRANSFER', spend: spend('transfer-3', A + 9) }), spendTx('transfer-4', { type: 'TRANSFER', spend: spend('transfer-4', A + 10) }), listGene);
at(A + 12, { txid: txid('take-sh20'), env: { type: 'TAKE', ...op('sh20-buyer') }, spendsLock: listGene.txid, vout: [{ value: 60000n, script: p2wpkh('sh20-seller') }] });
at(A + 13, deploy('deploy-kiln', {
  type: 'DEPLOY', ticker: 'KILN', max: 1000000n, lim: 100n, pre: 0n, start: A + 16, end: A + 2016, unlock: A + 16,
  price: 0n, payMode: 0, payScript: Buffer.alloc(0), team: null, spend: spend('deploy-kiln', A + 12),
}));
for (let i = 0; i < 4; i++) at(A + 16, mintTx(`kiln-mint-${i}`, 'KILN', { burnSats: 0n }));
at(A + 16, spendTx('burn-sh20', { type: 'BURN', ticker: 'SH20', vPub: 300n, spend: spend('burn-sh20', A + 15) }));
const listNova = spendTx('list-nova', {
  type: 'LIST', ticker: 'NOVA', amount: 1000n, price: 25000n, lockVout: 0, payScript: p2wpkh('nova-seller'), spend: spend('list-nova', A + 16),
});
listNova.lock = [{ value: 330n, script: p2tr(sellerKey) }];
at(A + 17, spendTx('transfer-5', { type: 'TRANSFER', spend: spend('transfer-5', A + 15) }), spendTx('transfer-6', { type: 'TRANSFER', spend: spend('transfer-6', A + 16) }), listNova);
at(A + 18, { txid: txid('nova-lock-spent'), spendsLock: listNova.txid, vout: [{ value: 200n, script: p2wpkh('seller-change') }] });
const back = op('nova-claim');
at(A + 19, { txid: txid('claim-nova'), env: { type: 'CLAIM', listTxid: listNova.txid, ...back, sig: sign(seller, Indexer.claimMessage(listNova.txid, back.npk)) } });
at(A + 20, spendTx('transfer-7', { type: 'TRANSFER', spend: spend('transfer-7', A + 19) }));

// ---- turn the script into Bitcoin-shaped blocks -----------------------------

function toTx(t) {
  const vin = [];
  const vout = [];
  if (t.spendsLock) vin.push({ txid: t.spendsLock, vout: 0, witness: [Buffer.alloc(64, 3)] });
  if (t.env) {
    const env = serializeEnvelope(t.env);
    if (t.carrier === 'witness') vin.unshift({ txid: txid('reveal/' + t.txid), vout: 0, witness: witness(env) });
    else vout.push({ value: t.burnSats ?? 0n, script: opReturn(env) });
  }
  vin.push(fee(t.txid));
  vout.push(...(t.lock || []), ...(t.vout || []));
  return { txid: t.txid, vin, vout };
}

const TIP = A + 21;
const chain = [];
for (let height = A; height <= TIP; height++) {
  chain.push({ height, hash: h('demo-block/' + height).toString('hex'), txs: (blocks.get(height) || []).map(toTx) });
}

const demoVerifier = { name: 'demo (accepts any 480-byte proof)', verifySpend: (a) => a.proof.length === 480 };
const ix = new Indexer({ profile: { network: 'demo', activationHeight: A, deployBurn: 1000n }, verifier: demoVerifier });
for (const b of chain) ix.applyBlock(b);

// ---- capture the API ---------------------------------------------------------

const server = await listen(ix, { port: 0, network: 'demo' });
const base = `http://127.0.0.1:${server.address().port}`;
const routes = {};
const get = async (p) => {
  const r = await fetch(base + p);
  if (!r.ok) throw new Error(`${p}: ${r.status}`);
  routes[p] = await r.json();
  return routes[p];
};
await get('/status');
await get('/tokens');
await get('/listings');
const recent = await get('/blocks?limit=200');
for (const b of recent) for (const e of [...b.events, ...b.rejected]) if (e.txid) await get(`/tx/${e.txid}`);
await get(`/digest/${ix.height}`);
const spent = await get('/nullifiers');
for (const x of spent.nullifiers) await get(`/nullifier/${x.nullifier}`);
server.close();

const data = JSON.stringify({ generated: 'build-demo.mjs', activationHeight: A, routes });

// ---- inline into index.html, with a CSP hash for the page script ------------------

const file = new URL('./index.html', import.meta.url);
let html = readFileSync(file, 'utf8');
const demoRe = /(<script id="demo-data" type="application\/json">)[\s\S]*?(<\/script>)/;
if (!demoRe.test(html)) throw new Error('index.html has no demo-data block');
html = html.replace(demoRe, (_, a, b) => a + data.replace(/</g, '\\u003c') + b);
const app = html.match(/<script id="app">([\s\S]*?)<\/script>/);
if (!app) throw new Error('index.html has no app script');
const sha = createHash('sha256').update(app[1], 'utf8').digest('base64');
html = html.replace(/script-src 'sha256-[^']*'/, `script-src 'sha256-${sha}'`);
writeFileSync(file, html);
console.log(`demo: ${chain.length} blocks, ${recent.length} with activity, ${Object.keys(routes).length} routes, ${data.length} bytes; app sha256-${sha}`);
