// DEPLOY maturity (SPEC-WIRE §5, against ticker sniping): a DEPLOY is always a reveal in the witness,
// of a commit confirmed at least N = 6 blocks earlier. The vault keeps the signed reveal until then,
// and proves again if the proof's anchor would leave the window W meanwhile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer } from '../../indexer/src/indexer.js';
import { chain, deployEnv, tx as helperTx } from '../../indexer/test/helpers.js';
import { buildSweep, revealSchedule, planPlainDeploy, planCarrier, revealFor, pendingRecord, tickerState } from '../src/send.js';
import { keyPathOutput, sigMsg, sigHash } from '../src/taproot.js';
import { addressToScript, txid as txidOf } from '../src/btc.js';
import { schnorrVerify } from '../src/sh20.js';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { NOTE_SCHEME } from '../src/notekeys.js';

const PAYER = { address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' };
const toIx = (t, id, prevHeight) => ({
  txid: id,
  vin: t.vin.map((i, k) => ({ txid: i.txid, vout: i.vout, witness: (i.witness?.length ? i.witness : [new Uint8Array(71), new Uint8Array(33)]).map((w) => Buffer.from(w)), ...(k === 0 && prevHeight !== undefined ? { prevHeight } : {}) })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

test('the reveal schedule: unconfirmed, the countdown, ready at N blocks, expired past the anchor window', () => {
  assert.deepEqual(revealSchedule({ commitHeight: null, tip: 100, N: 6 }), { state: 'unconfirmed', blocks: null });
  assert.deepEqual(revealSchedule({ commitHeight: 100, tip: 100, N: 6 }), { state: 'waiting', blocks: 5 }, 'mined at 100: the reveal may land at 106');
  assert.deepEqual(revealSchedule({ commitHeight: 100, tip: 104, N: 6 }), { state: 'waiting', blocks: 1 });
  assert.deepEqual(revealSchedule({ commitHeight: 100, tip: 105, N: 6 }), { state: 'ready', blocks: 0 });
  assert.equal(revealSchedule({ commitHeight: 100, tip: 300, N: 6 }).state, 'ready', 'no proof: no anchor, never expires');
  // a proof anchored at 10 is valid in blocks up to 10 + W = 110
  assert.equal(revealSchedule({ commitHeight: 100, tip: 105, N: 6, anchorHeight: 10, W: 100 }).state, 'ready');
  assert.equal(revealSchedule({ commitHeight: 100, tip: 109, N: 6, anchorHeight: 10, W: 100 }).state, 'ready', 'lands at 110: still in the window');
  assert.equal(revealSchedule({ commitHeight: 100, tip: 110, N: 6, anchorHeight: 10, W: 100 }).state, 'expired', 'lands at 111: prove again');
  assert.equal(revealSchedule({ commitHeight: 106, tip: 101, N: 6, anchorHeight: 10, W: 100 }).state, 'expired', 'mature only at 112: expired before it is due');
});

test('a DEPLOY without a burn: always commit + reveal; accepted N blocks after its commit, never in an OP_RETURN', () => {
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n } }); // N = 6, the reference profile
  const c = chain(ix);
  c.block();
  const d = { ...deployEnv({ ticker: 'SNIP', start: 30, unlock: 30 }), payScript: new Uint8Array(0) };
  const plan = planPlainDeploy({ d, team: null });
  assert.equal(plan.envelope.length, 56);
  const cp = planCarrier({ envelope: plan.envelope, payer: PAYER, utxos: [{ txid: '11'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: c.next - 1 });
  const commitTxid = txidOf(cp.commit.tx);
  const commitHeight = c.next;
  c.block(toIx(cp.commit.tx, commitTxid));
  const reveal = revealFor(cp, commitTxid);
  for (let i = 0; i < 4; i++) c.block();
  assert.equal(revealSchedule({ commitHeight, tip: c.next - 1, N: 6 }).state, 'waiting');
  assert.deepEqual(c.block(toIx(reveal.tx, reveal.txid, commitHeight)).rejected.map((x) => x.reason), ['DEPLOY commit confirmed less than 6 blocks before']);
  assert.equal(revealSchedule({ commitHeight, tip: c.next - 1, N: 6 }).state, 'ready');
  const r = c.block(toIx(reveal.tx, reveal.txid, commitHeight));
  assert.deepEqual(r.rejected, []);
  assert.equal(r.events[0].type, 'DEPLOY');
  assert.ok(ix.token('SNIP'));
  // the same envelope in an OP_RETURN is refused, whatever its age
  const op = c.block(helperTx({ env: deployEnv({ ticker: 'OPRT', start: 40, unlock: 40 }), carrier: 'opreturn' }));
  assert.deepEqual(op.rejected.map((x) => x.reason), ['DEPLOY must use the witness carrier']);
});

test('proving again: the new commit takes the old commit output back by its key path', () => {
  const d = { ...deployEnv({ ticker: 'AGIN', start: 30, unlock: 30 }), payScript: new Uint8Array(0) };
  const env = planPlainDeploy({ d, team: null }).envelope;
  const old = planCarrier({ envelope: env, payer: PAYER, utxos: [{ txid: '22'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: 10 });
  const rec = { ...pendingRecord('DEPLOY', old, env, []), commitTxid: txidOf(old.commit.tx) };
  const again = planCarrier({ envelope: env, payer: PAYER, utxos: [{ txid: '33'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: 20, sweep: rec });
  const t = again.commit.tx;
  assert.equal(t.vin[0].txid, rec.commitTxid, 'the old commit output is input 0');
  assert.deepEqual(again.commit.inputIndexes, [1], 'the wallet signs only its own input');
  const key = keyPathOutput(old.secret, old.c.leaf);
  assert.equal(Buffer.from(key.script).toString('hex'), Buffer.from(old.c.scriptPubKey).toString('hex'), 'the commit output is the one-time key tweaked with the leaf');
  const prevouts = [{ value: old.value, script: old.c.scriptPubKey }, { value: 50000n, script: again.returnScript }];
  const msg = sigHash(sigMsg(t, 0, prevouts));
  assert.ok(schnorrVerify(Buffer.from(key.key), Buffer.from(msg), Buffer.from(t.vin[0].witness[0])), 'signed by the key path');
});

test('the notes a DEPLOY burn reserved are reserved while it waits, and given back if its ticker is taken', async () => {
  const m = new Map();
  const st = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
  st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: '05'.repeat(32) } }));
  const v = await Vault.open(st);
  const n = await v.addNote({ index: 0, ticker: 'SH20', v: 2000n, txid: null, status: 'in tree', pos: 4 });
  await v.updateNote(n.id, { spent: 'no' });
  const pid = await v.addPending({ kind: 'DEPLOY', inputs: [n.id], status: 'waiting maturity', revealHex: 'ab' });
  assert.equal(v.state.notes[0].status, 'spending', 'reserved while the reveal waits');
  const again = await Vault.open(st);
  assert.equal(again.state.pending.find((p) => p.id === pid).revealHex, 'ab', 'the signed reveal survives a reload (in the vault record)');
  await again.releaseInputs([n.id]);
  assert.equal(again.state.notes[0].status, 'in tree');
});

test('no path of the page broadcasts a DEPLOY reveal before its commit is N blocks deep', async () => {
  const { readFileSync } = await import('node:fs');
  // the page's code, every module of it (app.js and src/ui/)
  const { readdirSync } = await import('node:fs');
  const app = ['app.js', ...readdirSync(new URL('../src/ui/', import.meta.url)).sort().map((f) => `ui/${f}`)]
    .map((f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8')).join('\n');
  const gate = app.slice(app.indexOf('async function broadcastDeployReveal'), app.indexOf('async function processDeploys'));
  assert.match(gate, /await requireProfile\(\);[\s\S]*deploySchedule\(p, /, 'indexers on the vault\'s profile, then N and W of that profile');
  assert.match(gate, /if \(sched\.state !== 'ready'\) throw/);
  // every broadcast of a reveal: the gate itself, or a path a DEPLOY never takes
  const calls = [...app.matchAll(/await esplora\.broadcast\((p\.revealHex|reveal\.hex)\)/g)].map((m) => m.index);
  assert.equal(calls.length, 3);
  const inGate = (i) => i > app.indexOf('async function broadcastDeployReveal') && i < app.indexOf('async function processDeploys');
  const spends = readFileSync(new URL('../src/ui/spends.js', import.meta.url), 'utf8');
  const carry = spends.slice(spends.indexOf('async function carryOnce'));
  assert.ok(carry.indexOf('if (deploy) {') < carry.indexOf('await esplora.broadcast(reveal.hex)'), 'carry returns before the reveal for a DEPLOY');
  assert.match(carry, /if \(deploy\) \{[\s\S]*?await processDeploys\(\);\s*return;\s*\}/);
  for (const i of calls.filter((x) => !inGate(x))) {
    const before = app.slice(Math.max(0, i - 200), i);
    assert.ok(/else $/.test(before.trimEnd() + ' ') || carry.includes(app.slice(i, i + 40)), 'a non-DEPLOY path');
  }
  assert.match(app, /if \(p\.kind === 'DEPLOY'\) await broadcastDeployReveal\(/, 'Broadcast again goes through the gate for a DEPLOY');
});

test('before a reveal the ticker must be known free: no indexer answering holds it back', () => {
  const ok = (list) => ({ status: 'fulfilled', value: list });
  const down = { status: 'rejected', reason: new Error('connection refused') };
  assert.equal(tickerState([down, down], 'SNIP'), 'unknown', 'every /tokens failed: never reveal blind');
  assert.equal(tickerState([], 'SNIP'), 'unknown');
  assert.equal(tickerState([down, ok([{ ticker: 'SH20' }])], 'SNIP'), 'free', 'one answer is enough to say free');
  assert.equal(tickerState([ok([{ ticker: 'SH20' }]), ok([{ ticker: 'SNIP' }])], 'SNIP'), 'taken', 'any indexer listing it: taken');
  assert.equal(tickerState([{ status: 'fulfilled', value: null }], 'SNIP'), 'unknown', 'a malformed answer is no answer');
  const app = readFileSync(new URL('../src/ui/deploy-panel.js', import.meta.url), 'utf8');
  assert.match(app, /if \(ticker === 'unknown'\) \{[\s\S]{0,200}continue;/, 'processDeploys waits on unknown');
});

test('vault-4: a reveal whose mint would start before it can land is held, and its commit taken back alone', () => {
  // the commit confirmed at 11 (N = 6): the reveal lands at 17 at the earliest, so a start of 17 or less passes no chain
  assert.deepEqual(revealSchedule({ commitHeight: 11, tip: 12, N: 6, start: 17 }), { state: 'late', blocks: null });
  assert.deepEqual(revealSchedule({ commitHeight: 11, tip: 12, N: 6, start: 18 }), { state: 'waiting', blocks: 4 });
  assert.deepEqual(revealSchedule({ commitHeight: 11, tip: 40, N: 6, start: 30 }), { state: 'late', blocks: null }, 'a commit that waited, or a page closed long');
  // the sweep: the commit output, by the one-time key's key path, to the wallet's address, at the rate given
  const d = { ...deployEnv({ ticker: 'LATE', start: 30, unlock: 30 }), payScript: new Uint8Array(0) };
  const env = planPlainDeploy({ d, team: null }).envelope;
  const plan = planCarrier({ envelope: env, payer: PAYER, utxos: [{ txid: '22'.repeat(32), vout: 0, value: 50000n }], feeRate: 1, tipHeight: 10 });
  const rec = { ...pendingRecord('DEPLOY', plan, env, []), commitTxid: txidOf(plan.commit.tx) };
  const to = addressToScript(PAYER.address);
  const sw = buildSweep(rec, { toScript: to, feeRate: 1 }); // a plain DEPLOY's commit holds what its reveal costs, a few hundred sats
  assert.deepEqual([sw.tx.vin.length, sw.tx.vin[0].txid, sw.tx.vout.length], [1, rec.commitTxid, 1]);
  assert.equal(sw.tx.vout[0].value + sw.fee, plan.value, 'all of the commit, less the fee');
  assert.deepEqual(Buffer.from(sw.tx.vout[0].script), Buffer.from(to));
  const key = keyPathOutput(plan.secret, plan.c.leaf);
  const msg = sigHash(sigMsg(sw.tx, 0, [{ value: plan.value, script: plan.c.scriptPubKey }]));
  assert.ok(schnorrVerify(Buffer.from(key.key), Buffer.from(msg), Buffer.from(sw.tx.vin[0].witness[0])), 'signed by the key path');
  assert.throws(() => buildSweep(rec, { toScript: to, feeRate: 1000 }), /too little to take back/);
  // the page: held, its notes back, and the sweep offered from the list of spends
  const deploys = readFileSync(new URL('../src/ui/deploy-panel.js', import.meta.url), 'utf8');
  assert.match(deploys, /if \(sched\.state === 'late'\) \{[\s\S]*?await v\.releaseInputs\(p\.inputs \?\? \[\]\);\s*await v\.updatePending\(p\.id, \{ status: 'start passed' \}\);\s*continue;/);
  assert.match(readFileSync(new URL('../src/ui/send-panel.js', import.meta.url), 'utf8'), /if \(p\.status === 'start passed'\) \{[\s\S]*?buildSweep\(p, \{ toScript: addressToScript\(st\.wallet\.address\), feeRate: feeRateOf\(sendForm\.fee\) \}\)/);
});
