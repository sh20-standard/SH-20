// DEPLOY maturity (SPEC-WIRE §5, against ticker sniping): a DEPLOY is always a reveal in the witness,
// of a commit confirmed at least N = 6 blocks earlier. The vault keeps the signed reveal until then,
// and proves again if the proof's anchor would leave the window W meanwhile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { chain, deployEnv, tx as helperTx } from '../../indexer/test/helpers.js';
import { revealSchedule, planPlainDeploy, planCarrier, revealFor, pendingRecord } from '../src/send.js';
import { keyPathOutput, sigMsg, sigHash } from '../src/taproot.js';
import { txid as txidOf } from '../src/btc.js';
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
  const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
  const gate = app.slice(app.indexOf('async function broadcastDeployReveal'), app.indexOf('async function processDeploys'));
  assert.match(gate, /revealSchedule\(/);
  assert.match(gate, /if \(sched\.state !== 'ready'\) throw/);
  // every broadcast of a reveal: the gate itself, or a path a DEPLOY never takes
  const calls = [...app.matchAll(/await esplora\.broadcast\((p\.revealHex|reveal\.hex)\)/g)].map((m) => m.index);
  assert.equal(calls.length, 3);
  const inGate = (i) => i > app.indexOf('async function broadcastDeployReveal') && i < app.indexOf('async function processDeploys');
  const carry = app.slice(app.indexOf('async function carryOnce'), app.indexOf('// ---- send ---'));
  assert.ok(carry.indexOf('if (deploy) {') < carry.indexOf('await esplora.broadcast(reveal.hex)'), 'carry returns before the reveal for a DEPLOY');
  assert.match(carry, /if \(deploy\) \{[\s\S]*?await processDeploys\(\);\s*return;\s*\}/);
  for (const i of calls.filter((x) => !inGate(x))) {
    const before = app.slice(Math.max(0, i - 200), i);
    assert.ok(/else $/.test(before.trimEnd() + ' ') || app.slice(app.indexOf('async function carryOnce'), app.indexOf('// ---- send ---')).includes(app.slice(i, i + 40)), 'a non-DEPLOY path');
  }
  assert.match(app, /if \(p\.kind === 'DEPLOY'\) await broadcastDeployReveal\(/, 'Broadcast again goes through the gate for a DEPLOY');
});
