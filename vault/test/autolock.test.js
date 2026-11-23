// docs/AUDIT.md §8.8: the vault locks itself after a time without use, and what a lock can erase it
// erases: the master secret, the viewing key and the lock keys are zeroed, the state is let go, the
// prover's workers (and with them the last witness) are stopped. dev/e2e.js runs the page's lock
// in Chrome: the clock moved past the time, the vault locks and opens again.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { Vault } from '../src/keys.js';
import { autoLock, LOCK_AFTER_MS, ACTIVITY_EVENTS } from '../src/autolock.js';
import { SPEND_VK_DIGEST } from '../src/sh20.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const zero = (b) => b.every((x) => x === 0);

test('8.8 a locked vault keeps no key it can overwrite, and reads nothing until it is opened again', async () => {
  const storage = memStorage();
  const v = await Vault.fromWords(storage, WORDS, 'pass');
  const address = v.address;
  const lock = await v.lockOutput(0);
  const ivk = v.wallet.ivk;
  await v.reserveNote();
  assert.ok(!zero(lock.secret) && !zero(ivk));
  v.lock();
  assert.ok(v.locked);
  assert.ok(zero(lock.secret), 'the lock key, zeroed');
  assert.ok(zero(ivk), 'the viewing key, zeroed');
  assert.throws(() => v.state, /locked/, 'the state, with its note tweaks and one-time keys, is gone');
  assert.throws(() => v.address, /locked/);
  assert.throws(() => v.words, /locked/);
  await assert.rejects(v.save(), /locked/);
  await assert.rejects(v.lockOutput(0), /locked|null/);
  const again = await Vault.open(storage, 'pass');
  assert.equal(again.address, address, 'opened again from storage, with its passphrase');
  assert.equal(again.state.next, 1);
});

/** An event target with a visibility state, as `document`. */
function fakeDocument() {
  const d = new EventTarget();
  d.visibilityState = 'visible';
  return d;
}

test('8.8 the vault locks itself after ten minutes without use, never during an action nor while a DEPLOY waits', () => {
  assert.equal(LOCK_AFTER_MS, 10 * 60 * 1000);
  const min = 60 * 1000;
  let t = 0;
  let open = true;
  let held = null;
  let locks = 0;
  const target = new EventTarget();
  const doc = fakeDocument();
  const a = autoLock({ unlocked: () => open, held: () => held, lock: () => { locks++; open = false; }, now: () => t, target, doc, every: 1e9 });
  try {
    t = 9 * min;
    assert.equal(a.check(), false);
    for (const e of ACTIVITY_EVENTS) {
      t += min;
      target.dispatchEvent(new Event(e)); // each kind of use counts
    }
    const used = t;
    t = used + 10 * min - 1;
    assert.equal(a.check(), false, 'ten minutes from the last use, not from the unlock');
    assert.equal(a.remaining(), 1);
    t = used + 10 * min;
    assert.equal(a.check(), true);
    assert.equal(locks, 1);
    assert.equal(a.check(), false, 'locked once');

    // an action under way holds it, and the ten minutes count from its end
    open = true;
    t += 1;
    a.touch();
    held = 'an action is under way';
    t += 25 * min;
    assert.equal(a.check(), false);
    held = 'a DEPLOY waits for its reveal';
    t += 60 * min;
    assert.equal(a.check(), false);
    held = null;
    t += 9 * min;
    assert.equal(a.check(), false);
    t += 2 * min;
    assert.equal(a.check(), true);
    assert.equal(locks, 2);

    // a tab left in the background locks when it is shown again
    open = true;
    a.touch();
    doc.visibilityState = 'hidden';
    t += 30 * min;
    doc.dispatchEvent(new Event('visibilitychange'));
    assert.equal(locks, 2, 'nothing while hidden');
    doc.visibilityState = 'visible';
    doc.dispatchEvent(new Event('visibilitychange'));
    assert.equal(locks, 3);
  } finally {
    a.stop();
  }
});

test('8.8 the prover is stopped after a proof and when the vault locks: its workers end, a call waiting fails', async () => {
  const workers = [];
  class FakeWorker {
    constructor(url) {
      this.url = String(url);
      this.terminated = false;
      this.sent = [];
      workers.push(this);
    }
    postMessage(m) {
      this.sent.push(m);
      if (m.init) setTimeout(() => this.onmessage({ data: { ready: { threads: 1, vkDigest: SPEND_VK_DIGEST } } }), 0);
      // a proof is never answered here: it is still running when the prover is stopped
    }
    terminate() {
      this.terminated = true;
    }
  }
  const had = { Worker: globalThis.Worker, fetch: globalThis.fetch };
  globalThis.Worker = FakeWorker;
  globalThis.fetch = async (u) => ({ ok: true, arrayBuffer: async () => new Uint8Array(readFileSync(u)).buffer });
  try {
    const { loadProver, unloadProver } = await import('../src/prover.js');
    const p1 = await loadProver();
    assert.equal(workers.length, 1);
    assert.equal(await loadProver(), p1, 'loaded once while it runs');
    const proving = p1.prove(new Uint8Array(3232));
    unloadProver();
    assert.ok(workers[0].terminated, 'its worker ended, with the module memory that held the witness');
    await assert.rejects(proving, /stopped/);
    await assert.rejects(p1.prove(new Uint8Array(3232)), /stopped/, 'and nothing more goes to it');
    const p2 = await loadProver();
    assert.notEqual(p2, p1);
    assert.equal(workers.length, 2, 'the next proof loads it again');
    unloadProver();
    assert.ok(workers[1].terminated);
  } finally {
    globalThis.Worker = had.Worker;
    globalThis.fetch = had.fetch;
  }
});

test('8.8 the page: the inactivity lock, a lock that stops the prover, the witness zeroed after its proof', () => {
  const app = src('app.js');
  assert.match(app, /autoLock\(\{ unlocked: \(\) => st\.vault !== null, held: lockHeld, lock: \(\) => lockVault\(AUTO_LOCK_NOTE\) \}\)/);
  const panel = src('ui/vault-panel.js');
  const lv = panel.slice(panel.indexOf('export function lockVault('), panel.indexOf('export function lockHeld('));
  assert.match(lv, /st\.vault\?\.lock\(\);\n\s+st\.vault = null;/);
  assert.match(lv, /unloadProver\(\);/);
  const lh = panel.slice(panel.indexOf('export function lockHeld('));
  assert.match(lh.slice(0, 400), /activity\.running > 0/);
  assert.match(lh.slice(0, 400), /'waiting maturity'/);
  assert.match(panel, /onclick: lock \}, 'Lock'\)/);
  assert.match(panel, /const lock = \(\) => lockVault\(\);/, 'the Lock button does the same');
  const spends = src('ui/spends.js');
  assert.match(spends, /envelope = await proveSpend\(prover, built\);\n\s+\} finally \{\n(\s+\/\/.*\n)*\s+built\.witness\.fill\(0\);\n\s+unloadProver\(\);/);
  const ctx = src('ui/context.js');
  assert.match(ctx, /await during\(\(\) => fn\(\.\.\.args\)\);/, 'every button\'s action holds the lock off');
  assert.match(src('ui/notes-panel.js'), /export async function syncNotes\(opts\) \{\n\s+return during\(/, 'and every sync');
  // every place that locked the vault by hand now goes through lockVault
  const ui = [app, ...readdirSync(new URL('../src/ui/', import.meta.url)).filter((f) => f.endsWith('.js')).map((f) => src(`ui/${f}`))].join('\n');
  assert.equal([...ui.matchAll(/st\.vault = null;/g)].length, 1);
});
