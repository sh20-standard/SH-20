import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { deriveNpk, NPK_SCHEME } from '../src/npk.js';
import { FR } from '../src/sh20.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};

test('deriveNpk is deterministic, per index and per seed, in the field', () => {
  const s = new Uint8Array(32).fill(1);
  const a = deriveNpk(s, 0);
  assert.equal(a.scheme, NPK_SCHEME);
  assert.equal(deriveNpk(s, 0).npk, a.npk);
  assert.notEqual(deriveNpk(s, 1).npk, a.npk);
  assert.notEqual(deriveNpk(new Uint8Array(32).fill(2), 0).npk, a.npk);
  for (const x of [a.npk, a.ask, a.nk]) assert.ok(x > 0n && x < FR);
});

test('vault in clear: create, reserve, reopen, never reuse an index', async () => {
  const st = memStorage();
  const v = await Vault.create(st);
  assert.ok(!v.encrypted);
  const o0 = await v.reserveNote();
  const o1 = await v.reserveNote();
  assert.equal(o0.index, 0);
  assert.equal(o1.index, 1);
  assert.notEqual(o0.npk, o1.npk);
  assert.notEqual(o0.rho, o1.rho);
  const again = await Vault.open(st);
  assert.equal(again.state.next, 2);
  assert.equal(again.opening(0).npk, o0.npk);
  await assert.rejects(Vault.create(st), /already exists/);
});

test('vault with passphrase: seed not stored in clear, wrong passphrase fails, backup restores', async () => {
  const st = memStorage();
  const v = await Vault.create(st, 'correct horse');
  assert.ok(v.encrypted);
  const o = await v.reserveNote();
  await v.addNote({ ...o, tokenNum: 1, ticker: 'GENE', v: 1000n, txid: 'ab'.repeat(32), status: 'broadcast' });
  const rec = st.getItem(STORAGE_KEY);
  assert.ok(!rec.includes('GENE') && !rec.includes('seed'));
  await assert.rejects(Vault.open(st, 'wrong'), /wrong passphrase/);
  await assert.rejects(Vault.open(st), /needs its passphrase/);
  const st2 = memStorage();
  const r = await Vault.restore(st2, v.exportBackup(), 'correct horse');
  assert.equal(r.opening(0).npk, o.npk);
  assert.equal(r.state.notes[0].ticker, 'GENE');
  assert.ok(r.npkWindow(5).has(r.state.notes[0].npk));
});
