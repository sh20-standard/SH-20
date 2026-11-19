import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Vault, STORAGE_KEY, noteOpening, RESTORE_GAP } from '../src/keys.js';
import { NOTE_SCHEME, wallet, publicNote, nullifierOf } from '../src/notekeys.js';
import { noteLeaf, tickerT, spendKeys, nullifier } from '../src/sh20.js';
import { frHex, frFromHex } from '../src/fr.js';
import { toHex, fromHex } from '../src/bytes.js';

const vectors = JSON.parse(readFileSync(new URL('../../circuit/js/vectors.json', import.meta.url), 'utf8'));

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};

// The vault's seed is SPEC-NOTES' master secret m: from the vectors' m, the vault must give the
// vectors' keys, signet address and public notes (circuit/js/vectors.json, written by the Rust model).
test('the vault derives the vector wallets: keys, signet address, public notes (rho = 0)', async () => {
  for (const w of vectors.wallets) {
    const k = await wallet(fromHex(w.m));
    assert.equal(k.ask.toString(), w.ask);
    assert.equal(k.nsk.toString(), w.nsk);
    assert.equal(toHex(k.ivk), w.ivk);
    assert.equal(toHex(k.address.ivkPub), w.IVK);
    assert.equal(k.addressString, w.addressTest, 'tsh20 on signet');
  }
  const seeds = Object.fromEntries(vectors.wallets.map((w) => [w.name, fromHex(w.m)]));
  assert.ok(vectors.publicNotes.length >= 4);
  for (const p of vectors.publicNotes) {
    const o = await noteOpening(seeds[p.wallet], p.i);
    assert.equal(o.npk.toString(), p.npk, `${p.wallet} #${p.i}`);
    assert.equal(o.rho, 0n);
    assert.equal(o.secrets.tauA.toString(), p.tauA);
    assert.equal(o.scheme, NOTE_SCHEME);
    assert.equal(noteLeaf(tickerT('GENE'), 1000n, o.npk, 0n).toString(), p.leafOf1000Gene);
  }
});

test('the vault opens the sealed outputs sent to it, refuses the others, and computes their nullifiers', async () => {
  const byName = Object.fromEntries(vectors.wallets.map((w) => [w.name, w]));
  for (const s of vectors.sealed) {
    for (const w of vectors.wallets) {
      const st = memStorage();
      st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: w.m } }));
      const v = await Vault.open(st);
      const out = { pos: 9, leaf: BigInt(s.leaf), pkEph: fromHex(s.pkEph), ct: fromHex(s.ct), txid: 'cd'.repeat(32) };
      const got = await v.receive(out);
      if (w.name !== s.to || s.v === '0') {
        assert.equal(got, null, `${s.to}'s output is not ${w.name}'s, or it is an unused one`);
        continue;
      }
      assert.equal(got.ticker, s.ticker);
      assert.equal(got.v, s.v);
      assert.equal(got.npk, frHex(BigInt(s.npk)));
      assert.equal(got.id, 'out:9');
      assert.equal(await v.receive(out), null, 'one note per position');
      assert.equal(await v.receive({ ...out, ct: Uint8Array.from(out.ct, (x, i) => (i ? x : x ^ 1)) }), null);
      assert.ok((await v.nullifier(got)) > 0n);
      assert.ok(byName[s.to]);
    }
  }
});

test('nullifiers of the vector spend: the vault gives the circuit\'s', async () => {
  // the spend's inputs are public notes of the payer; nf = Poseidon(nsk + τn, leaf, index)
  const sp = vectors.spend;
  const w = vectors.wallets.find((x) => x.name === sp.inputs[0].wallet);
  const st = memStorage();
  st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [], seed: w.m } }));
  const v = await Vault.open(st);
  for (const [k, inp] of sp.inputs.entries()) {
    assert.equal(inp.rho, '0');
    const note = { kind: 'public', index: inp.publicNote, pos: Number(inp.index), leaf: frHex(noteLeaf(tickerT(sp.ticker), BigInt(inp.v), (await v.opening(inp.publicNote)).npk, 0n)) };
    assert.equal((await v.nullifier(note)).toString(), sp.nf[k], `input ${k}`);
  }
  assert.equal(RESTORE_GAP, 50);
  // the vault's shortcut (nk = nsk + τn mod l) is circuit/js spendKeys' nk
  const k = await wallet(fromHex(w.m));
  for (let i = 0; i < 3; i++) {
    const { secrets } = await publicNote(k, i);
    assert.equal(nullifierOf(k, secrets, 77n, 5), nullifier(spendKeys(k, secrets).nk, 77n, 5));
  }
});

test('a vault of the provisional v0.2 keys keeps its notes aside and starts again at 0', async () => {
  const st = memStorage();
  st.setItem(STORAGE_KEY, JSON.stringify({ v: 0, plain: { v: 0, network: 'signet', next: 3, notes: [{ index: 2, scheme: 'provisional-0', ticker: 'GENE' }], seed: '07'.repeat(32) } }));
  const v = await Vault.open(st);
  assert.equal(v.state.scheme, NOTE_SCHEME);
  assert.equal(v.state.next, 0);
  assert.deepEqual(v.state.notes, []);
  assert.equal(v.state.obsolete.length, 1);
  assert.ok(frFromHex(frHex((await v.opening(0)).npk)) > 0n);
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
  assert.equal(o0.rho, 0n);
  assert.match(v.address, /^tsh201[02-9ac-hj-np-z]{162}$/);
  const again = await Vault.open(st);
  assert.equal(again.state.next, 2);
  assert.equal((await again.opening(0)).npk, o0.npk);
  await assert.rejects(Vault.create(st), /already exists/);
});

test('vault with passphrase: seed not stored in clear, wrong passphrase fails, backup restores', async () => {
  const st = memStorage();
  const v = await Vault.create(st, 'correct horse');
  assert.ok(v.encrypted);
  const o = await v.reserveNote();
  const n = await v.addNote({ index: o.index, ticker: 'GENE', v: 1000n, txid: 'ab'.repeat(32), status: 'broadcast' });
  assert.equal(n.id, 'pub:0');
  assert.equal(n.leaf, frHex(noteLeaf(tickerT('GENE'), 1000n, o.npk, 0n)));
  const rec = st.getItem(STORAGE_KEY);
  assert.ok(!rec.includes('GENE') && !rec.includes('seed'));
  await assert.rejects(Vault.open(st, 'wrong'), /wrong passphrase/);
  await assert.rejects(Vault.open(st), /needs its passphrase/);
  const st2 = memStorage();
  const r = await Vault.restore(st2, v.exportBackup(), 'correct horse');
  assert.equal((await r.opening(0)).npk, o.npk);
  assert.equal(r.state.notes[0].ticker, 'GENE');
  assert.ok((await r.npkWindow({ gap: 5, yieldEvery: async () => {} })).has(r.state.notes[0].npk));
  assert.equal(r.state.npks.length, 6, 'derived keys are kept in the state');
  assert.ok(!st2.getItem(STORAGE_KEY).includes(r.state.npks[0]), 'and stored encrypted');
});
