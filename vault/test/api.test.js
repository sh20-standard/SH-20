// The client against the documented API shape (docs/API.md, indexer-api branch).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IndexerApi, frOf } from '../src/api.js';

function fakeFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    const u = new URL(url);
    const body = routes(u);
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => body };
  };
  return calls;
}

test('tokens: decimal strings become bigints', async () => {
  fakeFetch((u) => (u.pathname === '/tokens'
    ? [{ ticker: 'GENE', t: '1195724357', max: '21000000', lim: '1000', pre: '0', start: 2, end: 0, unlock: 2, price: '1000', payMode: 1, payScript: '', mints: '5', burned: '0' }]
    : undefined));
  const [t] = await new IndexerApi('http://x/').tokens();
  assert.equal(t.max, 21000000n);
  assert.equal(t.mints, 5n);
  assert.equal(t.payMode, 1);
  assert.equal(t.t, 1195724357n);
});

test('notes: follows pages until total, reads kind / t / leaf, skips nothing', async () => {
  const all = Array.from({ length: 7 }, (_, i) => (i % 2
    ? { pos: i, height: 3, txid: 'aa'.repeat(32), leaf: i.toString(16).padStart(64, '0'), kind: 'OUT', j: 0, pkEph: '02' + '11'.repeat(32), ct: '00'.repeat(28) }
    : { pos: i, height: 2, txid: 'bb'.repeat(32), leaf: i.toString(16).padStart(64, '0'), kind: 'MINT', ticker: 'GENE', v: '1000', npk: 'ff'.repeat(31) + '00', rho: '01'.repeat(32) }));
  const calls = fakeFetch((u) => {
    if (u.pathname !== '/notes') return undefined;
    const from = Number(u.searchParams.get('from'));
    return { from, total: all.length, notes: all.slice(from, from + 3) }; // server caps pages at 3 here
  });
  const notes = await new IndexerApi('http://x').notes();
  assert.equal(notes.length, 7);
  assert.equal(calls.length, 3);
  assert.equal(notes[0].kind, 'MINT');
  assert.equal(notes[0].ticker, 'GENE');
  assert.equal(notes[0].v, 1000n);
  assert.equal(notes[1].npk, null, 'OUT notes have no public opening');
  assert.equal(notes[6].leaf, 6n);
});

test('field elements: hex (with or without 0x) or decimal, nothing else', () => {
  assert.equal(frOf('00'.repeat(31) + '0a'), 10n);
  assert.equal(frOf('0x' + '00'.repeat(31) + '0a'), 10n);
  assert.equal(frOf('12345'), 12345n);
  assert.equal(frOf('nope'), null);
  assert.equal(frOf(undefined), null);
});

test('a server cannot suggest a ruinous fee rate', async () => {
  const { Esplora, MAX_FEE_RATE } = await import('../src/api.js');
  for (const [body, want] of [[{ 2: 1e6 }, MAX_FEE_RATE], [{ 2: 'x' }, 1], [{ 2: -5 }, 1], [{ 2: 3.21 }, 3.3]]) {
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => body });
    assert.equal(await new Esplora('http://x').feeRate(), want);
  }
});
