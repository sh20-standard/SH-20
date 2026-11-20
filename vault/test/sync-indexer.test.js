// Private sync against the real indexer API (indexer/src/api.js): a MINT made
// by the vault, then a spend revealing its nullifier and sealing an output to the
// vault's sh20 address (circuit/js seal), which the vault finds by scanning.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { deployEnv, tx as helperTx, chain, mockVerifier, spend } from '../../indexer/test/helpers.js';
import { buildMint } from '../src/mint.js';
import { normToken, IndexerApi } from '../src/api.js';
import { Vault } from '../src/keys.js';
import { Sync } from '../src/sync.js';
import { memoryCache } from '../src/cache.js';
import { frHex } from '../src/fr.js';
import { txid } from '../src/btc.js';
import { seal, decodeAddress } from '../src/sh20.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};
const toIndexerTx = (t) => ({
  txid: txid(t),
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: [Buffer.alloc(64)] })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

test('sync finds the vault note, its path and its spend through the real API', async () => {
  // N = 0 here: the DEPLOY is only setup (test/deploy-maturity.test.js tests N = 6); its commit is one block old
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 }, verifier: mockVerifier() });
  const c = chain(idx);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }), prevHeight: c.next - 1 }));

  const vault = await Vault.create(memStorage());
  const o = await vault.reserveNote();
  const m = buildMint({
    token: normToken(JSON.parse(JSON.stringify(idx.token('GENE'), (_, v) => (typeof v === 'bigint' ? v.toString() : v)))),
    opening: o, payer: { address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' },
    utxos: [{ txid: '11'.repeat(32), vout: 0, value: 100000n }], feeRate: 1, tipHeight: c.next - 1,
  });
  const r2 = c.block(toIndexerTx(m.tx));
  assert.equal(r2.events[0]?.type, 'MINT');
  const pos = r2.events[0].pos;
  const note = await vault.addNote({ index: o.index, ticker: 'GENE', v: 1000n, txid: txid(m.tx), status: 'in tree', pos });
  const leaf = BigInt('0x' + note.leaf);
  const nf = await vault.nullifier(note);

  const server = await listen(idx, { port: 0 });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const api = new IndexerApi(base);
    const s = new Sync(memoryCache(), base);
    await s.sync(api);
    assert.equal(s.tree.root, idx.tree.root, 'local tree = indexer tree');
    assert.deepEqual(s.witness(pos, leaf).siblings, idx.tree.path(pos), 'local path = indexer path');
    assert.equal(s.spentAt(frHex(nf)), null, 'not spent yet');

    // a spend whose first nullifier is the vault note's (accepted by the mock verifier)
    const sp = spend(2);
    sp.nf[0] = nf;
    // output 1 is sealed to the vault: 400 GENE (the 32-byte X25519 pk_eph of wire v0.3)
    const sealed = await seal(await decodeAddress('tsh20', vault.address), 'GENE', 400n, new Uint8Array(32).fill(5));
    sp.outs[1] = { leaf: sealed.leaf, pkEph: sealed.pkEph, ct: sealed.ct };
    const r3 = c.block(helperTx({ env: { type: 'TRANSFER', spend: sp }, carrier: 'witness' }));
    assert.equal(r3.events[0]?.type, 'TRANSFER', JSON.stringify(r3.rejected));
    const r = await s.sync(api);
    assert.equal(s.spentAt(frHex(nf)), r3.height, 'spent, found in the bulk list');
    assert.equal(s.tree.root, idx.tree.root, 'the three outputs are in the local tree too');
    const outs = r.notes.filter((n) => n.kind === 'OUT');
    assert.equal(outs.length, 3);
    const got = [];
    for (const n of outs) got.push(await vault.receive(n));
    assert.deepEqual(got.map((g) => g && [g.ticker, g.v, g.id]), [null, ['GENE', '400', `out:${outs[1].pos}`], null], 'only the output sealed to the vault opens');
    const received = got[1];
    assert.equal(received.leaf, frHex(sealed.leaf));
    assert.deepEqual(s.witness(received.pos, sealed.leaf).siblings, idx.tree.path(received.pos), 'its path, computed here');
    assert.equal(s.spentAt(frHex(await vault.nullifier(received))), null, 'and its nullifier, computed here, is unspent');
  } finally {
    server.close();
  }
});
