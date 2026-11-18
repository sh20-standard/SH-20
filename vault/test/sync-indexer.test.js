// Private sync against the real indexer API (indexer/src/api.js): a MINT made
// by the vault, then a spend revealing its nullifier. Skipped until the indexer
// serves /nullifiers (PR #5); runs by itself once it is merged.
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

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
};
const toIndexerTx = (t) => ({
  txid: txid(t),
  vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: [Buffer.alloc(64)] })),
  vout: t.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

test('sync finds the vault note, its path and its spend through the real API', async (t) => {
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n }, verifier: mockVerifier() });
  const c = chain(idx);
  c.block(helperTx({ env: deployEnv({ start: 2, unlock: 2 }) }));

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
  const note = await vault.addNote({ ...o, ticker: 'GENE', v: 1000n, txid: txid(m.tx), status: 'in tree' });
  const leaf = BigInt('0x' + note.leaf);
  const nf = vault.nullifier(o.index, leaf, pos);

  const server = await listen(idx, { port: 0 });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    if ((await fetch(`${base}/nullifiers?from=0`)).status === 404) {
      t.skip('the indexer has no /nullifiers yet (PR #5)');
      return;
    }
    const api = new IndexerApi(base);
    const s = new Sync(memoryCache(), base);
    await s.sync(api);
    assert.equal(s.tree.root, idx.tree.root, 'local tree = indexer tree');
    assert.deepEqual(s.witness(pos, leaf).siblings, idx.tree.path(pos), 'local path = indexer path');
    assert.equal(s.spentAt(frHex(nf)), null, 'not spent yet');

    // a spend whose first nullifier is the vault note's (accepted by the mock verifier)
    const sp = spend(2);
    sp.nf[0] = nf;
    const r3 = c.block(helperTx({ env: { type: 'TRANSFER', spend: sp }, carrier: 'witness' }));
    assert.equal(r3.events[0]?.type, 'TRANSFER', JSON.stringify(r3.rejected));
    await s.sync(api);
    assert.equal(s.spentAt(frHex(nf)), r3.height, 'spent, found in the bulk list');
    assert.equal(s.tree.root, idx.tree.root, 'the three outputs are in the local tree too');
  } finally {
    server.close();
  }
});
