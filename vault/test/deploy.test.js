// The vault checks the indexer's mint terms against the DEPLOY transaction itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Indexer } from '../../indexer/src/indexer.js';
import { deployEnv } from '../../indexer/test/helpers.js';
import { serializeEnvelope } from '../src/sh20.js';
import { serializeTx, txid, addressToScript } from '../src/btc.js';
import { commitment, commitValue, signReveal, oneTimeSecret } from '../src/taproot.js';
import { toHex } from '../src/bytes.js';
import { normToken, Esplora } from '../src/api.js';
import { deployMismatches, verifyDeploy } from '../src/deploy.js';

const DEPLOYER = '0014' + '66'.repeat(20);
const ATTACKER = '0014' + 'ee'.repeat(20);

// A real DEPLOY (payMode 2, pays DEPLOYER): the reveal of a commit, in the witness as SPEC-WIRE §5
// requires, indexed by the reference indexer. N = 0: the terms are tested here (maturity in
// deploy-maturity.test.js), so the commit may be the block before.
function honest() {
  const env = deployEnv({ payMode: 2, price: 5000n, payScript: Buffer.from(DEPLOYER, 'hex') });
  const secret = oneTimeSecret();
  const c = commitment(secret, new Uint8Array(serializeEnvelope(env)));
  const back = addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
  // the commit, a transaction of its own: its output is what binds the reveal's witness (vault-6)
  const commitTx = { version: 2, locktime: 0, vin: [{ txid: '66'.repeat(32), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(64)] }], vout: [{ value: commitValue(c, back, 1), script: c.scriptPubKey }] };
  const commitTxid = txid(commitTx);
  const { tx } = signReveal({ secret, c, commitTxid, value: commitValue(c, back, 1), returnScript: back, feeRate: 1 });
  const idx = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, deployMaturity: 0 } });
  const itx = { txid: txid(tx), vin: [{ txid: commitTxid, vout: 0, witness: tx.vin[0].witness.map((w) => Buffer.from(w)), prevHeight: 0 }], vout: tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })) };
  const r = idx.applyBlock({ height: 1, hash: 'h1', txs: [itx] });
  assert.equal(r.events.at(-1)?.type, 'DEPLOY', JSON.stringify(r.rejected));
  return { token: normToken(JSON.parse(JSON.stringify(idx.token('GENE'), (_, v) => (typeof v === 'bigint' ? v.toString() : v)))), hex: toHex(serializeTx(tx)), commitHex: toHex(serializeTx(commitTx)), commitTxid };
}

test('an honest indexer matches the DEPLOY on chain', () => {
  const { token, hex } = honest();
  assert.equal(token.payScript, DEPLOYER);
  assert.deepEqual(deployMismatches(token, hex, 1), []);
});

test('an indexer that lies about payScript is caught, and the mint refused', async () => {
  const { token, hex, commitHex, commitTxid } = honest();
  const lying = { ...token, payScript: ATTACKER };
  assert.match(deployMismatches(lying, hex, 1).join(), /payScript: chain says 0014666/);
  let tip = 6; // the DEPLOY, in block 1, six blocks deep: a mint that pays may go (vault-1)
  globalThis.fetch = async (url) => ({
    ok: true, status: 200,
    text: async () => (url.endsWith('/blocks/tip/height') ? String(tip) : url.includes(commitTxid) ? commitHex : hex),
    json: async () => ({ confirmed: true, block_height: 1 }),
    url,
  });
  await assert.rejects(verifyDeploy(new Esplora('http://esplora'), lying), /refusing to mint GENE.*payScript/);
  await verifyDeploy(new Esplora('http://esplora'), token); // the honest terms pass
  tip = 5; // five deep at Esplora: a mint paid to the deployer waits (vault-1)
  await assert.rejects(verifyDeploy(new Esplora('http://esplora'), token), /not minted yet: the DEPLOY of GENE is 5 blocks deep: the vault pays once it is 6 deep/);
  await verifyDeploy(new Esplora('http://esplora'), { ...token, payMode: 0, price: 0n }).catch((e) => assert.doesNotMatch(e.message, /deep/, 'a free mint does not wait'));
});

test('every mint term is checked', () => {
  const { token, hex } = honest();
  for (const [k, v] of [['price', 1n], ['payMode', 1], ['start', 9], ['end', 99], ['lim', 1n], ['ticker', 'FAKE'], ['max', 1n], ['pre', 1n]]) {
    assert.match(deployMismatches({ ...token, [k]: v }, hex, 1).join(), new RegExp(`^${k}:`), k);
  }
  assert.match(deployMismatches(token, hex, 2).join(), /deploy height/);
  assert.match(deployMismatches({ ...token, t: 7n }, hex, 1).join(), /^t: the ticker gives 1195724357/);
  assert.match(deployMismatches({ ...token, deployTxid: 'ab'.repeat(32) }, hex, 1).join(), /another transaction/);
  assert.match(deployMismatches({ ...token, deployHeight: null }, hex, 1).join(), /no deployHeight/, 'a missing height refuses, never skips');
  assert.match(deployMismatches(token, hex, undefined).join(), /height is unknown/);
});
