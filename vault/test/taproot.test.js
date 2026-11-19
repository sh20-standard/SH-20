// The witness carrier: taproot tweak, leaf hash, control block and signature message against the
// BIP341 vectors, then a reveal of the real TRANSFER of plonk-scenario.json that the indexer's own
// carrier reads back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { leafHash, tweakKey, sigMsg, sigHash, commitment, commitValue, signReveal, revealVsize, oneTimeSecret, keyPathOutput, signKeyPath } from '../src/taproot.js';
import { parseTx, vsize, addressToScript, dustLimit } from '../src/btc.js';
import { fromHex, toHex } from '../src/bytes.js';
import { extractEnvelope, schnorrVerify } from '../src/sh20.js';

const json = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const v = json('./fixtures/bip341.json');
const scenario = json('../../indexer/test/fixtures/plonk-scenario.json');

test('BIP341: tweaked keys, leaf hashes and control blocks of the one-leaf trees', () => {
  let leaves = 0;
  for (const { given, intermediary, expected } of v.scriptPubKey) {
    const internal = fromHex(given.internalPubkey);
    const tree = given.scriptTree;
    if (tree && !Array.isArray(tree)) {
      assert.equal(tree.leafVersion, 0xc0);
      const leaf = leafHash(fromHex(tree.script));
      assert.equal(toHex(leaf), intermediary.leafHashes[0]);
      const q = tweakKey(internal, leaf);
      assert.equal(toHex(q.key), intermediary.tweakedPubkey);
      assert.equal(`${(0xc0 | q.parity).toString(16)}${given.internalPubkey}`, expected.scriptPathControlBlocks[0]);
      leaves++;
    } else if (!tree) {
      assert.equal(toHex(tweakKey(internal, null).key), intermediary.tweakedPubkey);
    }
  }
  assert.ok(leaves >= 2);
});

test('BIP341: signature message and hash for SIGHASH_DEFAULT and SINGLE | ANYONECANPAY', () => {
  for (const k of v.keyPathSpending) {
    const tx = parseTx(fromHex(k.given.rawUnsignedTx));
    const prevouts = k.given.utxosSpent.map((u) => ({ value: BigInt(u.amountSats), script: fromHex(u.scriptPubKey) }));
    const cases = k.inputSpending.filter((i) => i.given.hashType === 0 || i.given.hashType === 0x83);
    assert.deepEqual(cases.map((i) => i.given.hashType).sort(), [0, 0x83]);
    for (const i of cases) {
      const msg = sigMsg(tx, i.given.txinIndex, prevouts, null, i.given.hashType);
      assert.equal(toHex(msg), i.intermediary.sigMsg, `hash type ${i.given.hashType}`);
      assert.equal(toHex(sigHash(msg)), i.intermediary.sigHash);
    }
  }
});

test('BIP86 key-path outputs: the tweaked secret of the vectors, and a signature that verifies', () => {
  let n = 0;
  for (const k of v.keyPathSpending) {
    for (const i of k.inputSpending.filter((x) => x.given.merkleRoot === null)) {
      const o = keyPathOutput(fromHex(i.given.internalPrivkey));
      assert.equal(toHex(o.internal), i.intermediary.internalPubkey);
      assert.equal(toHex(o.secret), i.intermediary.tweakedPrivkey);
      const utxo = k.given.utxosSpent[i.given.txinIndex];
      assert.equal(toHex(o.script), utxo.scriptPubKey);
      const tx = parseTx(fromHex(k.given.rawUnsignedTx));
      const prevouts = k.given.utxosSpent.map((u) => ({ value: BigInt(u.amountSats), script: fromHex(u.scriptPubKey) }));
      for (const type of [0, 0x83]) {
        const msg = sigMsg(tx, i.given.txinIndex, prevouts, null, type);
        const sig = signKeyPath(o.secret, msg, type);
        assert.equal(sig.length, type ? 65 : 64);
        assert.ok(schnorrVerify(Buffer.from(o.key), Buffer.from(sigHash(msg)), Buffer.from(sig.subarray(0, 64))), `type ${type}`);
      }
      n++;
    }
  }
  assert.ok(n >= 1);
});

test('a reveal carries the real TRANSFER where the indexer looks for it, signed by the one-time key', () => {
  const envelope = fromHex(scenario.transfer);
  const secret = oneTimeSecret();
  const c = commitment(secret, envelope);
  const back = addressToScript('tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c');
  const value = commitValue(c, back, 2);
  const r = signReveal({ secret, c, commitTxid: 'ab'.repeat(32), value, returnScript: back, feeRate: 2 });
  assert.equal(r.vsize, vsize(r.tx), 'the size used for the fee is the real one');
  assert.equal(r.tx.vout[0].value, dustLimit(back), 'the dust comes back to the user');
  assert.equal(r.vsize, revealVsize(c, back));
  console.log(`  TRANSFER reveal: ${r.vsize} vB with a P2TR return output`);
  const found = extractEnvelope({
    vin: r.tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
    vout: r.tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
  });
  assert.equal(found.carrier, 'witness');
  assert.equal(Buffer.from(found.bytes).toString('hex'), scenario.transfer);
  const msg = sigHash(sigMsg(r.tx, 0, [{ value, script: c.scriptPubKey }], c.leaf));
  assert.ok(schnorrVerify(Buffer.from(c.e), Buffer.from(msg), Buffer.from(r.tx.vin[0].witness[0])));
  assert.throws(() => signReveal({ secret, c, commitTxid: 'ab'.repeat(32), value: value - 1n, returnScript: back, feeRate: 2 }), /does not pay/);
});
