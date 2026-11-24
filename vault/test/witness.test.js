// docs/audit/2026-11-24-vault.md, vault-6: an envelope read from Esplora is bound to the chain through the output its
// input 0 spends (src/witness.js). The audit's own test is `vault-6: …` in test/audit-vault.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { witnessProblem } from '../src/witness.js';
import { commitment, commitValue, signReveal, oneTimeSecret, leafHash, tweakKey, LEAF_VERSION } from '../src/taproot.js';
import { addressToScript, parseTx, serializeTx, txid } from '../src/btc.js';
import { serializeEnvelope, taggedHash } from '../src/sh20.js';
import { deployEnv } from '../../indexer/test/helpers.js';
import { concat, fromHex, toHex } from '../src/bytes.js';

const back = addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
const hex = (tx) => toHex(serializeTx(tx));
const txOut = (script, value = 10000n) => ({ version: 2, locktime: 0, vin: [{ txid: '66'.repeat(32), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(64)] }], vout: [{ value, script }] });

function pair() {
  const secret = oneTimeSecret();
  const c = commitment(secret, new Uint8Array(serializeEnvelope(deployEnv())));
  const commit = txOut(c.scriptPubKey, commitValue(c, back, 1));
  const { tx } = signReveal({ secret, c, commitTxid: txid(commit), value: commit.vout[0].value, returnScript: back, feeRate: 1 });
  return { c, commit, reveal: tx };
}

test('vault-6: a reveal is bound to the commit output it spends, and to nothing else', () => {
  const { commit, reveal } = pair();
  assert.equal(witnessProblem(hex(reveal), hex(commit)), null);
  // another script in the same witness: the same txid, and not the committed one
  const forged = parseTx(fromHex(hex(reveal)));
  forged.vin[0].witness[1] = concat(forged.vin[0].witness[1], Uint8Array.of(0x75));
  assert.equal(txid(forged), txid(reveal));
  assert.match(witnessProblem(hex(forged), hex(commit)), /not the script the output it spends commits to/);
  // another transaction than the one input 0 names, a key-path spend, a non-P2TR output, nothing known
  assert.match(witnessProblem(hex(reveal), hex(txOut(commit.vout[0].script, 9999n))), /another transaction than the one input 0 spends/);
  const keyPath = parseTx(fromHex(hex(reveal)));
  keyPath.vin[0].witness = [new Uint8Array(64)];
  assert.match(witnessProblem(hex(keyPath), hex(commit)), /not spent by a script path/);
  const other = txOut(back);
  const spendsWpkh = parseTx(fromHex(hex(reveal)));
  spendsWpkh.vin[0].txid = txid(other);
  assert.match(witnessProblem(hex(spendsWpkh), hex(other)), /does not spend a P2TR output/);
  assert.match(witnessProblem(hex(reveal), null), /is unknown/);
});

test('vault-6: an annex is set aside; a tree of more than one leaf, or a control block of the other parity, binds nothing', () => {
  const { commit, reveal } = pair();
  const annexed = parseTx(fromHex(hex(reveal)));
  annexed.vin[0].witness = [...annexed.vin[0].witness, Uint8Array.of(0x50, 1, 2)];
  assert.equal(witnessProblem(hex(annexed), hex(commit)), null);
  // the same script as one leaf of two, the tree valid: the same txid would fit a witness that reveals the other leaf
  const [sig, script, control] = reveal.vin[0].witness;
  const internal = control.subarray(1, 33);
  const sibling = leafHash(Uint8Array.of(0x51));
  const mine = leafHash(script);
  const [x, y] = Buffer.compare(Buffer.from(mine), Buffer.from(sibling)) <= 0 ? [mine, sibling] : [sibling, mine];
  const q = tweakKey(internal, new Uint8Array(taggedHash('TapBranch', x, y)));
  const prev = txOut(concat(Uint8Array.of(0x51, 0x20), q.key));
  const t = parseTx(fromHex(hex(reveal)));
  t.vin[0].txid = txid(prev);
  t.vin[0].witness = [sig, script, concat(Uint8Array.of(LEAF_VERSION | q.parity), internal, sibling)];
  assert.match(witnessProblem(hex(t), hex(prev)), /commits to more than one script/);
  // the parity bit of the control block is the output key's
  const flipped = parseTx(fromHex(hex(reveal)));
  flipped.vin[0].witness[2] = Uint8Array.from(control, (b, i) => (i === 0 ? b ^ 1 : b));
  assert.match(witnessProblem(hex(flipped), hex(commit)), /not the script the output it spends commits to/);
});

test('vault-6: the page reads every envelope it pays or vouches for through that check', () => {
  const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
  assert.match(src('deploy.js'), /hex = await committedHex\(esplora, token\.deployTxid\);/);
  const market = src('ui/market-panel.js');
  assert.match(market, /committedHex\(esplora, listTxid\)/, 'an offer to buy');
  assert.match(market, /listingFromChain\(l\.listTxid, await committedHex\(esplora, l\.listTxid\)/, 'a listing found again by its lock key');
  assert.match(market, /sent \?\? \(await committedHex\(esplora, rec\.listTxid\)\)/, 'an own listing the vault has no copy of');
  assert.doesNotMatch(market.replace(/claimProblem\(l, out\.spent && out\.txid \? await esplora\.txHex\(out\.txid\)/, ''), /esplora\.txHex\(/, 'no other envelope read on Esplora\'s word');
});
