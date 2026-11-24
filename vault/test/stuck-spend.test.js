// docs/audit/2026-11-24-vault.md, vault-2: a spend that is never mined gives its notes back once no block can take
// it, one the wallet never signed gives them back at once, and the vault funds its transactions from confirmed coins
// only. The audit's own test is `vault-2: …` in test/audit-vault.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { REFUSAL_DEPTH, refusalAt, refusedSpend } from '../src/send.js';
import { PROFILE } from '../src/profile.js';

const W = PROFILE.anchorWindow;
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const body = (text, name) => text.slice(text.indexOf(name), text.indexOf('\n}\n', text.indexOf(name)));
const notes = (pathAt, spent = 'no') => [{ id: 'a', spent, pathAt }, { id: 'b', spent, pathAt }];
const spend = (status, anchorHeight = 1000) => ({ status, inputs: ['a', 'b'], anchorHeight });
const at = (h, more = {}) => ({ revealHeight: null, syncHeight: h, nullifiersKnown: true, ...more });

test('vault-2: never mined, its notes come back W + REFUSAL_DEPTH blocks after its anchor, whatever was sent of it', () => {
  const end = 1000 + W + REFUSAL_DEPTH;
  for (const status of ['signed', 'commit broadcast', 'broadcast']) {
    assert.equal(refusedSpend(spend(status), notes(end - 1), at(end - 1)), false, `${status}: a block could still take it, after a reorg`);
    assert.equal(refusedSpend(spend(status), notes(end), at(end)), true, status);
  }
  assert.equal(refusalAt(spend('broadcast'), null), 1000 + W + REFUSAL_DEPTH - 1, 'every indexer past the last block that could take it');
  // not one whose notes are spent, whose state is not that of this sync, or whose nullifiers the sync does not know
  assert.equal(refusedSpend(spend('broadcast'), notes(end, 'block 1050'), at(end)), false, 'it was mined: its nullifiers are recorded');
  assert.equal(refusedSpend(spend('broadcast'), notes(end - 3), at(end)), false, 'notes not checked against this tree');
  assert.equal(refusedSpend(spend('broadcast'), notes(end), at(end, { nullifiersKnown: false })), false);
  // nor what has a path of its own: prepared (given up by hand or by carry), a DEPLOY waiting for its maturity
  // (processDeploys proves it again when its anchor expires), one already settled
  for (const status of ['prepared', 'waiting maturity', 'refused by the indexers', 'given up']) assert.equal(refusedSpend(spend(status), notes(end), at(end)), false, status);
  assert.equal(refusedSpend({ ...spend('broadcast'), anchorHeight: undefined, envelope: 'zz' }, notes(end), at(end)), false, 'no anchor, no expiry');
  // a reveal that is mined keeps the rule it had: refused once REFUSAL_DEPTH deep with no nullifier recorded
  assert.equal(refusedSpend(spend('broadcast'), notes(1010), at(1010, { revealHeight: 1005 })), true);
  assert.equal(refusedSpend(spend('commit broadcast'), notes(1010), at(1010, { revealHeight: 1005 })), false, 'a confirmed reveal is a broadcast one');
});

test('vault-2: the page gives back what was never signed, lists what was left prepared, and settles what never confirms', () => {
  const carry = body(src('ui/spends.js'), 'async function carryOnce(');
  assert.match(carry, /done = await signFunded\(cp\.commit\);\s*\} catch \(e\) \{[\s\S]*?await st\.vault\.givePendingUp\(pid, 'not signed'\);/, 'a wallet that does not sign');
  assert.ok(carry.indexOf("?.status !== 'prepared') throw") > carry.indexOf('signFunded('), 'a spend given up while the wallet signed is not sent');
  assert.ok(carry.indexOf("?.status !== 'prepared') throw") < carry.indexOf('revealFor(cp, done.txid)'));
  const pending = src('ui/send-panel.js');
  assert.match(pending, /if \(p\.status === 'prepared'\) \{[\s\S]*?name: 'give-up' \}, 'Give up'\);/);
  const settle = body(src('ui/notes-panel.js'), 'async function settleRefused(');
  assert.match(settle, /\['signed', 'commit broadcast', 'broadcast'\]\.includes\(x\.status\)/);
  assert.match(settle, /refusalAgreed\(indexers, nfs, \{ atLeast: refusalAt\(p, revealHeight\) \}\)/, 'every indexer, as for a refusal');
});

test('vault-2: the page pays from coins Esplora lists as confirmed, a wallet\'s own list included', () => {
  const coins = body(src('ui/spends.js'), 'export async function walletUtxos(');
  assert.match(coins, /const chain = await esplora\.utxos\(w\.address\);/);
  assert.match(coins, /spendableCoins\(\{ chain, listed, apart,/, 'coins.js decides');
  const rule = body(src('coins.js'), 'export function spendableCoins(');
  assert.match(rule, /chain\.filter\(\(u\) => u\.confirmed === true\)/);
  assert.match(rule, /\(listed \?\? chain\)\.filter\(\(u\) => confirmed\.has\(key\(u\)\)\)/, 'UniSat\'s list too, which it marks confirmed itself');
  assert.match(body(src('ui/tokens-panel.js'), 'async function prepareMint('), /const utxos = await walletUtxos\(\);/, 'a MINT too');
  for (const f of ['ui/spends.js', 'ui/market-panel.js', 'ui/tokens-panel.js', 'ui/deploy-panel.js']) {
    assert.doesNotMatch(src(f).replace(body(src('ui/spends.js'), 'export async function walletUtxos('), ''), /adapter\.utxos|esplora\.utxos/, `${f}: no other source of coins`);
  }
});
