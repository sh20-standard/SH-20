// docs/audit/2026-11-24-vault.md, vault-1: the vault pays for a listing (a TAKE) or for a ticker (a MINT that pays
// its deployer or burns its price) only once the LIST or the DEPLOY is PAY_DEPTH blocks deep, at every indexer that
// answers and at Esplora. The reorgs that leave the price paid for nothing are in test/audit-vault.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { PAY_DEPTH, listingCheck, payDepthProblem } from '../src/consensus.js';
import { mintDepthProblem } from '../src/mint.js';
import { PAY_MODE } from '../src/sh20.js';

const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const page = () => ['app.js', ...readdirSync(new URL('../src/ui/', import.meta.url)).sort().map((f) => `ui/${f}`)].map(src).join('\n');
const body = (text, name) => text.slice(text.indexOf(name), text.indexOf('\n}\n', text.indexOf(name)));

test('vault-1: six blocks, counted with the block itself; no height, no tip, no payment', () => {
  assert.equal(PAY_DEPTH, 6);
  assert.equal(payDepthProblem('the LIST', 100, 105), null, '100 to 105: six blocks');
  assert.match(payDepthProblem('the LIST', 100, 104), /^the LIST is 5 blocks deep: the vault pays once it is 6 deep/);
  assert.match(payDepthProblem('the LIST', 100, 100), /is 1 block deep/);
  assert.match(payDepthProblem('the LIST', 100, 99), /is not in the chain yet/, 'a tip below the block: another chain');
  assert.match(payDepthProblem('the LIST', null, 200), /has no block yet/);
  for (const tip of [NaN, null, undefined, 104.5]) assert.match(payDepthProblem('the LIST', 100, tip), /the chain tip is unknown/, String(tip));
});

const LISTED = { listTxid: 'ab'.repeat(32), ticker: 'GENE', amount: 600n, price: 5000n, payScript: '0014' + '66'.repeat(20), lock: `${'ab'.repeat(32)}:0`, lockKey: 'cd'.repeat(32), state: 'ACTIVE', height: 100 };
const at = (base, height) => ({ base, listing: async () => LISTED, status: async () => ({ height }) });

test('vault-1: listingCheck counts the depth at the shallowest indexer, and names it', async () => {
  let r = await listingCheck([at('a', 110), at('b', 105)], LISTED.listTxid);
  assert.deepEqual([r.enough, r.depth, r.deep, r.depthProblem], [true, 6, true, null]);
  r = await listingCheck([at('a', 110), at('b', 104)], LISTED.listTxid);
  assert.deepEqual([r.enough, r.depth, r.deep], [true, 5, false], 'one indexer five blocks past the LIST holds the TAKE back');
  assert.match(r.depthProblem, /^the listing, at b, is 5 blocks deep/);
  r = await listingCheck([at('a', 110), { ...at('b', 110), status: async () => ({ height: null }) }], LISTED.listTxid);
  assert.equal(r.deep, false, 'an indexer with no height is no depth');
  // an indexer whose /status does not answer still counts for the listing, at a depth unknown
  const noStatus = (x) => ({ ...x, status: async () => { throw new Error('down'); } });
  r = await listingCheck([at('a', 110), at('b', 110), noStatus(at('c', 110))], LISTED.listTxid);
  assert.deepEqual([r.agreed, r.down, r.deep], [3, [], false]);
  assert.match(r.depthProblem, /^the listing, at c, has no block yet|the chain tip is unknown/);
  // and one that does not know the listing still refuses it when its /status fails (docs/AUDIT.md §8.3)
  await assert.rejects(listingCheck([at('a', 110), at('b', 110), noStatus({ base: 'c', listing: async () => null })], LISTED.listTxid), /c does not know this listing/);
  assert.equal(r.listing.at, undefined, 'the listing is the indexers\' record, without the height of one of them');
});

test('vault-1: a MINT waits for its DEPLOY only when it pays or burns', () => {
  const t = { ticker: 'PAID', genesis: false, deployHeight: 100, payMode: PAY_MODE.PAY };
  assert.match(mintDepthProblem(t, 104), /^the DEPLOY of PAID is 5 blocks deep/);
  assert.equal(mintDepthProblem(t, 105), null);
  assert.match(mintDepthProblem({ ...t, payMode: PAY_MODE.BURN }, 104), /5 blocks deep/, 'a burned price is lost the same way');
  assert.match(mintDepthProblem({ ...t, deployHeight: null }, 104), /has no block yet/);
  assert.equal(mintDepthProblem({ ...t, payMode: PAY_MODE.NONE }, 100), null, 'a free mint risks its network fee alone');
  assert.equal(mintDepthProblem({ ticker: 'SH20', genesis: true, deployHeight: null, payMode: PAY_MODE.NONE }, 1), null, 'SH20 has no DEPLOY');
});

test('vault-1: the page checks the depth where it pays, and says how far it is', () => {
  const p = page();
  const take = body(p, 'async function sendTake(');
  assert.ok(take.indexOf('if (!fresh.deep) throw') > 0 && take.indexOf('if (!fresh.deep) throw') < take.indexOf('buildTake('), 'checked again right before the TAKE is built');
  const checked = body(p, 'async function checkedListing(');
  assert.match(checked, /listingCheck\(indexers, listTxid\)/);
  assert.match(checked, /payDepthProblem\('the LIST transaction, at Esplora,', tx\?\.confirmed \? tx\.block_height : null, tip\)/, 'and at Esplora');
  assert.match(p, /disabled: !st\.wallet \|\| c\.state !== 'ACTIVE' \|\| !c\.enough \|\| !c\.deep/, 'no Buy button before it');
  assert.match(p, /id: 'listing-depth' \}/);
  assert.match(p, /\[\.\.\.mintProblems\(t, H \+ 1\), mintDepthProblem\(t, H\)\]/, 'the tickers table says why a mint waits');
  // and in the code that builds what the wallet signs, whatever the page did
  assert.match(body(src('market.js'), 'export function buildTake('), /payDepthProblem\('the listing', l\.height, tipHeight\)/);
  assert.match(body(src('mint.js'), 'export function buildMint('), /mintDepthProblem\(token, tipHeight\)/);
  assert.match(body(src('deploy.js'), 'export async function verifyDeploy('), /payDepthProblem\(`the DEPLOY of \$\{token\.ticker\}`, status\.block_height, tip\)/);
});
