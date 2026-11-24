// docs/audit/2026-11-24-vault.md, vault-17: what a mainnet page proposes and says, and its release. The fee every
// field proposes is the network's (Esplora's estimate), not 2 sat/vB; the wallet line names the page's network;
// release.js builds a mainnet release from the activation height the commit fixes, recorded apart from signet's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { Esplora } from '../src/api.js';
import { buildRelease, recordIn, releaseHeading } from '../release.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PROFILE_MODULE, fsReader, site, writeSite } from '../build.js';
import { IS_MAINNET } from '../src/profile.js';

const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');

test('vault-17: Esplora\'s estimate, or none: a rate is never made up where the server gives none', async () => {
  const at = (answer) => {
    globalThis.fetch = async () => (answer instanceof Error ? Promise.reject(answer) : { ok: true, status: 200, json: async () => answer, text: async () => JSON.stringify(answer) });
    return new Esplora('http://esplora');
  };
  assert.equal(await at({ 2: 14.23, 6: 3 }).feeEstimate(), 14.3, 'about two blocks, rounded up');
  assert.equal(await at({ 6: 4 }).feeEstimate(), 4);
  assert.equal(await at({ 2: 5000 }).feeEstimate(), 200, 'capped: a server cannot suggest a ruinous rate');
  assert.equal(await at({}).feeEstimate(), null);
  assert.equal(await at({ 2: 'x' }).feeEstimate(), null);
  assert.equal(await at(new Error('down')).feeEstimate(), null);
  assert.equal(await at({}).feeRate(), 1, 'feeRate keeps its floor for the callers that want one');
});

test('vault-17: every fee field proposes that estimate; without one, 2 sat/vB off mainnet and nothing on mainnet', () => {
  const context = src('ui/context.js');
  assert.match(context, /export const proposedFee = \(\) => st\.feeRate \?\? \(IS_MAINNET \? null : 2\);/);
  assert.match(context, /if \(!\(r > 0\)\) throw new Error\('no fee rate: Esplora gives no estimate now, so type one \(sat\/vB\)'\);/);
  assert.match(src('ui/tokens-panel.js'), /st\.feeRate = await esplora\.feeEstimate\(\);/, 'read with the tip');
  const ui = ['ui/send-panel.js', 'ui/market-panel.js', 'ui/deploy-panel.js', 'ui/tokens-panel.js'].map(src).join('\n');
  assert.doesNotMatch(ui, /fee: '2'|value: '2'|\|\| 2[,)]/, 'no fixed 2 sat/vB left');
  assert.equal((ui.match(/feeRate: feeRateOf\(/g) ?? []).length, 6, 'a BURN, a LIST, a TRANSFER, a TAKE, a cancel, a CLAIM');
  assert.match(src('ui/deploy-panel.js'), /sendDeploy\(d, D, feeRateOf\(fee\.value\)\)/);
  assert.match(src('ui/vault-panel.js'), /`Pick a wallet set to \$\{NET_TITLE\}\.`/);
  assert.doesNotMatch(src('ui/vault-panel.js'), /set to Signet/);
});

test('vault-17: a mainnet release is built from the A its commit fixes, never from a flag, and recorded apart', () => {
  const commit = execFileSync('git', ['rev-parse', 'HEAD']).toString().trim();
  const fixed = /^export const MAINNET_ACTIVATION_HEIGHT = (\d+);$/m.exec(execFileSync('git', ['show', `${commit}:vault/src/profile.js`]).toString());
  if (!fixed) assert.throws(() => buildRelease(commit, { mainnet: true }), /no mainnet build without its activation height/);
  else assert.equal(buildRelease(commit, { mainnet: true }).activation, Number(fixed[1]));
  assert.match(readFileSync(new URL('../release.js', import.meta.url), 'utf8'), /!\['--check', '--mainnet'\]\.includes\(a\)\) throw/, 'no --activation');
  // a signet and a mainnet release of one version are two entries, each with its profile and its A
  const r = (profile, sha) => ({ version: '0.4.0', name: `sh20-vault-0.4.0${profile === 'mainnet' ? '-mainnet' : ''}`, profile, activation: profile === 'mainnet' ? 840000 : 300000, entries: [], bytes: 1, sha256: sha.repeat(64), cid: 'bafy' });
  assert.equal(releaseHeading(r('mainnet', 'a')), '## 0.4.0 (mainnet)');
  const head = '# Vault releases\n\n## How to verify a release\n\ntext\n';
  let text = recordIn(head, r('signet', 'a'), 'c'.repeat(40));
  text = recordIn(text, r('mainnet', 'b'), 'c'.repeat(40));
  assert.match(text, /## 0\.4\.0 \(mainnet\)\n\n- Profile: mainnet, from block 840000\n/);
  assert.match(text, /## 0\.4\.0\n\n- Profile: signet, from block 300000\n/);
  assert.equal(recordIn(text, r('mainnet', 'b'), 'c'.repeat(40)), null, 'the same bytes: already recorded');
  assert.throws(() => recordIn(text, r('mainnet', 'd'), 'c'.repeat(40)), /version 0\.4\.0 \(mainnet\) is already released with SHA-256 b+/);
});

test('vault-17: what only mainnet needs is keyed on IS_MAINNET, which a mainnet page sets and no other', async () => {
  assert.equal(IS_MAINNET, false, 'the source tree: the test profile');
  const dir = mkdtempSync(join(tmpdir(), 'sh20-mainnet-page-'));
  try {
    const fs = fsReader();
    const reader = { ...fs, read: (p) => (p === PROFILE_MODULE ? Buffer.from(fs.read(p).toString('utf8').replace(/^export const MAINNET_ACTIVATION_HEIGHT = (null|0|[1-9]\d*);$/m, 'export const MAINNET_ACTIVATION_HEIGHT = null;')) : fs.read(p)) };
    writeSite(site(reader, { mainnet: true, activation: 840000 }), dir);
    const built = await import(pathToFileURL(join(dir, 'vault/src/profile.js')).href);
    assert.equal(built.IS_MAINNET, true);
    assert.equal(built.CHAIN.bitcoin, 'bitcoin', 'the chain a mainnet page names; \'main\' is the network an indexer reports');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // and no page code compares a network name of its own
  for (const f of ['ui/context.js', 'ui/spends.js', 'ui/tokens-panel.js', 'ui/send-panel.js', 'coins.js']) {
    if (!existsSync(new URL(`../src/${f}`, import.meta.url))) continue;
    assert.doesNotMatch(src(f), /CHAIN\.bitcoin === 'main'/, f);
  }
});

test('vault-14: a page that finds the other network\'s vault says so, and sends it to no words', () => {
  const panel = src('ui/vault-panel.js');
  assert.match(panel, /const other = Vault\.otherNetwork\(localStorage\);/);
  assert.match(panel, /other \? h\('p', \{ class: 'warn', id: 'other-network' \}, `A \$\{other\} vault is stored on this device too;[^`]*Create it with new words, and do not restore the \$\{other\} words here/);
  assert.doesNotMatch(src('keys.js'), /restore it from its 12 words/);
});
