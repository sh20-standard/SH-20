// docs/audit/2026-11-24-sealing.md, sealing-1, the vault's part: how long a scan takes is not shown to any server.
// circuit/js/test/audit-sealing.test.js measures what a scan costs (0.2 s for an output that opens, a fraction of a
// millisecond for one that does not); that stays. What the vault changes is that no request waits on it: every
// request of a sync goes out before the scan, and none after it, so the indexer's clock reads nothing of the scan.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const notes = readFileSync(new URL('../src/ui/notes-panel.js', import.meta.url), 'utf8');
const code = (s) => s.replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '').replace(/`[^`]*`|'[^'\n]*'/g, "''"); // what runs, not what the comments and the texts say
const body = (name) => code(notes.slice(notes.indexOf(name), notes.indexOf('\n}\n', notes.indexOf(name))));
// what reaches a server: an indexer, Esplora, or a helper of the page that asks one
const NETWORK = /\bindexers?\b|\besplora\b|\bfetch\(|\.status\(|\.notes\(|\.listings\(|syncListings\(|settleRefused\(|processDeploys\(|digestAgreement\(|refusalAgreed\(|beforeAProblem\(|\bs\.sync\(/;

test('sealing-1: after the scan, a sync asks no server anything', () => {
  const sync = body('async function syncOnce(');
  const scan = sync.indexOf('await matchNotes(');
  assert.ok(scan > 0, 'the sync scans');
  const after = sync.slice(scan);
  const asked = after.split('\n').filter((l) => NETWORK.test(l));
  assert.deepEqual(asked, [], `requests after the scan:\n${asked.join('\n')}`);
  // and everything the sync asks is before it
  const before = sync.slice(0, scan);
  for (const call of ['s.sync(indexer', 'digestAgreement(', 'settleRefused(s)', 'syncListings()', 'processDeploys()', 'i.notes(0)']) {
    assert.ok(before.includes(call), `${call} before the scan`);
  }
});

test('sealing-1: what runs after the scan is local: the paths and spends of the notes just found', () => {
  const sync = body('async function syncOnce(');
  const after = sync.slice(sync.indexOf('await matchNotes('));
  assert.match(after, /await checkOwned\(s, \{ rest: true \}\)/, 'only the notes the scan found or placed');
  assert.deepEqual(body('async function checkOwned(').split('\n').filter((l) => NETWORK.test(l)), [], 'checkOwned reads the local tree and nullifier set only');
  // what the page does once the sync returns: drawing, and the warnings it computes itself
  assert.doesNotMatch(after, /processDeploys|then\(/);
});

test('sealing-1: the DEPLOY timer keeps its own clock, whatever a scan does', () => {
  const deploys = readFileSync(new URL('../src/ui/deploy-panel.js', import.meta.url), 'utf8');
  assert.match(deploys, /export const startDeployTimer = \(\) => setInterval\(\(\) => processDeploys\(\)\.catch\(report\), 60000\);/, 'every minute, not after a sync');
  assert.doesNotMatch(body('async function syncOnce('), /startDeployTimer|setTimeout|setInterval/, 'no sync starts or moves a timer');
});
