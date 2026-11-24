// docs/audit/2026-11-24-verifier.md, verifier-4: an indexer verifies spends only with the pinned PLONK verifier
// (`plonk-bn254-hermez` in /status). Any other verifier, `reject-all`, `test`, one the vault does not know or none,
// is one that does not verify spends: the status line says so, and beside the balance, what it means.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Indexer, rejectAllVerifier } from '../../indexer/src/indexer.js';
import { listen } from '../../indexer/src/api.js';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { mockVerifier } from '../../indexer/test/helpers.js';
import { SPEND_VERIFIER, profileCheck, unverifiedSpends } from '../src/consensus.js';
import { IndexerApi } from '../src/api.js';
import { PROFILE } from '../src/profile.js';

const WASM = new URL('../prover/sh20_circuit.wasm', import.meta.url);
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');

test('verifier-4: the one name that verifies spends is the pinned PLONK verifier\'s, as both indexers report it', () => {
  assert.equal(plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }).name, SPEND_VERIFIER);
  assert.match(readFileSync(new URL('../../indexer-rs/src/main.rs', import.meta.url), 'utf8'), /--verifier <name>\s+plonk-bn254-hermez/);
  assert.equal(unverifiedSpends({ verifier: SPEND_VERIFIER }), null);
});

test('verifier-4: reject-all, test, a name the vault does not know or none: spends not verified, each said for what it is', () => {
  assert.match(unverifiedSpends({ verifier: rejectAllVerifier.name }), /refuses every spend \(verifier reject-all\): a transfer to you does not show/);
  assert.match(unverifiedSpends({ verifier: 'test' }), /does not check the proofs of spends \(verifier "test"\): a note it lists may not exist/);
  for (const v of ['mock', 'custom', 'Plonk-bn254-hermez', 'plonk-bn254-hermez ', 'plonk']) assert.match(unverifiedSpends({ verifier: v }), /does not check the proofs/, v);
  for (const s of [{}, { verifier: '' }, { verifier: null }, { verifier: 7 }, null]) assert.match(unverifiedSpends(s), /it names no verifier/, JSON.stringify(s));
});

test('verifier-4: profileCheck names every indexer that answers and does not verify spends, in the order configured', async () => {
  const servers = [];
  try {
    const at = async (verifier) => {
      const s = await listen(new Indexer({ profile: { activationHeight: PROFILE.activationHeight }, verifier }), { port: 0 });
      servers.push(s);
      return new IndexerApi(`http://127.0.0.1:${s.address().port}`);
    };
    const plonk = await at(plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }));
    const reject = await at(undefined); // the indexer's default: reject-all
    const mock = await at(mockVerifier()); // the vectors' rule, under another name
    const down = new IndexerApi('http://127.0.0.1:9');
    let r = await profileCheck([plonk, reject, down, mock]);
    assert.deepEqual(r.problems, []);
    assert.equal(r.answered, 3);
    assert.deepEqual(r.unverified.map((u) => u.base), [reject.base, mock.base]);
    assert.match(r.unverified[0].why, /verifier reject-all/);
    assert.match(r.unverified[1].why, /verifier "mock"/);
    r = await profileCheck([plonk]);
    assert.deepEqual(r.unverified, []);
  } finally {
    servers.forEach((s) => s.close());
  }
});

test('verifier-4: the page says it on the status line and beside the balance, from unverifiedSpends alone', () => {
  const tokens = src('ui/tokens-panel.js');
  const notes = src('ui/notes-panel.js');
  assert.ok(!/'reject-all'/.test(tokens + notes), 'no verifier name singled out in the page');
  assert.match(tokens, /unverifiedSpends\(status\) \? h\('span', \{ class: 'err', id: 'spends-unverified' \}/);
  assert.match(tokens, /st\.profile = await profileCheck\(indexers\);[\s\S]*?renderNotes\(\);/, 'the balance is drawn again once every indexer answered');
  assert.match(notes, /st\.profile\?\.unverified\?\.length\s*\? h\('p', \{ class: 'err', id: 'balance-unverified' \}/);
  assert.match(notes, /fill\('notes-body', h\('p', \{ class: 'muted' \}, 'No note yet\.'\), unverified\)/);
  assert.match(notes, /h\('p', \{ id: 'balance' \}[^\n]*\n\s*unverified,/);
});

test('vault-16: where the page acts, an indexer that verifies no spend counts for nothing', () => {
  const context = src('ui/context.js');
  const require = context.slice(context.indexOf('export async function requireProfile('), context.indexOf('\n}\n', context.indexOf('export async function requireProfile(')));
  assert.match(require, /const act = actProblems\(st\.profile, indexer\?\.base\);\s*if \(act\.length\) throw/, 'no spend on the tree of a primary that verifies none');
  const deploys = src('ui/deploy-panel.js');
  assert.match(deploys, /const act = actProblems\(pc, indexer\?\.base\);\s*if \(act\.length\) \{/, 'a DEPLOY reveal waits');
  assert.match(deploys, /const act = actProblems\(pr, indexer\?\.base\);/, 'the deploy screen offers no D');
  const consensus = src('consensus.js');
  assert.match(consensus, /enough: verifying >= TAKE_QUORUM/, 'a TAKE');
  assert.match(consensus, /if \(!verifying\.length\) problems\.push\(/, 'a mint');
  assert.match(consensus, /if \(!verifiesSpends\(status\)\) continue;[\s\S]*if \(!vouched\) return \{ ok: false/, 'a refusal');
});
