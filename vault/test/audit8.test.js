// The findings of docs/AUDIT.md §8 (a reading of the vault's cryptography), one test or more each:
// every test here fails on the code the reading was made on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Vault, STORAGE_KEY } from '../src/keys.js';
import { ownOrigins } from '../src/isolation.js';

const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
};
const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Runs `fn` with globalThis.location at `url`, as the page has it. */
async function at(url, fn) {
  const had = Object.getOwnPropertyDescriptor(globalThis, 'location');
  const u = new URL(url);
  Object.defineProperty(globalThis, 'location', { value: { pathname: u.pathname, hostname: u.hostname, search: u.search }, configurable: true });
  try {
    return await fn();
  } finally {
    if (had) Object.defineProperty(globalThis, 'location', had);
    else delete globalThis.location;
  }
}

// ---- 8.1: on a path gateway the vault warned and went on ---------------------------------------

const CID = 'bafybeigfj45xzun5mek5zvqeby6bs76ukwkslx7ifa7ipzdoylfl4pnavi';

test('8.1 no vault is created, restored from words or a backup, or unlocked on a path gateway', async () => {
  const backup = memStorage();
  await (await Vault.fromWords(backup, WORDS, 'pass')).save();
  const record = backup.getItem(STORAGE_KEY);
  await at(`https://ipfs.io/ipfs/${CID}/vault/`, async () => {
    const s = memStorage();
    await assert.rejects(Vault.create(s, 'pass'), /path gateway/);
    await assert.rejects(Vault.fromWords(s, WORDS, 'pass'), /path gateway/);
    await assert.rejects(Vault.restore(s, record, 'pass'), /path gateway/);
    assert.equal(s.getItem(STORAGE_KEY), null, 'nothing stored');
    await assert.rejects(Vault.open(backup, 'pass'), /path gateway/, 'a vault stored there earlier is not unlocked either');
  });
  await at(`https://${CID}.ipfs.dweb.link/vault/`, async () => {
    assert.ok(await Vault.open(backup, 'pass'), 'a subdomain gateway is its own origin');
  });
  await at('http://localhost:8000/vault/', async () => assert.ok(await Vault.open(backup, 'pass')));
});

test('8.1 the page says where to open the same release instead', () => {
  const o = (url) => { const u = new URL(url); return ownOrigins({ pathname: u.pathname }); };
  assert.deepEqual(o(`https://ipfs.io/ipfs/${CID}/vault/`), [`https://${CID}.ipfs.dweb.link/vault/`, `http://${CID}.ipfs.localhost:8080/vault/`]);
  assert.deepEqual(o(`https://ipfs.io/ipfs/${CID}`), [`https://${CID}.ipfs.dweb.link/`, `http://${CID}.ipfs.localhost:8080/`]);
  assert.deepEqual(o('https://gw.example/ipns/vault.sh20-test.org/vault/'), ['https://vault-sh20--test-org.ipns.dweb.link/vault/', 'http://vault-sh20--test-org.ipns.localhost:8080/vault/'], 'a DNSLink name, inlined in one label');
  const v0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';
  assert.deepEqual(o(`https://ipfs.io/ipfs/${v0}/vault/`), [`https://dweb.link/ipfs/${v0}/vault/`, `http://localhost:8080/ipfs/${v0}/vault/`], 'a CIDv0 is no DNS label: the path form that redirects');
  assert.equal(o(`https://${CID}.ipfs.dweb.link/vault/`), null);
  assert.equal(o('http://localhost:8000/vault/'), null);
});

test('8.1 on a path gateway the page stops before it reads its settings or shows a form', () => {
  const app = src('app.js');
  const stop = app.indexOf("if (gatewayKind() === 'path')");
  assert.ok(stop > 0, 'app.js checks for a path gateway');
  const block = app.slice(stop, app.indexOf('await new Promise(() => {});', stop));
  assert.match(block, /ownOrigins\(\)/, 'and names the addresses to use');
  for (const later of ['initContext()', 'loadSettings()', 'ensureIsolation()', 'renderAll()', 'Vault.open(', 'Vault.create(']) {
    const i = app.indexOf(later);
    assert.ok(i < 0 || i > stop, `${later} comes after the stop`);
  }
  const ctx = src('ui/context.js');
  assert.ok(!/path gateway/.test(ctx.slice(ctx.indexOf('function staticWarnings'))), 'no warning that lets the page go on');
});
