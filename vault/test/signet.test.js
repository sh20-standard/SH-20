// Version 0.3.1, ready for the signet: a signet profile next to the test one (profile.js), default
// servers that lead to nobody of ours (servers.js), and a release that is built on the signet profile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { PROFILE, PROFILES, PROFILE_NAME, SIGNET_ACTIVATION_HEIGHT, profileAt } from '../src/profile.js';
import { SERVERS, defaultSettings } from '../src/servers.js';
import { PROFILE_NAME_MODULE, SIGNET_NAME_MODULE, fsReader, signetActivation, site, writeSite } from '../build.js';

const fixedAt = (A) => {
  // the working tree, with the signet's activation height fixed at A, as at launch
  const fs = fsReader();
  return {
    ...fs,
    read: (p) => (p === 'vault/src/profile.js'
      ? Buffer.from(fs.read(p).toString('utf8').replace(/^export const SIGNET_ACTIVATION_HEIGHT = null;$/m, `export const SIGNET_ACTIVATION_HEIGHT = ${A};`))
      : fs.read(p)),
  };
};

test('1. a signet profile next to the test one: DEFAULT_PROFILE, with the activation height its only parameter', () => {
  const keys = ['network', 'activationHeight', 'deployBurn', 'deployMaturity', 'anchorWindow', 'anchorMinDepth', 'genesis'];
  assert.deepEqual({ ...PROFILES.test }, {
    network: DEFAULT_PROFILE.network, activationHeight: DEFAULT_PROFILE.activationHeight, deployBurn: DEFAULT_PROFILE.deployBurn,
    deployMaturity: DEFAULT_PROFILE.deployMaturity, anchorWindow: DEFAULT_PROFILE.anchorWindow, anchorMinDepth: DEFAULT_PROFILE.anchorMinDepth,
    genesis: DEFAULT_PROFILE.genesis.ticker,
  });
  const at = profileAt(230000);
  assert.deepEqual(Object.keys(at), keys);
  for (const k of keys) assert.equal(at[k], k === 'activationHeight' ? 230000 : PROFILES.test[k], k);
  assert.ok(Object.isFrozen(at));
  for (const bad of [-1, 1.5, '230000', null, NaN]) assert.throws(() => profileAt(bad), /not a block height/, String(bad));

  // not fixed yet: no signet profile, and the source tree follows the test one
  assert.equal(SIGNET_ACTIVATION_HEIGHT, null);
  assert.equal(PROFILES.signet, null);
  assert.equal(PROFILE_NAME, 'test');
  assert.equal(PROFILE, PROFILES.test);
  assert.equal(signetActivation(fsReader()), null);
  assert.equal(signetActivation(fixedAt(230000)), 230000);
  assert.equal(signetActivation(fixedAt(0)), 0);
});

test('1. a signet build refuses until the activation height is fixed; then only profile-name.js differs, and the page follows it', async () => {
  assert.throws(() => site(fsReader(), { signet: true }), /no signet build: the signet activation height is not fixed/);
  const test = new Map(site(fixedAt(230000)));
  const signet = new Map(site(fixedAt(230000), { signet: true }));
  assert.deepEqual([...signet.keys()], [...test.keys()]);
  const differ = [...signet.keys()].filter((p) => !signet.get(p).equals(test.get(p)));
  assert.deepEqual(differ, [PROFILE_NAME_MODULE], 'the one file a signet build changes');
  assert.equal(signet.get(PROFILE_NAME_MODULE).toString(), SIGNET_NAME_MODULE);
  assert.match(test.get(PROFILE_NAME_MODULE).toString(), /^export const PROFILE_NAME = 'test';$/m);

  // the built page, loaded as a browser would: the signet profile, from block 230000
  const dir = mkdtempSync(join(tmpdir(), 'sh20-signet-'));
  try {
    writeSite([...signet.entries()], dir);
    const built = await import(pathToFileURL(join(dir, 'vault/src/profile.js')).href);
    assert.equal(built.PROFILE_NAME, 'signet');
    assert.deepEqual({ ...built.PROFILE }, { ...profileAt(230000) });
    assert.equal(built.ACTIVATION_HEIGHT, 230000);
    const servers = await import(pathToFileURL(join(dir, 'vault/src/servers.js')).href);
    assert.deepEqual(servers.defaultSettings(built.PROFILE_NAME), defaultSettings('signet'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Hosts a default, or any URL in the site, may name. None is run by the SH-20 contributors. Adding a
// public indexer to the signet defaults means adding its host here, in review (vault/RELEASES.md).
const LOOPBACK = new Set(['127.0.0.1', 'localhost']);
const THIRD_PARTY = new Set(['mempool.space', 'dweb.link']); // a public signet Esplora; the IPFS gateway of isolation.js

test('2. the default servers are the site\'s own mirrors on signet, and none leads to us', () => {
  assert.deepEqual(Object.keys(SERVERS), ['test', 'signet'], 'one set per profile');
  // the mirrors beside the page (docs/API.md, "The static mirror"), resolved against the page's URL
  assert.deepEqual(defaultSettings('signet', 'https://sh-20.github.io/SH-20/vault/'), { indexer: 'https://sh-20.github.io/SH-20/api/js/\nhttps://sh-20.github.io/SH-20/api/rs/', esplora: 'https://mempool.space/signet/api' });
  assert.deepEqual(defaultSettings('signet', 'http://localhost:8000/vault/?x=1'), { indexer: 'http://localhost:8000/api/js/\nhttp://localhost:8000/api/rs/', esplora: 'https://mempool.space/signet/api' });
  assert.deepEqual(defaultSettings('signet', undefined), { indexer: '../api/js/\n../api/rs/', esplora: 'https://mempool.space/signet/api' }, 'no page: as written');
  assert.deepEqual(defaultSettings('test', 'https://sh-20.github.io/SH-20/vault/'), { indexer: 'http://127.0.0.1:8020\nhttp://127.0.0.1:8030', esplora: 'http://127.0.0.1:8020/esplora' });
  assert.throws(() => defaultSettings('mainnet'), /no servers for the mainnet profile/);
  const PAGE = 'https://page.invalid/vault/';
  for (const [name, s] of Object.entries(SERVERS)) {
    for (const u of [...s.indexers, s.esplora]) {
      const { hostname } = new URL(u, PAGE);
      assert.ok(hostname === 'page.invalid' || LOOPBACK.has(hostname) || THIRD_PARTY.has(hostname), `${name}: ${u}`);
    }
    assert.ok(s.indexers.every((u) => ['page.invalid', ...LOOPBACK].includes(new URL(u, PAGE).hostname)), `${name}: every default indexer is the page's own origin or your machine`);
  }
  assert.ok(SERVERS.signet.indexers.every((u) => new URL(u, PAGE).origin === new URL(PAGE).origin), 'on signet, the page\'s own origin only');
  // the page takes them from servers.js, for its profile; Settings and a confirmed link replace them
  const context = readFileSync(new URL('../src/ui/context.js', import.meta.url), 'utf8');
  assert.match(context, /const DEFAULTS = defaultSettings\(PROFILE_NAME\);/);
  assert.doesNotMatch(context, /https?:\/\//, 'no server written in the page itself');

  // and no URL anywhere in the site names another host
  for (const [p, bytes] of site(fsReader())) {
    if (!/\.(html|js|css)$/.test(p)) continue;
    for (const [, host] of bytes.toString('utf8').matchAll(/https?:\/\/(?:\$\{[^}]+\}\.)*([a-z0-9.-]+)/gi)) {
      const base = host.replace(/^.*?((?:[a-z0-9-]+\.)?[a-z0-9-]+\.[a-z]+|localhost|127\.0\.0\.1)$/i, '$1');
      assert.ok(LOOPBACK.has(host) || THIRD_PARTY.has(host) || THIRD_PARTY.has(base) || /\.(localhost|invalid)$/.test(host), `${p}: ${host}`); // .invalid never resolves (RFC 2606): mirror-read.js parses routes against it
    }
  }
});
