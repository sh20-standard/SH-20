// The mainnet profile, next to test and signet: its network (Bitcoin addresses, SH-20 addresses, what
// the wallet extensions are asked for, what the vault records), its servers, and a mainnet build, which
// takes its activation height from --activation or from profile.js and refuses without one. These hold
// whether vault/src/profile.js has MAINNET_ACTIVATION_HEIGHT fixed or not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DEFAULT_PROFILE } from '../../indexer/src/constants.js';
import { CHAINS, MAINNET_ACTIVATION_HEIGHT, MAINNET_NETWORK, PROFILES, profileAt } from '../src/profile.js';
import { NETWORKS, addressToScript, scriptToAddress } from '../src/btc.js';
import { MAINNET_NAME_MODULE, PROFILE_MODULE, PROFILE_NAME_MODULE, fsReader, mainnetActivation, site, writeSite } from '../build.js';
import { toHex } from '../src/bytes.js';

const WORDS = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};
/** The working tree with MAINNET_ACTIVATION_HEIGHT at `A` (null: not fixed), whatever the tree holds. */
const fixedAt = (A) => {
  const fs = fsReader();
  return { ...fs, read: (p) => (p === PROFILE_MODULE ? Buffer.from(fs.read(p).toString('utf8').replace(/^export const MAINNET_ACTIVATION_HEIGHT = (null|0|[1-9]\d*);$/m, `export const MAINNET_ACTIVATION_HEIGHT = ${A};`)) : fs.read(p)) };
};

test('the mainnet profile: the rules of the others, its own A, and the network its indexers report', () => {
  assert.deepEqual(Object.keys(PROFILES), ['test', 'signet', 'mainnet']);
  if (MAINNET_ACTIVATION_HEIGHT === null) assert.equal(PROFILES.mainnet, null, 'no mainnet profile before its A is fixed');
  else assert.deepEqual({ ...PROFILES.mainnet }, { ...profileAt(MAINNET_ACTIVATION_HEIGHT, MAINNET_NETWORK) });
  assert.equal(mainnetActivation(fsReader()), MAINNET_ACTIVATION_HEIGHT);
  assert.equal(mainnetActivation(fixedAt(null)), null);
  assert.equal(mainnetActivation(fixedAt(840000)), 840000);
  const at = profileAt(840000, MAINNET_NETWORK);
  assert.equal(MAINNET_NETWORK, 'main', "Bitcoin Core's chain name, which follow.js reports in /status");
  for (const k of Object.keys(at)) assert.equal(at[k], { activationHeight: 840000, network: 'main' }[k] ?? PROFILES.test[k], k);
  assert.equal(PROFILES.test.network, DEFAULT_PROFILE.network);
  assert.deepEqual({ ...CHAINS.mainnet }, { bitcoin: 'bitcoin', addresses: 'mainnet', label: 'mainnet' });
  assert.equal(CHAINS.test, CHAINS.signet, 'the test profile is signet\'s network');
});

test('btc.js on Bitcoin mainnet: bc1, 1 and 3 addresses, and none of another network', () => {
  const net = NETWORKS.bitcoin;
  assert.deepEqual({ ...net }, { name: 'bitcoin', hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 });
  // BIP173, BIP350 and the base58 forms
  const vectors = {
    bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4: '0014751e76e8199196d454941c45d1b3a323f1433bd6',
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0: '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2': '76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac',
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy': 'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87',
  };
  for (const [a, script] of Object.entries(vectors)) {
    assert.equal(toHex(addressToScript(a, net)), script, a);
    assert.equal(scriptToAddress(addressToScript(a, net), net), a, `${a} back`);
    assert.throws(() => addressToScript(a, NETWORKS.signet), /not a signet address/, `${a} is not signet's`);
  }
  assert.throws(() => addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', net), /not a bitcoin address/);
  assert.throws(() => addressToScript('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn', net), /not a bitcoin address/);
});

test('a mainnet build refuses without an activation height; --activation gives one, else profile.js', () => {
  assert.throws(() => site(fixedAt(null), { mainnet: true }), /no mainnet build without its activation height/);
  for (const bad of [-1, 1.5, '840000', NaN]) assert.throws(() => site(fixedAt(null), { mainnet: true, activation: bad }), /not a block height/, String(bad));
  assert.throws(() => site(fixedAt(null), { activation: 840000 }), /--activation is for a mainnet build/);
  assert.throws(() => site(fixedAt(840000), { signet: true, mainnet: true }), /one profile per build/);
  const test = new Map(site(fixedAt(null)));
  const differ = (m) => [...m.keys()].filter((p) => !m.get(p).equals(test.get(p)));
  // from the command line: profile-name.js, and the height written into the built profile.js
  const cli = new Map(site(fixedAt(null), { mainnet: true, activation: 840000 }));
  assert.deepEqual([...cli.keys()], [...test.keys()]);
  assert.deepEqual(differ(cli), [PROFILE_NAME_MODULE, PROFILE_MODULE]);
  assert.equal(cli.get(PROFILE_NAME_MODULE).toString(), MAINNET_NAME_MODULE);
  assert.match(cli.get(PROFILE_MODULE).toString(), /^export const MAINNET_ACTIVATION_HEIGHT = 840000;$/m);
  assert.equal(cli.get(PROFILE_MODULE).toString().replace('= 840000;', '= null;'), test.get(PROFILE_MODULE).toString(), 'that line alone');
  // fixed in profile.js: profile-name.js alone; --activation still wins when given
  const fixed = new Map(site(fixedAt(830000), { mainnet: true }));
  assert.deepEqual(differ(new Map([...fixed].map(([p, b]) => [p, p === PROFILE_MODULE ? test.get(p) : b]))), [PROFILE_NAME_MODULE]);
  assert.match(new Map(site(fixedAt(830000), { mainnet: true, activation: 840000 })).get(PROFILE_MODULE).toString(), /MAINNET_ACTIVATION_HEIGHT = 840000;/);
});

test('the built mainnet page: its profile, Bitcoin and SH-20 addresses, servers, wallets and vaults are mainnet\'s', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sh20-mainnet-'));
  const saved = { XverseProviders: globalThis.XverseProviders, unisat: globalThis.unisat, LeatherProvider: globalThis.LeatherProvider };
  try {
    writeSite(site(fixedAt(null), { mainnet: true, activation: 840000 }), dir);
    const built = (f) => import(pathToFileURL(join(dir, 'vault/src', f)).href);
    const profile = await built('profile.js');
    assert.equal(profile.PROFILE_NAME, 'mainnet');
    assert.deepEqual({ ...profile.PROFILE }, { ...profileAt(840000, 'main') });
    assert.equal(profile.CHAIN.bitcoin, 'bitcoin');
    const btc = await built('btc.js');
    assert.equal(btc.NETWORK.name, 'bitcoin');
    assert.equal(toHex(btc.addressToScript('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')), '0014751e76e8199196d454941c45d1b3a323f1433bd6', 'mainnet addresses by default');
    assert.throws(() => btc.addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'), /not a bitcoin address/);
    assert.equal(btc.scriptToAddress(btc.addressToScript('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')), '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy');
    const notekeys = await built('notekeys.js');
    assert.equal(notekeys.NETWORK_HRP, 'sh20', 'SPEC-NOTES §2: the mainnet prefix');
    const servers = await built('servers.js');
    assert.deepEqual(servers.defaultSettings(profile.PROFILE_NAME, 'https://example.invalid/vault/'), { indexer: '', esplora: 'https://mempool.space/api' });

    // the vault: a mainnet address, the network recorded, and a signet vault not opened here
    const { Vault } = await built('keys.js');
    const store = memStorage();
    const v = await Vault.fromWords(store, WORDS, 'pass');
    assert.match(v.address, /^sh201/);
    assert.equal(v.state.network, 'bitcoin');
    const { Vault: SignetVault } = await import('../src/keys.js'); // the source tree: the test profile, signet's network
    const signetStore = memStorage();
    const sv = await SignetVault.fromWords(signetStore, WORDS, 'pass');
    assert.match(sv.address, /^tsh201/);
    assert.equal(sv.address.slice(5, -6), v.address.slice(4, -6), 'the same keys under another prefix (the bech32m checksum covers the prefix)');
    await assert.rejects(Vault.open(signetStore, 'pass'), /made on signet, and this page follows mainnet: restore it from its 12 words/);
    await assert.rejects(Vault.restore(memStorage(), sv.exportBackup(), 'pass'), /made on signet/, 'nor its backup');
    await assert.rejects(SignetVault.open(store, 'pass'), /made on mainnet, and this page follows signet/);
    const again = await Vault.fromWords(memStorage(), WORDS, 'p2', { restored: true });
    assert.equal(again.address, v.address, 'the words restore it on mainnet');

    // the wallets: each extension asked for mainnet, and switched to it
    const asked = [];
    globalThis.XverseProviders = { BitcoinProvider: { request: async (method, params) => {
      asked.push(['xverse', method, params]);
      if (method === 'wallet_connect') return { result: { addresses: [{ purpose: 'payment', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: '02'.padEnd(66, '1') }] } };
      if (method === 'wallet_getNetwork') return { result: { bitcoin: { name: 'Signet' } } };
      return { result: {} };
    } } };
    let chain = 'BITCOIN_SIGNET';
    globalThis.unisat = {
      requestAccounts: async () => ['bc1q-unisat'], getAccounts: async () => ['bc1q-unisat'], getPublicKey: async () => '02',
      getChain: async () => ({ enum: chain }), switchChain: async (c) => { asked.push(['unisat', 'switchChain', c]); chain = c; },
    };
    globalThis.LeatherProvider = { request: async (method, params) => {
      asked.push(['leather', method, params]);
      return { result: { addresses: [{ symbol: 'BTC', type: 'p2wpkh', address: 'bc1q-leather', publicKey: '02' }] } };
    } };
    const { WALLETS } = await built('wallets.js');
    const [xverse, unisat, leather] = ['xverse', 'unisat', 'leather'].map((id) => WALLETS.find((w) => w.id === id));
    assert.equal((await xverse.connect()).network, 'Mainnet');
    assert.equal(asked.find(([w, m]) => w === 'xverse' && m === 'wallet_connect')[2].network, 'Mainnet');
    assert.match(asked.find(([w, m]) => w === 'xverse' && m === 'wallet_connect')[2].message, /on mainnet/);
    assert.deepEqual(asked.find(([w, m]) => w === 'xverse' && m === 'wallet_changeNetwork')[2], { name: 'Mainnet' }, 'a wallet on signet is switched');
    assert.equal((await unisat.connect()).network, 'mainnet');
    assert.deepEqual(asked.find(([w]) => w === 'unisat'), ['unisat', 'switchChain', 'BITCOIN_MAINNET']);
    globalThis.unisat = { requestAccounts: async () => ['x'], getAccounts: async () => ['x'], getPublicKey: async () => '02', getNetwork: async () => 'testnet' };
    await assert.rejects(unisat.connect(), /cannot switch to mainnet/, 'an older UniSat on testnet');
    globalThis.unisat.getNetwork = async () => 'livenet';
    assert.equal((await unisat.connect()).network, 'mainnet');
    assert.equal((await leather.connect()).network, 'mainnet');
    assert.equal(asked.find(([w, m]) => w === 'leather' && m === 'getAddresses')[2].network, 'mainnet');
  } finally {
    Object.assign(globalThis, saved);
    rmSync(dir, { recursive: true, force: true });
  }
});
