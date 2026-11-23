// Development only: the relayer on a real Bitcoin Core regtest chain (docs/RELAYER.md). Bitcoin Core
// judges the relayer's commit and reveal by the network's relay policy; the two reference indexers of
// vault/dev/regtest.js read its batch with the real PLONK verifier.
//
//   node vault/dev/regtest.js &   then   node relayer/dev/regtest.js
//
// Two senders, each a vault in memory, mint SH20 (the dev wallet pays), sync, and prove a TRANSFER
// in Node (the vault's single-thread prover) whose outputs pay a recipient, the relayer's fee and
// their change. Each hands its 830 bytes to the relayer over HTTP; the relayer checks them, publishes
// both in one batch from its own coins, and the indexers, the recipient, the senders and the
// relayer's words (restored as a vault) all see the result. Prints the sizes Bitcoin Core accepted.

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { plonkVerifier } from '../../indexer/src/adapters/plonk.js';
import { IndexerApi, Esplora, normToken } from '../../vault/src/api.js';
import { Vault } from '../../vault/src/keys.js';
import { Sync } from '../../vault/src/sync.js';
import { memoryCache } from '../../vault/src/cache.js';
import { matchNotes } from '../../vault/src/match.js';
import { buildMint, buildFunded } from '../../vault/src/mint.js';
import { spendFrom, shuffled, proveSpend } from '../../vault/src/send.js';
import { decodeAddress } from '../../vault/src/sh20.js';
import { NETWORK_HRP } from '../../vault/src/notekeys.js';
import { finalizePsbt } from '../../vault/src/btc.js';
import { frHex } from '../../vault/src/fr.js';
import { newMnemonic } from '../../vault/src/bip39.js';
import { sha256 } from '../../vault/src/hash.js';
import { fromHex, toHex, utf8 } from '../../vault/src/bytes.js';
import { WALLET, signPsbt } from '../../vault/dev/test-wallet.js';
import { nodeProver, WASM } from '../../vault/test/prover-node.js';
import { relayerKeys } from '../src/keys.js';
import { Relayer } from '../src/relayer.js';
import { relayerHandler } from '../src/http.js';

const BASE = 'http://127.0.0.1:8020';
const api = new IndexerApi(BASE);
const second = new IndexerApi('http://127.0.0.1:8030');
const esplora = new Esplora(`${BASE}/esplora`);
const FEE = 25n; // SH20 a transfer, this relayer's price
const SEND = 100n;
const step = (s) => console.log(`· ${s}`);
const memStorage = () => {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};
const settle = async (h) => { // the followers step every 2 s and after each block the harness mines
  for (let i = 0; i < 50; i++) {
    if ((await api.status()).height >= h && (await second.status()).height >= h) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`the indexers did not reach block ${h}`);
};

/** A transaction paying `fixed` from the dev wallet, signed and broadcast (the harness mines it at once). */
async function payFromWallet(build) {
  const m = build({ payer: WALLET, utxos: await esplora.utxos(WALLET.address), feeRate: 2, tipHeight: await esplora.tipHeight() });
  const done = finalizePsbt(fromHex(signPsbt(toHex(m.psbt), m.inputIndexes)));
  await esplora.broadcast(done.hex);
  await settle(await esplora.tipHeight());
  return done.txid;
}

async function synced(vault) {
  const s = new Sync(memoryCache(), BASE);
  const r = await s.sync(api, { full: true });
  await matchNotes(vault, r.notes); // its MINTs by their keys, what it received by scanning
  for (const n of vault.state.notes) {
    if (n.pos === null) continue;
    const at = s.spentAt(frHex(await vault.nullifier(n)));
    await vault.updateNote(n.id, { pathAt: s.height, spent: at === null ? 'no' : `block ${at}` });
  }
  return s;
}
const unspent = (v) => v.state.notes.filter((n) => n.spent === 'no').map((n) => BigInt(n.v)).sort((a, b) => (a < b ? -1 : 1));

try {
  await api.status();
} catch {
  console.error('start the regtest chain first: node vault/dev/regtest.js');
  process.exit(1);
}

// ---- the relayer, funded by the dev wallet --------------------------------------------------------

const relayerWords = newMnemonic();
const keys = await relayerKeys({ words: relayerWords, btcSecret: sha256(utf8(`sh20 relayer regtest ${Date.now()}`)) });
await payFromWallet((p) => buildFunded({ ...p, fixed: [{ value: 200000n, script: keys.btc.script }] }));
step(`relayer funded: 200,000 sats at ${keys.btc.address}; fees sealed to ${keys.notes.addressString.slice(0, 20)}…`);
const relayer = new Relayer({
  keys, fees: new Map([['SH20', FEE]]), indexer: api, esplora, maxBatch: 2, log: (s) => step(`relayer: ${s}`),
  verifier: plonkVerifier({ wasm: new Uint8Array(readFileSync(WASM)) }),
});
const http = createServer(relayerHandler(relayer));
await new Promise((r) => http.listen(0, '127.0.0.1', r));
const RELAYER = `http://127.0.0.1:${http.address().port}`;

try {
  // ---- two senders mint SH20, a recipient waits -------------------------------------------------

  const token = normToken(await (await fetch(`${BASE}/token/SH20`)).json());
  const senders = [];
  for (let i = 0; i < 2; i++) {
    const v = await Vault.fromWords(memStorage(), newMnemonic(), '');
    const opening = await v.reserveNote();
    await payFromWallet((p) => buildMint({ ...p, token, opening }));
    senders.push(v);
  }
  const recipient = await Vault.fromWords(memStorage(), newMnemonic(), '');
  step(`two senders minted ${token.lim} SH20 each`);

  // ---- each proves a TRANSFER that pays the relayer, and hands it over ------------------------

  const info = await (await fetch(`${RELAYER}/info`)).json();
  assert.deepEqual(info.fees, { SH20: String(FEE) });
  const relayerAddr = await decodeAddress(NETWORK_HRP, info.address);
  const to = await decodeAddress(NETWORK_HRP, recipient.address);
  const prover = nodeProver();
  const handed = [];
  for (const [i, v] of senders.entries()) {
    const sync = await synced(v);
    const built = await spendFrom({
      vault: v, sync, tip: await esplora.tipHeight(), ticker: 'SH20', need: SEND + FEE,
      outputs: ({ change, me }) => shuffled([{ address: to, v: SEND }, { address: relayerAddr, v: FEE }, { address: me, v: change }]),
      envelope: (spend) => ({ type: 'TRANSFER', spend }),
    });
    const t0 = performance.now();
    const envelope = await proveSpend(prover, built);
    built.witness.fill(0);
    const r = await fetch(`${RELAYER}/transfer`, { method: 'POST', body: Buffer.from(envelope).toString('hex') });
    const body = await r.json();
    assert.equal(r.status, 202, JSON.stringify(body));
    handed.push({ envelope, nullifiers: body.nullifiers });
    step(`sender ${i + 1}: proved in ${((performance.now() - t0) / 1000).toFixed(1)} s, handed ${envelope.length} bytes to the relayer: ${body.state}, deadline block ${body.deadline}`);
  }
  // the relayer refuses the same notes twice, and answers the same bytes with their status
  assert.equal((await fetch(`${RELAYER}/transfer`, { method: 'POST', body: Buffer.from(handed[0].envelope).toString('hex') })).status, 200);

  // ---- one batch ------------------------------------------------------------------------------------

  const out = await relayer.tick();
  assert.equal(out?.transfers, 2, 'two queued, maxBatch 2: due');
  await settle(await esplora.tipHeight());
  const tx = await (await fetch(`${BASE}/tx/${out.txid}`)).json();
  assert.deepEqual(tx.events.map((e) => e.type), ['TRANSFER', 'TRANSFER'], JSON.stringify(tx));
  assert.deepEqual(tx.rejections, []);
  assert.equal(tx.event, null, 'a batch: one verdict per envelope, none for the whole');
  step(`batch ${out.txid.slice(0, 16)}…: both TRANSFERs accepted by the indexer; reveal ${out.revealVsize} vB, commit ${out.commitVsize} vB, ${out.fees} sats (${((out.revealVsize + out.commitVsize) / 2).toFixed(1)} vB a transfer)`);
  for (const h of handed) {
    const s = await (await fetch(`${RELAYER}/transfer/${h.nullifiers[0]}`)).json();
    assert.equal(s.state, 'published');
    assert.equal(s.txid, out.txid);
  }
  const height = (await api.status()).height;
  assert.equal(await api.digest(height), await second.digest(height), 'the two indexers agree on the state after the batch');
  step(`both indexers agree on the digest at block ${height}`);

  // ---- who got what ---------------------------------------------------------------------------------

  await synced(recipient);
  assert.deepEqual(unspent(recipient), [SEND, SEND]);
  step(`recipient: ${unspent(recipient).join(' + ')} SH20, sealed, found by scanning`);
  for (const [i, v] of senders.entries()) {
    await synced(v);
    assert.deepEqual(unspent(v), [token.lim - SEND - FEE], `sender ${i + 1}: the change, and the minted note spent`);
  }
  step(`senders: ${token.lim - SEND - FEE} SH20 of change each`);
  const earned = await Vault.fromWords(memStorage(), relayerWords, '');
  await synced(earned);
  assert.deepEqual(unspent(earned), [FEE, FEE]);
  step(`the relayer's words, restored as a vault: ${unspent(earned).join(' + ')} SH20 earned`);
  console.log('\nOK: the relayer took two transfers, Bitcoin Core accepted its commit and its reveal, the indexers accepted both transfers');
} finally {
  http.close();
}
