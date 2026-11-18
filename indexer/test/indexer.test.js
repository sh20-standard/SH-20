import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Indexer } from '../src/indexer.js';
import { noteLeaf, tickerT } from '../src/notes.js';

const G = tickerT('GENE');
import { publicKey, sign } from '../src/schnorr.js';
import { chain, deployEnv, mockVerifier, opening, p2tr, p2wpkh, spend, tx, txid } from './helpers.js';

const mint = (ticker, burnSats = 1000n, o = opening()) => tx({ env: { type: 'MINT', ticker, ...o }, burnSats });
const reasons = (r) => r.rejected.map((x) => x.reason);

function setup(profile = {}) {
  const verifier = mockVerifier();
  const ix = new Indexer({ profile: { activationHeight: 1, deployBurn: 0n, ...profile }, verifier });
  const c = chain(ix);
  return { ix, c, verifier };
}

test('SH20 exists from activation, free to mint; a DEPLOY adds paid mints; unpaid, early and duplicate are rejected', () => {
  const { ix, c } = setup();
  const b1 = c.block(tx({ env: deployEnv() }), mint('GENE'), tx({ env: deployEnv() }), mint('SH20', 0n), tx({ env: deployEnv({ ticker: 'SH20' }) }));
  assert.equal(b1.events[0].type, 'GENESIS');
  assert.equal(ix.genesis, 'SH20');
  const g = ix.token('SH20');
  assert.deepEqual([g.max, g.lim, g.pre, g.price, g.payMode, g.mints, g.deployTxid], [21000000n, 1000n, 0n, 0n, 0, 1n, null]);
  assert.equal(ix.token('GENE').t, 0x47454e45n);
  assert.deepEqual(reasons(b1), ['mint not open yet', 'ticker already deployed', 'ticker already deployed']);

  const o = opening();
  const b2 = c.block(mint('GENE', 1000n, o), mint('GENE', 999n));
  assert.deepEqual(reasons(b2), ['mint not paid']);
  assert.equal(ix.token('GENE').mints, 1n);
  assert.equal(ix.tree.leaves[1], noteLeaf(G, 1000n, o.npk, o.rho));
  assert.equal(b2.root, ix.tree.root);
});

test('payMode 2 pays the deployer script; sold out after (max - pre) / lim mints', () => {
  const { ix, c } = setup();
  const pay = p2wpkh();
  c.block(tx({ env: deployEnv({ max: 3000n, payMode: 2, payScript: pay }) }));
  const paid = () => tx({ env: { type: 'MINT', ticker: 'GENE', ...opening() }, vout: [{ value: 1000n, script: pay }] });
  const b2 = c.block(paid(), paid(), paid(), paid(), mint('GENE', 5000n));
  assert.deepEqual(reasons(b2), ['sold out', 'sold out']);
  assert.equal(ix.token('GENE').mints, 3n);
});

test('DEPLOY rules: public mint required, multiples, windows, prices', () => {
  const { c } = setup();
  const b1 = c.block(
    tx({ env: deployEnv({ ticker: 'AAAA', pre: 21000000n, team: opening() }) }),
    tx({ env: deployEnv({ ticker: 'BBBB', lim: 11n }) }),
    tx({ env: deployEnv({ ticker: 'CCCC', start: 1 }) }),
    tx({ env: deployEnv({ ticker: 'DDDD', unlock: 3, start: 5 }) }),
    tx({ env: deployEnv({ ticker: 'EEEE', payMode: 0 }) }),
  );
  assert.deepEqual(reasons(b1), [
    'pre must leave a public mint (pre < max)',
    '(max - pre) must be a multiple of lim',
    'start must be after the DEPLOY block',
    'unlock before start',
    'payMode 0 needs price 0',
  ]);
});

test('team allocation enters the tree at the unlock block, not before', () => {
  const { ix, c } = setup();
  const team = opening();
  c.block(tx({ env: deployEnv({ pre: 1000000n, team, unlock: 4 }) }));
  c.block();
  c.block();
  assert.equal(ix.tree.size, 0);
  const b4 = c.block();
  assert.equal(b4.events[0].type, 'TEAM_UNLOCK');
  assert.equal(ix.tree.leaves[0], noteLeaf(G, 1000000n, team.npk, team.rho));
});

test('with D > 0 every DEPLOY burns D SH20 through a proof; with D = 0 it carries none', () => {
  const { ix, c, verifier } = setup({ deployBurn: 1000n });
  c.block(mint('SH20', 0n));
  const b2 = c.block(
    tx({ env: deployEnv({ ticker: 'NOPE', start: 4, unlock: 4 }) }),
    tx({ env: deployEnv({ ticker: 'TWO2', start: 4, unlock: 4, spend: spend(1) }), carrier: 'witness' }),
  );
  assert.deepEqual(reasons(b2), ['DEPLOY must burn genesis units']);
  assert.equal(ix.token('TWO2').t, tickerT('TWO2'));
  assert.equal(ix.token('SH20').burned, 1000n);
  const call = verifier.calls.at(-1);
  assert.equal(call.vPub, 1000n);
  assert.equal(call.tPub, tickerT('SH20'));
  assert.equal(call.root, ix.roots.get(1));

  const free = setup();
  free.c.block();
  const b = free.c.block(tx({ env: deployEnv({ ticker: 'WITH', start: 4, unlock: 4, spend: spend(1) }), carrier: 'witness' }));
  assert.deepEqual(reasons(b), ['DEPLOY carries no burn when D = 0']);
});

test('TRANSFER: anchor window, nullifiers, proof', () => {
  const { ix, c, verifier } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  const s = spend(2);
  const b3 = c.block(
    tx({ env: { type: 'TRANSFER', spend: s }, carrier: 'witness' }),
    tx({ env: { type: 'TRANSFER', spend: { ...spend(2), nf: [s.nf[0], 5n] } }, carrier: 'witness' }),
    tx({ env: { type: 'TRANSFER', spend: spend(3) }, carrier: 'witness' }),
    tx({ env: { type: 'TRANSFER', spend: spend(2, 'forged') }, carrier: 'witness' }),
  );
  assert.deepEqual(reasons(b3), ['nullifier already spent', 'anchor outside the window', 'invalid proof']);
  assert.equal(verifier.calls[0].vPub, 0n);
  assert.equal(verifier.calls[0].tPub, 0n);
  assert.equal(ix.tree.size, 1 + 3);
  for (let i = 0; i < 101; i++) c.block();
  const late = c.block(tx({ env: { type: 'TRANSFER', spend: spend(2) }, carrier: 'witness' }));
  assert.deepEqual(reasons(late), ['anchor outside the window']);
});

test('BURN reveals amount and ticker, and lowers circulating supply', () => {
  const { ix, c, verifier } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  c.block(tx({ env: { type: 'BURN', ticker: 'GENE', vPub: 400n, spend: spend(2) }, carrier: 'witness' }));
  assert.equal(ix.token('GENE').burned, 400n);
  assert.equal(verifier.calls.at(-1).tPub, G);
});

function listed() {
  const env = setup();
  const sk = randomBytes(32);
  const lockScript = p2tr(publicKey(sk));
  const pay = p2wpkh();
  env.c.block(tx({ env: deployEnv() }));
  env.c.block(mint('GENE'));
  const listTx = tx({
    env: { type: 'LIST', ticker: 'GENE', amount: 1000n, price: 50000n, lockVout: 0, payScript: pay, spend: spend(2) },
    carrier: 'witness',
    vout: [{ value: 330n, script: lockScript }],
  });
  const b3 = env.c.block(listTx);
  assert.deepEqual(reasons(b3), []);
  return { ...env, sk, pay, listTxid: listTx.txid, lockIn: { txid: listTx.txid, vout: 0, witness: [] } };
}

test('LIST then TAKE with payment: SOLD, buyer gets a public note', () => {
  const { ix, c, pay, listTxid, lockIn } = listed();
  const buyer = opening();
  const b = c.block(tx({ env: { type: 'TAKE', ...buyer }, vin: [lockIn], vout: [{ value: 50000n, script: pay }] }));
  assert.equal(b.events[0].outcome, 'SOLD');
  assert.equal(ix.listings.get(listTxid).state, 'SOLD');
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(G, 1000n, buyer.npk, buyer.rho));
});

test('TAKE without payment is a cancel by the seller', () => {
  const { ix, c, listTxid, lockIn } = listed();
  const b = c.block(tx({ env: { type: 'TAKE', ...opening() }, vin: [lockIn] }));
  assert.equal(b.events[0].outcome, 'CANCELLED');
  assert.equal(ix.listings.get(listTxid).state, 'CANCELLED');
});

test('lock spent without TAKE: CLOSED, then CLAIM signed by the lock key', () => {
  const { ix, c, sk, listTxid, lockIn } = listed();
  c.block({ txid: txid(), vin: [lockIn], vout: [] });
  assert.equal(ix.listings.get(listTxid).state, 'CLOSED');
  const back = opening();
  const msg = Indexer.claimMessage(listTxid, back.npk, back.rho);
  const forged = c.block(tx({ env: { type: 'CLAIM', listTxid, ...back, sig: sign(randomBytes(32), msg) } }));
  assert.deepEqual(reasons(forged), ['bad CLAIM signature']);
  const ok = c.block(tx({ env: { type: 'CLAIM', listTxid, ...back, sig: sign(sk, msg) } }));
  assert.deepEqual(reasons(ok), []);
  assert.equal(ix.listings.get(listTxid).state, 'CLAIMED');
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(G, 1000n, back.npk, back.rho));
});

test('LIST needs a P2TR lock of at least 330 sats', () => {
  const { c } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  const list = (vout) => tx({ env: { type: 'LIST', ticker: 'GENE', amount: 10n, price: 10n, lockVout: 0, payScript: p2wpkh(), spend: spend(2) }, carrier: 'witness', vout });
  const b = c.block(list([{ value: 329n, script: p2tr() }]), list([{ value: 1000n, script: p2wpkh() }]));
  assert.deepEqual(reasons(b), ['lock output below 330 sats', 'lock output must be P2TR']);
});

test('the default verifier accepts no proof at all', () => {
  const ix = new Indexer({ profile: { activationHeight: 1 } });
  const c = chain(ix);
  c.block(mint('SH20', 0n));
  c.block();
  const b = c.block(tx({ env: { type: 'TRANSFER', spend: spend(2) }, carrier: 'witness' }));
  assert.deepEqual(reasons(b), ['invalid proof']);
});

test('envelopes before the activation height are ignored', () => {
  const ix = new Indexer({ profile: { activationHeight: 3 }, verifier: mockVerifier() });
  const c = chain(ix);
  c.block(tx({ env: deployEnv({ start: 4, unlock: 4 }) }));
  c.block();
  assert.equal(ix.tokens.size, 0);
});

test('a MINT names its ticker: an unknown ticker is rejected, two tokens never mix', () => {
  const { ix, c } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  c.block(tx({ env: deployEnv({ ticker: 'TWO2', start: 5, unlock: 5 }) }));
  c.block();
  const o = opening();
  const b = c.block(mint('NONE'), mint('TWO2', 1000n, o));
  assert.deepEqual(reasons(b), ['unknown ticker']);
  assert.equal(ix.token('TWO2').mints, 1n);
  assert.equal(ix.token('GENE').mints, 1n);
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(tickerT('TWO2'), 1000n, o.npk, o.rho));
  assert.deepEqual(ix.notes.at(-1).ticker, 'TWO2');
});

test('ticker ids: big-endian ASCII, never 0 (reserved for BTC)', () => {
  assert.equal(tickerT('GENE'), 0x47454e45n);
  assert.equal(tickerT('0000'), 0x30303030n);
  assert.ok(tickerT('0000') > 0n);
});
