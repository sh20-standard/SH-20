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
  const ix = new Indexer({ profile: { deployMaturity: 0, activationHeight: 1, deployBurn: 0n, ...profile }, verifier });
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
  assert.equal(ix.tree.leaves[1], noteLeaf(G, 1000n, o.npk, 0n));
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

test('batch MINT: one note of k × lim for k × price, and the last batch gets what is left', () => {
  const { ix, c } = setup();
  const pay = p2wpkh();
  c.block(tx({ env: deployEnv({ max: 12000n, payMode: 2, payScript: pay }) }));
  const batch = (k, sats, o = opening()) => tx({ env: { type: 'MINT', ticker: 'GENE', ...o, k }, vout: [{ value: sats, script: pay }] });
  const o = opening();
  const b2 = c.block(batch(10, 9999n), batch(10, 10000n, o), batch(5, 2000n), batch(3, 2000n), batch(2, 2000n));
  // 10 underpaid; 10 paid; 5 when 2 are left pays 2 and gets 2; then sold out.
  assert.deepEqual(reasons(b2), ['mint not paid', 'sold out', 'sold out']);
  assert.deepEqual(b2.events.map((e) => [e.type, e.v]), [['MINT', 10000n], ['MINT', 2000n]]);
  assert.equal(ix.token('GENE').mints, 12n);
  const note = ix.notes.find((x) => x.kind === 'MINT' && x.v === 10000n);
  assert.equal(note.npk, o.npk.toString(16).padStart(64, '0'));
  assert.equal(BigInt('0x' + note.leaf), noteLeaf(G, 10000n, o.npk, 0n));
  assert.equal(ix.notes.filter((x) => x.kind === 'MINT').length, 2); // one leaf per envelope, whatever k

  // The genesis token is free: a batch costs network fees only.
  const g = c.block(tx({ env: { type: 'MINT', ticker: 'SH20', ...opening(), k: 10 } }));
  assert.deepEqual([g.events[0].v, ix.token('SH20').mints], [10000n, 10n]);
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
  assert.equal(ix.tree.leaves[0], noteLeaf(G, 1000000n, team.npk, 0n));
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
  const lockKey = publicKey(sk);
  const lockScript = p2tr(lockKey);
  const pay = p2wpkh();
  env.c.block(tx({ env: deployEnv() }));
  env.c.block(mint('GENE'));
  const listTx = tx({
    env: { type: 'LIST', ticker: 'GENE', amount: 1000n, price: 50000n, lockVout: 0, lockKey, payScript: pay, spend: spend(2) },
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
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(G, 1000n, buyer.npk, 0n));
});

test('TAKE without payment is a cancel by the seller', () => {
  const { ix, c, listTxid, lockIn } = listed();
  const b = c.block(tx({ env: { type: 'TAKE', ...opening() }, vin: [lockIn] }));
  assert.equal(b.events[0].outcome, 'CANCELLED');
  assert.equal(ix.listings.get(listTxid).state, 'CANCELLED');
});

test('turnstile: no spend takes more of a ticker out of the pool than went in, even with a broken circuit', () => {
  // The mock verifier accepts any proof: it plays a circuit with a soundness bug, where hidden notes can be forged.
  const { ix, c } = setup({ deployBurn: 1000n });
  const burn = (ticker, vPub) => tx({ env: { type: 'BURN', ticker, vPub, spend: spend(c.next - 1) }, carrier: 'witness' });
  const sh20Deploy = (ticker) => tx({ env: deployEnv({ ticker, start: c.next + 1, unlock: c.next + 1, spend: spend(c.next - 1) }), carrier: 'witness' });
  const b1 = c.block(mint('SH20', 0n), sh20Deploy('NOPE'));
  assert.deepEqual(reasons(b1), []); // 1,000 SH20 in the pool: the DEPLOY burns them
  const b2 = c.block(burn('SH20', 1n), sh20Deploy('NOPF'), burn('GENE', 1n));
  assert.deepEqual(reasons(b2), ['more than the pool holds of this ticker', 'more than the pool holds of this ticker', 'unknown ticker']);
  assert.deepEqual([ix.token('SH20').pool, ix.token('SH20').burned], [0n, 1000n]);

  // NOPE: two mints in, then exits up to exactly what went in.
  const b3 = c.block(mint('NOPE'), mint('NOPE'));
  assert.deepEqual(reasons(b3), []);
  const lockKey = publicKey(randomBytes(32));
  const lock = { value: 330n, script: p2tr(lockKey) };
  const list = (amount) => tx({ env: { type: 'LIST', ticker: 'NOPE', amount, price: 1n, lockVout: 0, lockKey, payScript: p2wpkh(), spend: spend(c.next - 1) }, carrier: 'witness', vout: [lock] });
  const b4 = c.block(list(2001n), list(1500n), burn('NOPE', 501n), burn('NOPE', 500n));
  assert.deepEqual(reasons(b4), ['more than the pool holds of this ticker', 'more than the pool holds of this ticker']);
  const t = ix.token('NOPE');
  assert.deepEqual([t.pool, t.burned], [0n, 500n]);
  // pool + what sits in listings + what was burned = what was issued
  const listed = [...ix.listings.values()].filter((l) => l.ticker === 'NOPE' && ['ACTIVE', 'CLOSED'].includes(l.state)).reduce((a, l) => a + l.amount, 0n);
  assert.equal(t.pool + listed + t.burned, t.mints * t.lim);
});

test('turnstile: TAKE, CLAIM and team unlocks bring units back into the pool, and a rollback restores it', () => {
  const { ix, c, listTxid, lockIn, sk } = listed();
  assert.equal(ix.token('GENE').pool, 0n); // 1,000 minted, 1,000 listed
  c.block({ txid: txid(), vin: [lockIn], vout: [] }); // CLOSED
  const back = opening();
  const claimed = c.block(tx({ env: { type: 'CLAIM', listTxid, ...back, sig: sign(sk, Indexer.claimMessage(listTxid, back.npk)) } }));
  assert.equal(ix.token('GENE').pool, 1000n);
  ix.rollback(claimed.height - 1);
  assert.equal(ix.token('GENE').pool, 0n);

  const { ix: iy, c: cy } = setup();
  cy.block(tx({ env: deployEnv({ pre: 5000n, team: opening(), start: 2, unlock: 3 }) }));
  cy.block();
  assert.equal(iy.token('GENE').pool, 0n);
  cy.block();
  assert.equal(iy.token('GENE').pool, 5000n);
});

test('lock spent without TAKE: CLOSED, then CLAIM signed by the lock key', () => {
  const { ix, c, sk, listTxid, lockIn } = listed();
  c.block({ txid: txid(), vin: [lockIn], vout: [] });
  assert.equal(ix.listings.get(listTxid).state, 'CLOSED');
  const back = opening();
  const msg = Indexer.claimMessage(listTxid, back.npk);
  const forged = c.block(tx({ env: { type: 'CLAIM', listTxid, ...back, sig: sign(randomBytes(32), msg) } }));
  assert.deepEqual(reasons(forged), ['bad CLAIM signature']);
  const ok = c.block(tx({ env: { type: 'CLAIM', listTxid, ...back, sig: sign(sk, msg) } }));
  assert.deepEqual(reasons(ok), []);
  assert.equal(ix.listings.get(listTxid).state, 'CLAIMED');
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(G, 1000n, back.npk, 0n));
});

test('LIST needs a P2TR lock to its lockKey, of at least 330 sats', () => {
  const { c } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  const key = publicKey(randomBytes(32));
  const list = (vout, lockKey = key) => tx({ env: { type: 'LIST', ticker: 'GENE', amount: 10n, price: 10n, lockVout: 0, lockKey, payScript: p2wpkh(), spend: spend(2) }, carrier: 'witness', vout });
  const b = c.block(list([{ value: 329n, script: p2tr(key) }]), list([{ value: 1000n, script: p2wpkh() }]), list([]));
  assert.deepEqual(reasons(b), ['lock output below 330 sats', 'lock output must be P2TR to lockKey', 'no lock output']);
});

test('a LIST copied into another transaction cannot point its lock at the copier', () => {
  // The seller's LIST is in the mempool; a copier puts the same envelope (same proof, same body) in a
  // transaction of its own whose output lockVout is a P2TR the copier controls, and gets it mined first.
  const { ix, c } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'));
  const sellerKey = publicKey(randomBytes(32));
  const env = { type: 'LIST', ticker: 'GENE', amount: 1000n, price: 50000n, lockVout: 0, lockKey: sellerKey, payScript: p2wpkh(), spend: spend(2) };
  const copy = tx({ env, carrier: 'witness', vout: [{ value: 330n, script: p2tr(publicKey(randomBytes(32))) }] });
  const seller = tx({ env, carrier: 'witness', vout: [{ value: 330n, script: p2tr(sellerKey) }] });
  const b = c.block(copy, seller);
  assert.deepEqual(reasons(b), ['lock output must be P2TR to lockKey']);
  assert.equal(ix.listings.get(seller.txid).lockKey, sellerKey.toString('hex'));
  // A copy that keeps the seller's lock key only creates a lock the seller controls: no theft.
});

test('the default verifier accepts no proof at all', () => {
  const ix = new Indexer({ profile: { deployMaturity: 0, activationHeight: 1 } });
  const c = chain(ix);
  c.block(mint('SH20', 0n));
  c.block();
  const b = c.block(tx({ env: { type: 'TRANSFER', spend: spend(2) }, carrier: 'witness' }));
  assert.deepEqual(reasons(b), ['invalid proof']);
});

test('envelopes before the activation height are ignored', () => {
  const ix = new Indexer({ profile: { deployMaturity: 0, activationHeight: 3 }, verifier: mockVerifier() });
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
  assert.equal(ix.tree.leaves.at(-1), noteLeaf(tickerT('TWO2'), 1000n, o.npk, 0n));
  assert.deepEqual(ix.notes.at(-1).ticker, 'TWO2');
});

test('ticker ids: big-endian ASCII, never 0 (reserved for BTC)', () => {
  assert.equal(tickerT('GENE'), 0x47454e45n);
  assert.equal(tickerT('0000'), 0x30303030n);
  assert.ok(tickerT('0000') > 0n);
});

test('a LIST whose txid already names a listing is refused (a chain built by hand)', () => {
  const { ix, c } = setup();
  c.block(tx({ env: deployEnv() }));
  c.block(mint('GENE'), mint('GENE'));
  const lockKey = publicKey(randomBytes(32));
  const list = (anchor) => tx({ id: 'aa'.repeat(32), env: { type: 'LIST', ticker: 'GENE', amount: 10n, price: 10n, lockVout: 0, lockKey, payScript: p2wpkh(), spend: spend(anchor) }, carrier: 'witness', vout: [{ value: 330n, script: p2tr(lockKey) }] });
  assert.deepEqual(reasons(c.block(list(2))), []);
  assert.deepEqual(reasons(c.block(list(3))), ['a listing already has this txid']);
  assert.equal(ix.listings.get('aa'.repeat(32)).amount, 10n);
});

test('a DEPLOY reveals a commit confirmed at least N blocks before, in the witness carrier only (no ticker sniping)', () => {
  const { ix, c } = setup({ deployMaturity: 6 });
  for (let i = 0; i < 9; i++) c.block();
  const H = c.next; // 10
  const env = deployEnv({ start: H + 1, unlock: H + 1 });
  // A watcher copies the ticker from the mempool: its commit is fresh, so its reveal is refused.
  const sniper = tx({ env: deployEnv({ start: H + 1, unlock: H + 1, payMode: 2, payScript: p2wpkh() }), prevHeight: H - 1 });
  const viaOpReturn = tx({ env, carrier: 'opreturn' });
  const original = tx({ env, prevHeight: H - 6 });
  const b = c.block(sniper, viaOpReturn, original);
  assert.deepEqual(reasons(b), ['DEPLOY commit confirmed less than 6 blocks before', 'DEPLOY must use the witness carrier']);
  assert.equal(ix.token('GENE').deployTxid, original.txid);
});

test('a block that does not follow the last one is refused before anything is applied', () => {
  const ix = new Indexer({ profile: { deployMaturity: 0, activationHeight: 1, deployBurn: 0n }, verifier: mockVerifier() });
  ix.applyBlock({ height: 1, hash: 'h1', txs: [] });
  const digest = ix.digest.toString('hex');
  assert.throws(() => ix.applyBlock({ height: 3, hash: 'h3', txs: [] }), /expected block 2, got 3/);
  assert.equal(ix.height, 1);
  assert.equal(ix.digest.toString('hex'), digest);
});
