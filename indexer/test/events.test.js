import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { encodeEvent, encodeEvents } from '../src/events.js';
import { Indexer } from '../src/indexer.js';
import { DOMAIN } from '../src/constants.js';
import { frToBytes } from '../src/notes.js';

const sha256 = (...p) => p.reduce((h, x) => h.update(x), createHash('sha256')).digest();
const TX = '11'.repeat(32);
const LIST = '22'.repeat(32);
const NF = ['0'.repeat(63) + '1', '0'.repeat(63) + '2'];
const spend = { nullifiers: NF, positions: [7, 8, 9] };

test('event records: byte order and layout pinned by hand', () => {
  // code ‖ txid ‖ ticker ‖ u64le v ‖ u32le pos
  assert.equal(
    encodeEvent({ type: 'MINT', txid: TX, ticker: 'SH20', v: 1000n, pos: 5 }).toString('hex'),
    '02' + TX + '53483230' + 'e803000000000000' + '05000000',
  );
  // Block events carry 32 zero bytes where a txid would be; GENESIS commits to the profile's rules.
  assert.equal(
    encodeEvent({ type: 'GENESIS', ticker: 'SH20', max: 21000000n, lim: 1000n, deployBurn: 1000n, anchorWindow: 100, anchorMinDepth: 1 }).toString('hex'),
    '80' + '00'.repeat(32) + '53483230' + '406f400100000000' + 'e803000000000000' + 'e803000000000000' + '64000000' + '01000000',
  );
  // Nullifiers are field elements, 32 bytes little-endian as on the wire.
  assert.equal(
    encodeEvent({ type: 'TRANSFER', txid: TX, ...spend }).toString('hex'),
    '03' + TX + '01' + '00'.repeat(31) + '02' + '00'.repeat(31) + '07000000' + '08000000' + '09000000',
  );
  assert.equal(
    encodeEvent({ type: 'TAKE', txid: TX, listTxid: LIST, outcome: 'CANCELLED', pos: 3 }).toString('hex'),
    '06' + TX + LIST + '02' + '03000000',
  );
});

test('event records: one fixed size per type', () => {
  const sizes = {
    GENESIS: [{ ticker: 'SH20', max: 1n, lim: 1n, deployBurn: 0n, anchorWindow: 1, anchorMinDepth: 1 }, 69],
    TEAM_UNLOCK: [{ ticker: 'GENE', v: 1n, pos: 0 }, 49],
    DEPLOY: [{ txid: TX, ticker: 'GENE' }, 38],
    MINT: [{ txid: TX, ticker: 'GENE', v: 1n, pos: 0 }, 49],
    TRANSFER: [{ txid: TX, ...spend }, 109],
    BURN: [{ txid: TX, ticker: 'GENE', v: 1n, ...spend }, 121],
    LIST: [{ txid: TX, listTxid: TX, ticker: 'GENE', amount: 1n, price: 1n, ...spend }, 129],
    TAKE: [{ txid: TX, listTxid: LIST, outcome: 'SOLD', pos: 0 }, 70],
    CLOSED: [{ txid: TX, listTxid: LIST }, 65],
    CLAIM: [{ txid: TX, listTxid: LIST, pos: 0 }, 69],
  };
  for (const [type, [fields, n]] of Object.entries(sizes)) assert.equal(encodeEvent({ type, ...fields }).length, n, type);
  assert.equal(encodeEvent({ type: 'DEPLOY', txid: TX, ticker: 'GENE', burn: spend }).length, 38 + 64 + 12);
  assert.equal(encodeEvents([]).length, 0);
  assert.throws(() => encodeEvent({ type: 'NOPE', txid: TX }), /unknown event type/);
  assert.throws(() => encodeEvent({ type: 'MINT', txid: TX, ticker: 'SH2', v: 1n, pos: 0 }), /ticker must be 4 bytes/);
  assert.throws(() => encodeEvent({ type: 'TRANSFER', txid: TX, nullifiers: NF, positions: [1] }), /2 nullifiers and 3 positions/);
});

test('digest: SHA256(prev ‖ u32le(H) ‖ root ‖ SHA256(events_H)), from SHA256("sh20-v0")', () => {
  const ix = new Indexer({ profile: { activationHeight: 2 } });
  const start = sha256(Buffer.from(DOMAIN.DIGEST, 'utf8'));
  const h = (n) => Buffer.from([n, 0, 0, 0]);
  const root = frToBytes(ix.tree.root);

  // A block below A has no root and no digest: digest_{A−1} = SHA256("sh20-v0") whatever was read before A.
  const b1 = ix.applyBlock({ height: 1, txs: [] });
  assert.deepEqual([b1.root, b1.digest, ix.digests.has(1), ix.roots.has(1)], [null, null, false, false]);
  assert.ok(ix.digest.equals(start));

  const b2 = ix.applyBlock({ height: 2, txs: [] }); // activation: the GENESIS record alone
  assert.deepEqual(b2.events.map((e) => e.type), ['GENESIS']);
  assert.equal(b2.digest, sha256(start, h(2), root, sha256(encodeEvents(b2.events))).toString('hex'));
  const fresh = new Indexer({ profile: { activationHeight: 2 } }); // started at A: the same digest
  assert.equal(fresh.applyBlock({ height: 2, txs: [] }).digest, b2.digest);
  const b3 = ix.applyBlock({ height: 3, txs: [] }); // an empty block after A
  assert.equal(b3.digest, sha256(Buffer.from(b2.digest, 'hex'), h(3), root, sha256(Buffer.alloc(0))).toString('hex'));

  // Two indexers with different rules part at the activation block.
  const other = new Indexer({ profile: { activationHeight: 2, anchorWindow: 99 } });
  other.applyBlock({ height: 1, txs: [] });
  assert.notEqual(other.applyBlock({ height: 2, txs: [] }).digest, b2.digest);
});

test('vectors: every block lists its events_H and they hash into its digest', () => {
  const v = JSON.parse(readFileSync(new URL('../vectors/v0.3.json', import.meta.url), 'utf8'));
  let d = sha256(Buffer.from(DOMAIN.DIGEST, 'utf8'));
  for (const b of v.scenario.after) {
    const h = Buffer.alloc(4);
    h.writeUInt32LE(b.height);
    const root = frToBytes(BigInt('0x' + b.root));
    d = sha256(d, h, root, sha256(Buffer.from(b.eventsH, 'hex')));
    assert.equal(d.toString('hex'), b.digest, `block ${b.height}`);
  }
});

test('vectors: the nine public inputs of every verifier call match the envelope and the roots', async () => {
  const { extractEnvelope } = await import('../src/carrier.js');
  const { parseEnvelope } = await import('../src/codec.js');
  const { FR, DOMAIN: D } = await import('../src/constants.js');
  const v = JSON.parse(readFileSync(new URL('../vectors/v0.3.json', import.meta.url), 'utf8'));
  const hex = (x) => x.toString(16).padStart(64, '0');
  const roots = new Map(v.scenario.after.map((b) => [b.height, b.root]));
  assert.equal(v.scenario.verifierCalls.length, 7);
  for (const call of v.scenario.verifierCalls) {
    const raw = v.scenario.blocks.find((b) => b.height === call.height).txs.find((x) => x.txid === call.txid);
    const tx = { txid: raw.txid, vin: raw.vin.map((i) => ({ ...i, witness: i.witness.map((w) => Buffer.from(w, 'hex')) })), vout: raw.vout.map((o) => ({ value: BigInt(o.value), script: Buffer.from(o.script, 'hex') })) };
    const { env, body } = parseEnvelope(extractEnvelope(tx).bytes);
    const s = env.spend;
    const bodyHash = BigInt('0x' + sha256(Buffer.from(D.BODY), body).toString('hex')) % FR;
    const [root, nf0, nf1, l0, l1, l2, bh, vPub, tPub] = call.publicInputs;
    assert.equal(root, roots.get(s.anchorHeight), `anchor root of ${call.txid}`);
    assert.deepEqual([nf0, nf1, l0, l1, l2], [...s.nf, ...s.outs.map((o) => o.leaf)].map(hex));
    assert.equal(bh, hex(bodyHash));
    const t = (ticker) => BigInt('0x' + Buffer.from(ticker).toString('hex'));
    const expectPub = { TRANSFER: () => [0n, 0n], BURN: () => [env.vPub, t(env.ticker)], LIST: () => [env.amount, t(env.ticker)], DEPLOY: () => [1000n, t('SH20')] }[env.type]();
    assert.deepEqual([vPub, tPub], expectPub.map(hex), `${env.type} vPub, tPub`);
  }
});
