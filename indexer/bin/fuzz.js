#!/usr/bin/env node
// Differential fuzzing: random chains through the reference indexer and `indexer-rs`, compared block by block.
//
//   node bin/fuzz.js --rs <path to sh20-indexer-rs> [--seed <text>] [--chains <n>] [--blocks <n>] [--keep <dir>]
//
// Each chain is a folder of `getblock <hash> 3` JSON files: valid and broken envelopes of every type, both carriers,
// batches, listings bought, claimed and closed, refused proofs, reused nullifiers, anchors at and past the window,
// DEPLOY commits old enough or not. The reference applies them in this process; `indexer-rs replay --json` reads the
// same folder. Every block's root and digest must agree, and so must the set of refused envelopes. A chain where they
// differ is kept (in --keep, default fuzz-failures/) with the command that replays it, and the run fails.
//
// The generator is not a model of the rules: it only makes inputs likely to reach them. Same seed, same chains.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FR } from '../src/constants.js';
import { serializeEnvelope } from '../src/codec.js';
import { Indexer } from '../src/indexer.js';
import { fromBitcoindBlock } from '../src/adapters/bitcoind.js';
import { publicKey, sign } from '../src/schnorr.js';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : dflt;
};
const RS = arg('--rs');
if (!RS) {
  console.error('usage: node bin/fuzz.js --rs <path to sh20-indexer-rs> [--seed <text>] [--chains <n>] [--blocks <n>] [--keep <dir>]');
  process.exit(2);
}
const SEED = arg('--seed', 'sh20');
const CHAINS = Number(arg('--chains', 50));
const BLOCKS = Number(arg('--blocks', 40));
const KEEP = arg('--keep', 'fuzz-failures');

// The profile both indexers are given: a short window and maturity so that chains of 40 blocks reach both ends.
const PROFILE = { activationHeight: 1, deployBurn: 1000n, deployMaturity: 3, anchorWindow: 12 };
const RS_FLAGS = ['--activation', '1', '--deploy-burn', '1000', '--maturity', '3', '--window', '12', '--verifier', 'test', '--json'];
const PROOF = Buffer.concat([Buffer.from('valid-proof'), Buffer.alloc(480 - 11)]);
const verifier = { name: 'test', verifySpend: (a) => Buffer.from(a.proof).equals(PROOF) };

// A deterministic stream of random numbers: SHA-256 of the seed and a counter.
function rng(seed) {
  let n = 0;
  let pool = Buffer.alloc(0);
  const take = (k) => {
    while (pool.length < k) pool = Buffer.concat([pool, createHash('sha256').update(`${seed}/${n++}`).digest()]);
    const out = pool.subarray(0, k);
    pool = pool.subarray(k);
    return Buffer.from(out);
  };
  const r = {
    bytes: take,
    int: (lo, hi) => lo + (take(4).readUInt32LE() % (hi - lo + 1)), // inclusive
    chance: (p) => take(4).readUInt32LE() / 2 ** 32 < p,
    pick: (a) => a[r.int(0, a.length - 1)],
    fr: () => BigInt('0x' + take(32).toString('hex')) % FR,
    hex: (k) => take(k).toString('hex'),
  };
  return r;
}

const push = (d) => {
  if (d.length <= 75) return Buffer.concat([Buffer.from([d.length]), d]);
  if (d.length <= 255) return Buffer.concat([Buffer.from([0x4c, d.length]), d]);
  const l = Buffer.alloc(2);
  l.writeUInt16LE(d.length);
  return Buffer.concat([Buffer.from([0x4d]), l, d]);
};
const opReturn = (d) => Buffer.concat([Buffer.from([0x6a]), push(d)]);
const tapscript = (...envs) => {
  const parts = [Buffer.from([0x20]), Buffer.alloc(32, 7), Buffer.from([0xac])];
  for (const env of envs) {
    parts.push(Buffer.from([0x00, 0x63]), push(Buffer.from('SH20')));
    const rest = env.subarray(4);
    for (let i = 0; i < rest.length; i += 520) parts.push(push(rest.subarray(i, i + 520)));
    parts.push(Buffer.from([0x68]));
  }
  return Buffer.concat(parts);
};
const witness = (...envs) => [Buffer.alloc(64, 1), tapscript(...envs), Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(32, 9)])];
const p2tr = (key) => Buffer.concat([Buffer.from([0x51, 0x20]), key]);
// Amounts as Bitcoin Core prints them: a decimal with 8 places, never an exponent (JSON.stringify would write 6e-7).
const sats = (n) => `@BTC${(Number(n) / 1e8).toFixed(8)}@`;
const blockJson = (b) => JSON.stringify(b).replace(/"@BTC([0-9.]+)@"/g, '$1');

function chain(seed) {
  const r = rng(seed);
  const tickers = ['SH20', 'AAAA', 'BBBB', 'CCCC', 'DDDD', 'EEEE'];
  const nullifiers = []; // seen in envelopes, to be reused now and then
  const listings = []; // { txid, secret, key, price, payScript, closed }
  const blocks = [];

  const nf = () => (nullifiers.length && r.chance(0.12) ? r.pick(nullifiers) : (nullifiers.push(r.fr()), nullifiers.at(-1)));
  const spend = (H) => {
    // mostly inside [H − W, H − 1]; now and then on either side of it, or at its ends
    const anchorHeight = r.chance(0.8) ? r.int(Math.max(0, H - 12), Math.max(0, H - 1)) : r.pick([H, H + 1, Math.max(0, H - 13), Math.max(0, H - 12)]);
    const n0 = nf();
    return {
      anchorHeight,
      nf: [n0, r.chance(0.03) ? n0 : nf()],
      outs: [0, 1, 2].map(() => ({ leaf: r.chance(0.01) ? 0n : r.fr(), pkEph: r.bytes(32), ct: r.bytes(28) })),
      proof: r.chance(0.9) ? PROOF : r.bytes(480),
    };
  };
  const payScript = () => r.pick([
    Buffer.concat([Buffer.from([0x00, 0x14]), r.bytes(20)]),
    Buffer.concat([Buffer.from([0x51, 0x20]), r.bytes(32)]),
    ...(r.chance(0.1) ? [Buffer.from('6a0453483230', 'hex'), Buffer.from('6a', 'hex'), Buffer.from('516a', 'hex')] : []),
  ]);
  const env = (fields) => {
    try {
      return serializeEnvelope(fields);
    } catch {
      return null; // a field the codec will not even write: dropped
    }
  };
  // now and then, a valid envelope with one byte changed or cut short
  const damage = (b) => {
    if (!b || !r.chance(0.06)) return b;
    const c = Buffer.from(b);
    if (r.chance(0.5)) c[r.int(4, c.length - 1)] ^= 1 << r.int(0, 7);
    else return c.subarray(0, r.int(4, c.length - 1));
    return c;
  };

  for (let H = 1; H <= BLOCKS; H++) {
    const txs = [{ txid: r.hex(32), vin: [{ coinbase: '03' + r.hex(3), ...(r.chance(0.1) ? { txinwitness: witness(env({ type: 'MINT', ticker: 'SH20', npk: r.fr() })).map((w) => w.toString('hex')) } : {}) }], vout: [{ value: sats(312500000), n: 0, scriptPubKey: { hex: '51' } }] }];
    const n = r.int(0, 7);
    for (let i = 0; i < n; i++) {
      const tx = { txid: r.hex(32), vin: [{ txid: r.hex(32), vout: 0 }], vout: [] };
      const out = (value, script) => tx.vout.push({ value: sats(value), n: tx.vout.length, scriptPubKey: { hex: script.toString('hex') } });
      const inWitness = (...envs) => {
        tx.vin[0].txinwitness = witness(...envs.filter(Boolean)).map((w) => w.toString('hex'));
      };
      // listings get bought, closed and claimed more often once there are some
      const market = listings.length ? ['take', 'take', 'claim', 'claim', 'lockSpend'] : [];
      const kind = r.pick(['mint', 'mint', 'mint', 'mintPaid', 'deploy', 'transfer', 'transfer', 'batch', 'burn', 'list', 'list', 'garbage', ...market]);
      if (kind === 'mint') {
        const k = r.chance(0.3) ? r.pick([2, 5, 10, r.int(0, 12)]) : undefined;
        const b = damage(env({ type: 'MINT', ticker: r.chance(0.85) ? 'SH20' : r.pick(tickers), npk: r.fr(), ...(k !== undefined ? { k } : {}) }));
        if (b) out(0, opReturn(b));
      } else if (kind === 'mintPaid') {
        const k = r.chance(0.3) ? r.int(2, 10) : 1;
        const b = env({ type: 'MINT', ticker: r.pick(tickers.slice(1)), npk: r.fr(), ...(k > 1 ? { k } : {}) });
        if (b) out(r.chance(0.5) ? r.int(0, 3000) * k : 0, opReturn(b));
        out(r.int(0, 3000) * k, payScript());
      } else if (kind === 'deploy') {
        const lim = BigInt(r.pick([100, 500, 1000]));
        const m = BigInt(r.int(2, 50));
        const p = BigInt(r.int(0, Number(m) - 1));
        const start = H + r.int(0, 4);
        const payMode = r.chance(0.95) ? r.int(0, 2) : 3;
        const b = damage(env({
          type: 'DEPLOY', ticker: r.pick(tickers), max: lim * m, lim, pre: lim * p, start, end: r.chance(0.7) ? 0 : start + r.int(0, 10),
          unlock: start + r.int(0, 6), price: BigInt(r.int(0, 3000)), payMode, payScript: payMode === 2 ? payScript() : Buffer.alloc(0),
          team: p > 0n ? { npk: r.fr() } : null, spend: spend(H),
        }));
        if (!b) continue;
        if (r.chance(0.9)) inWitness(b);
        else out(0, opReturn(b));
        // the commit: old enough, too young by one block, or (rarely) no height at all, which stops both indexers
        if (r.chance(0.995)) tx.vin[0].prevout = { height: r.chance(0.8) ? Math.max(0, H - 3 - r.int(0, 5)) : Math.max(0, H - 2), value: sats(10000), scriptPubKey: { hex: '51' } };
      } else if (kind === 'transfer' || kind === 'burn') {
        const b = damage(env(kind === 'transfer' ? { type: 'TRANSFER', spend: spend(H) } : { type: 'BURN', ticker: r.pick(tickers), vPub: BigInt(r.int(1, 3000)), spend: spend(H) }));
        if (!b) continue;
        if (r.chance(0.92)) inWitness(b);
        else out(0, opReturn(b));
      } else if (kind === 'batch') {
        const members = Array.from({ length: r.int(2, 5) }, () => damage(env({ type: 'TRANSFER', spend: spend(H) })));
        if (r.chance(0.1)) members.splice(r.int(0, members.length), 0, env({ type: 'MINT', ticker: 'SH20', npk: r.fr() }));
        if (r.chance(0.05)) members.splice(r.int(0, members.length), 0, Buffer.concat([Buffer.from('SH20'), Buffer.from([0x01, 0x03]), r.bytes(20)]));
        inWitness(...members);
      } else if (kind === 'list') {
        const secret = r.bytes(32);
        const key = publicKey(secret);
        const price = BigInt(r.int(1, 5000));
        const ps = payScript();
        const b = damage(env({ type: 'LIST', ticker: r.chance(0.7) ? 'SH20' : r.pick(tickers), amount: BigInt(r.int(1, 2000)), price, lockVout: 0, lockKey: key, payScript: ps, spend: spend(H) }));
        if (!b) continue;
        inWitness(b);
        out(r.chance(0.95) ? 330 : 329, r.chance(0.95) ? p2tr(key) : p2tr(r.bytes(32)));
        listings.push({ txid: tx.txid, secret, key, price, payScript: ps });
      } else if (kind === 'take' && listings.length) {
        const l = r.pick(listings);
        tx.vin.push({ txid: l.txid, vout: 0 });
        if (r.chance(0.3)) [tx.vin[0], tx.vin[1]] = [tx.vin[1], tx.vin[0]];
        const b = env({ type: 'TAKE', npk: r.fr() });
        out(0, opReturn(b));
        if (r.chance(0.85)) out(Number(l.price) - (r.chance(0.1) ? 1 : 0), l.payScript);
      } else if (kind === 'claim' && listings.length) {
        const l = r.pick(listings);
        const npk = r.fr();
        const secret = r.chance(0.9) ? l.secret : r.bytes(32);
        const b = env({ type: 'CLAIM', listTxid: l.txid, npk, sig: sign(secret, Indexer.claimMessage(l.txid, npk)) });
        if (b) out(0, opReturn(b));
      } else if (kind === 'lockSpend' && listings.length) {
        tx.vin.push({ txid: r.pick(listings).txid, vout: 0 });
        out(1000, Buffer.from('51', 'hex'));
      } else {
        const g = r.pick(['prefix', 'two', 'v1', 'push4']);
        if (g === 'prefix') out(0, opReturn(Buffer.concat([Buffer.from('SH20'), r.bytes(r.int(0, 60))])));
        if (g === 'two') {
          out(0, opReturn(env({ type: 'MINT', ticker: 'SH20', npk: r.fr() })));
          out(0, opReturn(env({ type: 'MINT', ticker: 'SH20', npk: r.fr() })));
        }
        if (g === 'v1') out(0, opReturn(Buffer.concat([Buffer.from('SH20'), Buffer.from([0x01, 0x02]), r.bytes(30)])));
        if (g === 'push4') out(0, Buffer.concat([Buffer.from([0x6a, 0x4c, 42]), env({ type: 'MINT', ticker: 'SH20', npk: r.fr() })])); // not minimal
      }
      if (!tx.vin[0].txinwitness) tx.vin[0].txinwitness = [];
      if (tx.vout.length === 0) out(546, Buffer.from('51', 'hex'));
      txs.push(tx);
    }
    blocks.push({ height: H, hash: r.hex(32), tx: txs });
  }
  return blocks;
}

// The reference, in this process: per block, root, digest and the refused envelopes; or the height it stopped at.
function reference(blocks) {
  const ix = new Indexer({ profile: PROFILE, verifier });
  const out = [];
  for (const b of blocks) {
    try {
      const res = ix.applyBlock(fromBitcoindBlock(JSON.parse(blockJson(b))));
      for (const e of res.events) seen[e.type] = (seen[e.type] ?? 0) + 1;
      out.push({ height: res.height, root: res.root.toString(16).padStart(64, '0'), digest: res.digest, rejected: res.rejected.map((x) => `${x.txid}/${x.envelope ?? '-'}`).sort() });
    } catch (e) {
      return { blocks: out, stopped: b.height, why: e.message };
    }
  }
  return { blocks: out };
}

function rust(dir) {
  let stdout;
  let stopped;
  try {
    stdout = execFileSync(RS, ['replay', dir, ...RS_FLAGS], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
  } catch (e) {
    stdout = e.stdout ?? '';
    stopped = e.stderr?.toString().trim() || 'exit ' + e.status;
  }
  const blocks = stdout.split('\n').filter(Boolean).map((line) => {
    const j = JSON.parse(line);
    return { height: j.height, root: j.root, digest: j.digest, rejected: (j.rejected ?? []).map((x) => `${x.txid}/${x.envelope ?? '-'}`).sort() };
  });
  return { blocks, stopped };
}

function compare(a, b) {
  const n = Math.max(a.blocks.length, b.blocks.length);
  for (let i = 0; i < n; i++) {
    const x = a.blocks[i];
    const y = b.blocks[i];
    if (!x || !y) return `block ${(x ?? y).height}: only ${x ? 'the reference' : 'indexer-rs'} applied it (reference: ${a.why ?? 'went on'}; indexer-rs: ${b.stopped ?? 'went on'})`;
    for (const k of ['height', 'root', 'digest']) if (x[k] !== y[k]) return `block ${x.height}: ${k} differs (reference ${x[k]}, indexer-rs ${y[k]})`;
    if (JSON.stringify(x.rejected) !== JSON.stringify(y.rejected)) {
      const only = (p, q) => p.filter((t) => !q.includes(t));
      return `block ${x.height}: refusals differ (only the reference: ${only(x.rejected, y.rejected).join(' ') || '-'}; only indexer-rs: ${only(y.rejected, x.rejected).join(' ') || '-'})`;
    }
  }
  if (Boolean(a.stopped) !== Boolean(b.stopped)) return `only ${a.stopped ? 'the reference' : 'indexer-rs'} stopped (${a.why ?? b.stopped})`;
  return null;
}

const seen = {}; // accepted events by type, so that a run shows what it reached
let failures = 0;
let applied = 0;
let refused = 0;
const t0 = Date.now();
for (let c = 0; c < CHAINS; c++) {
  const seed = `${SEED}/${c}`;
  const blocks = chain(seed);
  const dir = mkdtempSync(join(tmpdir(), 'sh20-fuzz-'));
  blocks.forEach((b) => writeFileSync(join(dir, `${String(b.height).padStart(6, '0')}.json`), blockJson(b)));
  const a = reference(blocks);
  const b = rust(dir);
  applied += a.blocks.length;
  refused += a.blocks.reduce((s, x) => s + x.rejected.length, 0);
  const diff = compare(a, b);
  if (diff) {
    failures++;
    const keep = join(KEEP, seed.replace(/[^A-Za-z0-9._-]/g, '_'));
    mkdirSync(keep, { recursive: true });
    cpSync(dir, keep, { recursive: true });
    console.log(`DIVERGENCE in chain ${seed}: ${diff}\n  kept in ${keep}; replay: ${RS} replay ${keep} ${RS_FLAGS.join(' ')}`);
  }
  rmSync(dir, { recursive: true, force: true });
}
console.log(`${CHAINS} chains, ${applied} blocks, ${refused} refused envelopes, ${failures} divergence(s), ${((Date.now() - t0) / 1000).toFixed(1)} s (seed "${SEED}")`);
console.log('accepted: ' + Object.entries(seen).sort().map(([k, v]) => `${k} ${v}`).join(', '));
process.exit(failures ? 1 : 0);
