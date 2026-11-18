// The deploy screen: checks a new ticker's terms against the DEPLOY rules
// (docs/SPEC-WIRE.md §5, the same checks as indexer/src/indexer.js `_deploy`)
// and states what it costs. When the profile's D > 0, a DEPLOY burns D SH20:
// it carries a spend (a proof over up to two of the deployer's SH20 notes,
// vPub = D, tPub = t("SH20")), so it uses the witness carrier.
//
// This module only plans. Sending a DEPLOY with a burn is a spend, like a
// transfer: it waits for the circuit's reference keys (npk, nullifier, EdDSA)
// and the `ct` sealing format.

import { serializeEnvelope, CodecError, PAY_MODE, PROOF_BYTES } from './sh20.js';
import { GENESIS } from './profile.js';

const U32 = 2 ** 32 - 1;
const U64 = 2n ** 64n - 1n;
const PAYSCRIPT_MAX = 34;

/** Same rules as the indexer, plus the ticker being free. `nextHeight` = the first block the DEPLOY can land in. */
export function deployProblems(d, { nextHeight, taken = [] }) {
  const p = [];
  if (!/^[A-Z0-9]{4}$/.test(d.ticker)) p.push('the ticker is 4 characters, A–Z and 0–9');
  else if (d.ticker === GENESIS.ticker) p.push(`${GENESIS.ticker} is the genesis token: it is never deployed`);
  else if (taken.includes(d.ticker)) p.push(`${d.ticker} is already deployed`);
  for (const k of ['max', 'lim', 'pre', 'price']) if (typeof d[k] !== 'bigint' || d[k] < 0n || d[k] > U64) p.push(`${k} must be a whole number below 2^64`);
  for (const k of ['start', 'end', 'unlock']) if (!Number.isInteger(d[k]) || d[k] < 0 || d[k] > U32) p.push(`${k} must be a block height`);
  if (p.length) return p;
  if (d.max <= 0n || d.lim <= 0n) p.push('max and the amount per mint must be positive');
  else {
    if (d.pre >= d.max) p.push('the team allocation must leave a public mint (pre < max)');
    else if ((d.max - d.pre) % d.lim !== 0n) p.push('max − pre must be a multiple of the amount per mint');
  }
  if (Number.isInteger(nextHeight) && d.start <= nextHeight) p.push(`the mint must start after the DEPLOY block (after ${nextHeight}; leave a margin, it may confirm later)`);
  if (d.end !== 0 && d.end < d.start) p.push('the mint ends before it starts');
  if (d.unlock < d.start) p.push('the team unlock is before the mint starts');
  if (![PAY_MODE.NONE, PAY_MODE.BURN, PAY_MODE.PAY].includes(d.payMode)) p.push('unknown payment mode');
  if (d.payMode === PAY_MODE.NONE && d.price !== 0n) p.push('a free mint has price 0');
  if (d.payMode !== PAY_MODE.NONE && d.price <= 0n) p.push('the price must be positive');
  if (d.payMode === PAY_MODE.PAY && !d.payScript?.length) p.push('payment to an address needs the address');
  if (d.payMode !== PAY_MODE.PAY && d.payScript?.length) p.push('only a payment to an address has a payScript');
  if (d.payScript?.length > PAYSCRIPT_MAX) p.push(`the payment script is longer than ${PAYSCRIPT_MAX} bytes`);
  return p;
}

// Placeholders with the real sizes (wire v0.3: 32-byte pk_eph, a 480-byte proof with no length
// field): the bytes of a DEPLOY do not depend on their values. Nothing here is sealed or sent.
const dummySpend = () => ({
  anchorHeight: 0,
  nf: [1n, 1n],
  outs: [0, 1, 2].map(() => ({ leaf: 1n, pkEph: Buffer.alloc(32), ct: Buffer.alloc(28) })), // v0.3: X25519 pk_eph, 32 bytes
  proof: Buffer.alloc(PROOF_BYTES),
});

/** Envelope size of this DEPLOY: with the team opening if pre > 0, and the spend if it burns. */
export function deployBytes(d, { burn }) {
  try {
    return serializeEnvelope({
      type: 'DEPLOY', ...d, payScript: Buffer.from(d.payScript ?? []),
      team: d.pre > 0n ? { npk: 1n } : null,
      spend: burn ? dummySpend() : null,
    }).length;
  } catch (e) {
    if (e instanceof CodecError) return null;
    throw e;
  }
}

/**
 * Which of the deployer's SH20 notes can pay a burn of D: a spend has two inputs,
 * so one note of at least D, or two that add up to D. Only notes known unspent count.
 */
export function burnInputs(notes, D) {
  const usable = notes
    .filter((n) => n.ticker === GENESIS.ticker && n.status === 'in tree' && n.spent === 'no')
    .sort((a, b) => (BigInt(b.v) > BigInt(a.v) ? 1 : BigInt(b.v) < BigInt(a.v) ? -1 : 0));
  const total = usable.reduce((s, n) => s + BigInt(n.v), 0n);
  let pick = null;
  const one = [...usable].reverse().find((n) => BigInt(n.v) >= D); // smallest single note that covers D
  if (one) pick = [one];
  else if (usable.length >= 2 && BigInt(usable[0].v) + BigInt(usable[1].v) >= D) pick = usable.slice(0, 2);
  return { total, count: usable.length, pick };
}

/**
 * Everything the deploy screen shows. `deployBurn` is the profile's D (from the
 * indexers, cross-checked), null when unknown.
 */
export function planDeploy(d, { nextHeight, taken, deployBurn, notes }) {
  const problems = deployProblems(d, { nextHeight, taken });
  const burn = deployBurn === null || deployBurn === undefined ? null : BigInt(deployBurn);
  const bytes = problems.length ? null : deployBytes(d, { burn: burn !== 0n });
  const plan = {
    problems,
    burn, // D SH20, or 0n, or null (unknown)
    carrier: burn === 0n ? 'OP_RETURN' : 'witness',
    proof: burn !== 0n, // a burn needs a spend proof
    bytes,
    mints: !problems.length ? (d.max - d.pre) / d.lim : null,
    inputs: burn ? burnInputs(notes ?? [], burn) : null,
  };
  return plan;
}
