// BURN, and trading tokens for BTC (docs/SPEC-WIRE.md §4–§5, DESIGN.md "Trading"):
//
//   LIST    a spend that moves `amount` out of the pool into a public escrow (vPub = amount,
//           tPub = t(ticker)); its reveal transaction's output 0 is the lock, a P2TR key-path
//           output of a key only this vault holds (330 sats)
//   offer   the seller signs a spend of the lock with SIGHASH_SINGLE | ANYONECANPAY that pays the
//           price to the seller's payScript at the same index; shared as a line of text
//   TAKE    the buyer completes the offer: the lock at input 0, the price at output 0, a TAKE
//           envelope (OP_RETURN, the buyer's npk) and the buyer's own inputs; the tokens become the
//           buyer's public note. A lock can be spent once, so a sale can be neither doubled nor unpaid
//   cancel  a TAKE by the seller itself, without the offer: the tokens come back as its public note
//   CLAIM   if the lock is spent with no TAKE, the listing is CLOSED; the seller claims the tokens
//           back with a BIP340 signature by the lock key over SHA256("sh20/v0/claim" ‖ listTxid ‖ npk)
//
// Lock keys are the vault's own (Vault.lockOutput): HMAC-SHA512("sh20/vault/lock", m ‖ u32le(i)),
// so the 12 words restore them. They are Bitcoin keys of this vault, not note keys: SPEC-NOTES
// does not define them.

import { serializeEnvelope, parseEnvelope, extractEnvelope, tickerT, schnorrSign, schnorrVerify, DOMAIN } from './sh20.js';
import { sigMsg, sigHash, signKeyPath, SIGHASH_DEFAULT, SIGHASH_SINGLE_ANYONECANPAY } from './taproot.js';
import { buildFunded } from './mint.js';
import { opReturnScript, parseTx, txid as txidOf, scriptType, dustLimit } from './btc.js';
import { sha256 } from './hash.js';
import { concat, fromHex, toHex, utf8 } from './bytes.js';
import { spendFrom, shuffled } from './send.js';

export const LOCK_SATS = 330n; // MIN_LOCK_SATS of the indexer
const OFFER_SEQUENCE = 0xfffffffd;
const OFFER_VERSION = 2;
const OFFER_LOCKTIME = 0; // an offer fixes the version and locktime of the transaction that takes it

/** A BURN of `amount` of `ticker`: a spend with vPub = amount, tPub = t(ticker). */
export function planBurn({ vault, sync, tip, ticker, amount }) {
  const v = BigInt(amount);
  if (v <= 0n) throw new Error('the amount must be positive');
  return spendFrom({
    vault, sync, tip, ticker, need: v, vPub: v, tPub: tickerT(ticker),
    outputs: ({ change, me }) => shuffled([{ address: me, v: change }, { address: me, v: 0n }, { address: me, v: 0n }]),
    envelope: (spend) => ({ type: 'BURN', ticker, vPub: v, spend }),
  });
}

/** A LIST of `amount` of `ticker` for `price` sats paid to `payScript`; the lock is `lockScript` at output 0. */
export function planList({ vault, sync, tip, ticker, amount, price, payScript }) {
  const v = BigInt(amount);
  const p = BigInt(price);
  if (v <= 0n || p <= 0n) throw new Error('the amount and the price must be positive');
  if (p < dustLimit(payScript)) throw new Error(`a price below ${dustLimit(payScript)} sats could not be paid in a standard transaction`);
  return spendFrom({
    vault, sync, tip, ticker, need: v, vPub: v, tPub: tickerT(ticker),
    outputs: ({ change, me }) => shuffled([{ address: me, v: change }, { address: me, v: 0n }, { address: me, v: 0n }]),
    envelope: (spend) => ({ type: 'LIST', ticker, amount: v, price: p, lockVout: 0, payScript: Buffer.from(payScript), spend }),
  });
}

/** The reveal outputs of a LIST: the lock alone. */
export const listOutputs = (lockScript) => [{ value: LOCK_SATS, script: lockScript }];

// ---- offers ----------------------------------------------------------------------------------

/** The part of the taking transaction an offer signs: input 0 (the lock), output 0 (the price). */
function offerSkeleton(l, offerValue) {
  return {
    version: OFFER_VERSION, locktime: OFFER_LOCKTIME,
    vin: [{ txid: l.listTxid, vout: l.lockVout, sequence: OFFER_SEQUENCE }],
    vout: [{ value: l.price, script: l.payScript }],
    prevouts: [{ value: offerValue, script: l.lockScript }],
  };
}

/** The seller's signature of an offer for listing `l` ({ listTxid, lockVout, lockValue, lockScript, price, payScript }). */
export function signOffer(lockSecret, l) {
  const sk = offerSkeleton(l, l.lockValue);
  return signKeyPath(lockSecret, sigMsg(sk, 0, sk.prevouts, null, SIGHASH_SINGLE_ANYONECANPAY), SIGHASH_SINGLE_ANYONECANPAY);
}

/** An offer as one line of text: sh20offer1:<listTxid>:<sig>. */
export const encodeOffer = (listTxid, sig) => `sh20offer1:${listTxid}:${toHex(sig)}`;

export function decodeOffer(text) {
  const m = /^sh20offer1:([0-9a-f]{64}):([0-9a-f]{130})$/.exec(text.trim());
  if (!m) throw new Error('not an SH-20 offer (sh20offer1:<listing>:<signature>)');
  const sig = fromHex(m[2]);
  if (sig[64] !== SIGHASH_SINGLE_ANYONECANPAY) throw new Error('the offer is not signed SIGHASH_SINGLE | ANYONECANPAY');
  return { listTxid: m[1], sig };
}

/** True when `sig` is the lock key's signature of a sale at the listing's price. */
export function offerValid(l, sig) {
  const sk = offerSkeleton(l, l.lockValue);
  const msg = sigHash(sigMsg(sk, 0, sk.prevouts, null, SIGHASH_SINGLE_ANYONECANPAY));
  return sig.length === 65 && sig[64] === SIGHASH_SINGLE_ANYONECANPAY && schnorrVerify(Buffer.from(l.lockKey), Buffer.from(msg), Buffer.from(sig.subarray(0, 64)));
}

/**
 * The listing as the chain shows it: the LIST envelope of `listTxid` (fetched with `txHex`) and its
 * lock output. Throws if the transaction is not a LIST, or if the indexer's listing differs from it.
 */
export function listingFromChain(listTxid, rawHex, indexed) {
  const tx = parseTx(fromHex(rawHex));
  if (txidOf(tx) !== listTxid) throw new Error('Esplora returned another transaction than the listing');
  const found = extractEnvelope({
    vin: tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
    vout: tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
  });
  if (!found.bytes) throw new Error('the listing transaction carries no SH-20 envelope');
  const { env } = parseEnvelope(found.bytes);
  if (env.type !== 'LIST') throw new Error(`the listing transaction carries a ${env.type}, not a LIST`);
  const lock = tx.vout[env.lockVout];
  if (!lock || scriptType(lock.script) !== 'p2tr') throw new Error('the listing has no P2TR lock');
  const l = {
    listTxid, ticker: env.ticker, amount: env.amount, price: env.price, payScript: Uint8Array.from(env.payScript),
    lockVout: env.lockVout, lockValue: lock.value, lockScript: lock.script, lockKey: lock.script.subarray(2),
  };
  if (indexed) {
    const bad = [];
    if (indexed.ticker !== l.ticker) bad.push('ticker');
    if (BigInt(indexed.amount) !== l.amount) bad.push('amount');
    if (BigInt(indexed.price) !== l.price) bad.push('price');
    if (indexed.payScript !== toHex(l.payScript)) bad.push('payScript');
    if (indexed.lock !== `${listTxid}:${l.lockVout}`) bad.push('lock');
    if (indexed.lockKey !== toHex(l.lockKey)) bad.push('lockKey');
    if (bad.length) throw new Error(`the indexer's listing differs from the chain: ${bad.join(', ')}`);
  }
  return l;
}

// ---- TAKE, cancel, CLAIM -----------------------------------------------------------------------

const takeOutput = (npk) => ({ value: 0n, script: opReturnScript(serializeEnvelope({ type: 'TAKE', npk })) });

/** The buyer's transaction: the signed lock at input 0, the price at output 0, the TAKE, the buyer's inputs. */
export function buildTake({ l, sig, npk, payer, utxos, feeRate, tipHeight }) {
  if (!offerValid(l, sig)) throw new Error('the offer\'s signature is not the lock key\'s, for this price and payee');
  return buildFunded({
    fixed: [{ value: l.price, script: l.payScript }, takeOutput(npk)],
    pre: [{ txid: l.listTxid, vout: l.lockVout, sequence: OFFER_SEQUENCE, value: l.lockValue, script: l.lockScript, witness: [sig] }],
    payer, utxos, feeRate, tipHeight, locktime: OFFER_LOCKTIME,
  });
}

/** The seller taking its own listing back: a TAKE that spends the lock without the offer. */
export function buildCancel({ l, lockSecret, npk, payer, utxos, feeRate, tipHeight }) {
  return buildFunded({
    fixed: [takeOutput(npk)],
    pre: [{ txid: l.listTxid, vout: l.lockVout, sequence: OFFER_SEQUENCE, value: l.lockValue, script: l.lockScript }],
    payer, utxos, feeRate, tipHeight,
    sign: (tx, k, prevouts) => [signKeyPath(lockSecret, sigMsg(tx, k, prevouts, null, SIGHASH_DEFAULT))],
  });
}

/** What the lock key signs to CLAIM a CLOSED listing (Indexer.claimMessage). */
export function claimMessage(listTxid, npk) {
  const le = new Uint8Array(32);
  for (let i = 0, x = BigInt(npk); i < 32; i++, x >>= 8n) le[i] = Number(x & 0xffn);
  return sha256(concat(utf8(DOMAIN.CLAIM), fromHex(listTxid), le));
}

/** The CLAIM of a CLOSED listing back to the public note `npk`: one OP_RETURN transaction. */
export function buildClaim({ listTxid, lockSecret, npk, payer, utxos, feeRate, tipHeight }) {
  const sig = new Uint8Array(schnorrSign(lockSecret, Buffer.from(claimMessage(listTxid, npk)), crypto.getRandomValues(new Uint8Array(32))));
  const envelope = serializeEnvelope({ type: 'CLAIM', listTxid, npk, sig: Buffer.from(sig) });
  return { ...buildFunded({ fixed: [{ value: 0n, script: opReturnScript(envelope) }], payer, utxos, feeRate, tipHeight }), envelope };
}
