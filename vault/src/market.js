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
import { opReturnScript, parseTx, txid as txidOf, scriptType, dustLimit, addressToScript, standardPayee } from './btc.js';
import { sha256 } from './hash.js';
import { concat, fromHex, toHex, utf8 } from './bytes.js';
import { spendFrom, shuffled } from './send.js';
import { publicInputs } from './spend.js';
import { frHex } from './fr.js';
import { payDepthProblem } from './consensus.js';

export const LOCK_SATS = 330n; // MIN_LOCK_SATS of the indexer
const OFFER_SEQUENCE = 0xfffffffd;
const OFFER_VERSION = 2;
const OFFER_LOCKTIME = 0; // an offer fixes the version and locktime of the transaction that takes it

/**
 * Why a spend taking `amount` of a ticker out of the pool (a BURN, a LIST, the DEPLOY burn of D
 * SH20) would be rejected by the turnstile of SPEC-WIRE §5, from what each indexer reports in
 * /token/:ticker; null when every one has room. Checked before proving: a rejected spend's fees
 * are lost. `tokens` are normToken records, one per indexer that answered.
 */
export function poolProblem(tokens, ticker, amount, what) {
  if (!tokens.length) return `no indexer reports ${ticker}`;
  if (tokens.some((t) => t.pool === null)) return `an indexer does not report the pool of ${ticker} (it predates the turnstile of SPEC-WIRE §5), so the vault cannot tell whether a ${what} would be accepted`;
  const pool = tokens.reduce((m, t) => (t.pool < m ? t.pool : m), tokens[0].pool);
  if (BigInt(amount) > pool) {
    return `the shielded pool holds only ${pool} ${ticker}: a ${what} of ${amount} would be rejected by the indexers (SPEC-WIRE §5, the turnstile), and its fees lost`;
  }
  return null;
}

/** A BURN of `amount` of `ticker`: a spend with vPub = amount, tPub = t(ticker). */
export async function planBurn({ vault, sync, tip, ticker, amount }) {
  const v = BigInt(amount);
  if (v <= 0n) throw new Error('the amount must be positive');
  return spendFrom({
    vault, sync, tip, ticker, need: v, vPub: v, tPub: tickerT(ticker),
    outputs: ({ change, me }) => shuffled([{ address: me, v: change }, { address: me, v: 0n }, { address: me, v: 0n }]),
    envelope: (spend) => ({ type: 'BURN', ticker, vPub: v, spend }),
  });
}

/**
 * A LIST of `amount` of `ticker` for `price` sats paid to `payScript`. The lock is output 0 of the
 * reveal, `OP_1 <lockKey>`; `lockKey` (its 32-byte x-only output key) is in the LIST's signed body
 * (SPEC-WIRE §4, PR #20), so a copy of the envelope in another transaction cannot point the lock at
 * a key its copier holds.
 */
export async function planList({ vault, sync, tip, ticker, amount, price, payScript, lockKey }) {
  const v = BigInt(amount);
  const p = BigInt(price);
  if (!(lockKey instanceof Uint8Array) || lockKey.length !== 32) throw new Error('a LIST needs the 32-byte key of its lock');
  if (v <= 0n || p <= 0n) throw new Error('the amount and the price must be positive');
  if (p < dustLimit(payScript)) throw new Error(`a price below ${dustLimit(payScript)} sats could not be paid in a standard transaction`);
  return spendFrom({
    vault, sync, tip, ticker, need: v, vPub: v, tPub: tickerT(ticker),
    outputs: ({ change, me }) => shuffled([{ address: me, v: change }, { address: me, v: 0n }, { address: me, v: 0n }]),
    envelope: (spend) => ({ type: 'LIST', ticker, amount: v, price: p, lockVout: 0, lockKey: Buffer.from(lockKey), payScript: Buffer.from(payScript), spend }),
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
  // the lock must be OP_1 <lockKey>, the key the LIST's signed body names (the indexers refuse it otherwise)
  if (toHex(lock.script.subarray(2)) !== toHex(env.lockKey)) throw new Error('the lock output is not P2TR to the LIST\'s lockKey');
  const l = {
    listTxid, ticker: env.ticker, amount: env.amount, price: env.price, payScript: Uint8Array.from(env.payScript),
    lockVout: env.lockVout, lockValue: lock.value, lockScript: lock.script, lockKey: Uint8Array.from(env.lockKey),
  };
  // the envelope's spend and signed body, for offerTerms: the witness that carries them is not under the txid
  Object.defineProperty(l, 'envelope', { value: { env, body: parseEnvelope(found.bytes).body } });
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
  l.height = Number.isInteger(indexed?.height) ? indexed.height : null; // the LIST's block, as the indexers give it (vault-1)
  return l;
}

/**
 * The terms an offer may be signed for (docs/AUDIT.md §8.2). `l` is listingFromChain's reading of
 * the LIST, from the bytes this vault sent or from Esplora. A txid does not cover the witness, and
 * the LIST envelope is in the witness: a server can return the listing's transaction with another
 * envelope (another price, another payee) under the same txid. So the vault signs only terms it
 * can vouch for:
 *
 *   'record'  a listing this vault sent (rec.source === 'sent'): the ticker, amount, price and payee
 *             of its own record, which the chain and the indexer (listingFromChain) must repeat;
 *             any difference is refused
 *   'proof'   a listing found again after a restore: one of the envelope's nullifiers is that of a
 *             note of this vault (`ownNullifiers`, hex), and its proof verifies for its body against
 *             the root at its anchor (`rootAt`, from the local tree). Only the owner of that note can
 *             have signed that body; the other input may be an unused one, whose fresh keys no
 *             wallet recognises
 *             If that note is the vault's and the root is known but the proof does not verify, the
 *             terms are not the ones the vault signed: refused, as a difference with the record is
 *   'ask'     the vault cannot check: no nullifier of its notes, a local tree that does not reach the
 *             anchor, or a verifier that cannot run (`verify` throws). `why` says which, and the page
 *             shows the price and payee and asks
 *
 * The lock key must be the vault's own for the record's index in every case. Returns { l, vouched, why }.
 */
export async function offerTerms({ rec, l, lockKey, ownNullifiers, rootAt, verify }) {
  if (toHex(l.lockKey) !== toHex(lockKey)) throw new Error(`not signed: the LIST locks to another key than this vault's lock #${rec.lockIndex}`);
  if (rec.source === 'sent') {
    const bad = [];
    if (l.ticker !== rec.ticker) bad.push(`ticker ${l.ticker}, not ${rec.ticker}`);
    if (l.amount !== BigInt(rec.amount)) bad.push(`amount ${l.amount}, not ${rec.amount}`);
    if (l.price !== BigInt(rec.price)) bad.push(`price ${l.price} sats, not ${rec.price}`);
    if (toHex(l.payScript) !== rec.payScript) bad.push(`payee ${toHex(l.payScript)}, not ${rec.payScript}`);
    if (bad.length) throw new Error(`not signed: the listing on chain and at the indexer differs from the one this vault sent (${bad.join('; ')})`);
    return { l, vouched: 'record', why: null };
  }
  const { env, body } = l.envelope ?? {};
  if (!env?.spend || !body) return { l, vouched: 'ask', why: 'the LIST envelope could not be read again' };
  if (!env.spend.nf.some((x) => ownNullifiers.has(frHex(x)))) {
    return { l, vouched: 'ask', why: 'the LIST spends no note this vault knows (sync first, or the listing was made from notes this vault never held)' };
  }
  const root = rootAt(env.spend.anchorHeight);
  if (root === undefined || root === null) return { l, vouched: 'ask', why: `the local tree does not reach block ${env.spend.anchorHeight}, the LIST's anchor (sync first)` };
  const publics = publicInputs({ root, env, body, vPub: env.amount, tPub: tickerT(env.ticker) });
  let ok;
  try {
    ok = await verify(publics, env.spend.proof);
  } catch (e) {
    return { l, vouched: 'ask', why: `the LIST's proof could not be checked (${e.message})` };
  }
  // a note of this vault, the root at the anchor, and a proof that fails: the body is not the one this vault signed
  if (ok !== true) throw new Error('not signed: the LIST\'s proof does not verify for the terms on chain, so they are not the ones this vault signed');
  return { l, vouched: 'proof', why: null };
}

// ---- TAKE, cancel, CLAIM -----------------------------------------------------------------------

const takeOutput = (npk) => ({ value: 0n, script: opReturnScript(serializeEnvelope({ type: 'TAKE', npk })) });

/**
 * Why a TAKE cannot pay this listing's payee, or null: a payScript that is not one of the standard
 * templates (btc.js PAYEE_TYPES) makes the TAKE non-standard, and the network would not relay it.
 */
export function payeeProblem(payScript) {
  if (standardPayee(payScript)) return null;
  return `the seller's payee is the script ${toHex(payScript)}, not a standard address (P2PKH, P2SH, P2WPKH, P2WSH or P2TR): the network would not relay a transaction that pays it`;
}

/** The buyer's transaction: the signed lock at input 0, the price at output 0, the TAKE, the buyer's inputs. */
export function buildTake({ l, sig, npk, payer, utxos, feeRate, tipHeight }) {
  const bad = payeeProblem(l.payScript);
  if (bad) throw new Error(`not bought: ${bad}`);
  if (!offerValid(l, sig)) throw new Error('the offer\'s signature is not the lock key\'s, for this price and payee');
  // the TAKE pays the seller whatever the indexers later decide: the LIST must be PAY_DEPTH deep first (vault-1)
  const shallow = payDepthProblem('the listing', l.height, tipHeight);
  if (shallow) throw new Error(`not bought yet: ${shallow}`);
  return buildFunded({
    fixed: [{ value: l.price, script: l.payScript }, takeOutput(npk)],
    pre: [{ txid: l.listTxid, vout: l.lockVout, sequence: OFFER_SEQUENCE, value: l.lockValue, script: l.lockScript, witness: [sig] }],
    payer, utxos, feeRate, tipHeight, locktime: OFFER_LOCKTIME,
  });
}

/**
 * Where a cancel sends its change: the first of the wallet's addresses that is not the listing's
 * payee. A TAKE whose outputs pay the payee at least the price counts as SOLD (to the seller itself),
 * so change on the payee's address can turn a cancel into a sale. With one address only, it stays there.
 */
export function cancelChangeScript(l, payer) {
  for (const a of [payer.address, payer.otherAddress].filter(Boolean)) {
    const s = addressToScript(a);
    if (toHex(s) !== toHex(l.payScript)) return s;
  }
  return addressToScript(payer.address);
}

/** The seller taking its own listing back: a TAKE that spends the lock without the offer. */
export function buildCancel({ l, lockSecret, npk, payer, utxos, feeRate, tipHeight }) {
  return buildFunded({
    fixed: [takeOutput(npk)],
    pre: [{ txid: l.listTxid, vout: l.lockVout, sequence: OFFER_SEQUENCE, value: l.lockValue, script: l.lockScript }],
    payer, utxos, feeRate, tipHeight, changeScript: cancelChangeScript(l, payer),
    sign: (tx, k, prevouts) => [signKeyPath(lockSecret, sigMsg(tx, k, prevouts, null, SIGHASH_DEFAULT))],
  });
}

/**
 * Why a CLAIM of listing `l` would be rejected, from the chain alone: its lock must be spent, by a
 * transaction that carries no TAKE (else the listing is SOLD or CANCELLED, not CLOSED). `spender`
 * is the raw hex of the transaction that spent the lock, or null if the lock is unspent.
 */
export function claimProblem(l, spender) {
  if (!spender) return 'the lock is not spent: the listing is not CLOSED';
  const tx = parseTx(fromHex(spender));
  if (!tx.vin.some((i) => i.txid === l.listTxid && i.vout === l.lockVout)) return 'Esplora named a transaction that does not spend the lock';
  const found = extractEnvelope({
    vin: tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
    vout: tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
  });
  if (found.bytes) {
    try {
      if (parseEnvelope(found.bytes).env.type === 'TAKE') return 'the lock was spent by a TAKE: the listing is SOLD or CANCELLED, not CLOSED';
    } catch {}
  }
  return null;
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
