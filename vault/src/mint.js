// MINT: one transaction, OP_RETURN carrier (docs/SPEC-WIRE.md §3, §4, §5).
//
//   vout 0  OP_RETURN <"SH20" 00 02 ticker npk [k]>      value = k × price if payMode 1 (burn), else 0
//   vout 1  payScript, value = k × price                 only if payMode 2
//   vout n  change to the payer                          only if above dust
//
// A batch mint (wire v0.3) asks for k mints, 2 to 10, with one more byte: one note
// of k × lim, paid k × price. payMode 1 burns the price on the envelope output
// itself, so a burn mint has no extra output. Inputs come from the payer's
// address, as few as possible.

import { serializeEnvelope, PAY_MODE, MINT_BATCH_MAX } from './sh20.js';
import {
  addressToScript, scriptType, dustLimit, opReturnScript, p2shP2wpkhRedeem, estimateVsize, createPsbt, SUPPORTED_INPUTS,
} from './btc.js';
import { fromHex } from './bytes.js';
import { payDepthProblem } from './consensus.js';

export const MAX_FEE_RATE = 1000; // sat/vB: refuse anything above, whoever typed it

const SEQUENCE = 0xfffffffd; // RBF on, no relative lock

/**
 * Reasons a MINT confirming at `nextHeight` would be rejected (rejected mints are not refunded).
 * `token` as normalised by api.js.
 */
export function mintProblems(token, nextHeight, k = 1) {
  const p = [];
  if (!token) return ['unknown ticker'];
  if (!Number.isInteger(k) || k < 1 || k > MINT_BATCH_MAX) return [`mint 1 to ${MINT_BATCH_MAX} at once`];
  if (nextHeight < token.start) p.push(`mint opens at block ${token.start} (next block is ${nextHeight})`);
  if (token.end !== 0 && nextHeight > token.end) p.push(`mint closed at block ${token.end}`);
  const total = (token.max - token.pre) / token.lim;
  if (token.mints >= total) p.push('sold out');
  // an indexer gives a late batch only what is left, and keeps the overpayment: never ask for more
  else if (BigInt(k) > total - token.mints) p.push(`only ${total - token.mints} mint(s) left`);
  if (token.payMode === PAY_MODE.PAY && !token.payScript) p.push('token has payMode 2 but no payScript');
  return p;
}

export const mintsLeft = (t) => (t.max - t.pre) / t.lim - t.mints;

function fixedOutputs(token, envelope, k) {
  const price = token.price * BigInt(k);
  const outs = [{ value: token.payMode === PAY_MODE.BURN ? price : 0n, script: opReturnScript(envelope) }];
  if (token.payMode === PAY_MODE.PAY) {
    const script = fromHex(token.payScript);
    const d = dustLimit(script);
    outs.push({ value: price > d ? price : d, script }); // ≥ k × price is accepted; never below dust
  }
  return outs;
}

/**
 * Smallest set of UTXOs paying `fixed` outputs plus the fee at `feeRate`,
 * with a change output only when it is above dust.
 */
export function selectCoins(utxos, fixed, inType, changeScript, feeRate, pre = []) {
  // `pre`: inputs already in the transaction (P2TR key path, signed): they add their value and weight
  const sumFixed = fixed.reduce((s, o) => s + o.value, 0n) - pre.reduce((s, i) => s + i.value, 0n);
  const scripts = fixed.map((o) => o.script);
  const fee = (n, change) => BigInt(Math.ceil(feeRate * estimateVsize([...pre.map(() => 'p2tr'), ...Array(n).fill(inType)], change ? [...scripts, changeScript] : scripts)));
  const dust = dustLimit(changeScript);
  const settle = (picked) => {
    const total = picked.reduce((s, u) => s + u.value, 0n);
    const n = picked.length;
    if (total >= sumFixed + fee(n, true) + dust) return { picked, change: total - sumFixed - fee(n, true), fee: fee(n, true) };
    if (total >= sumFixed + fee(n, false)) return { picked, change: 0n, fee: total - sumFixed };
    return null;
  };
  const asc = [...utxos].sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
  for (const u of asc) {
    const s = settle([u]);
    if (s) return s; // smallest single input that pays everything
  }
  const picked = [];
  for (const u of asc.reverse()) {
    picked.push(u);
    const s = settle(picked);
    if (s) return s;
  }
  const have = utxos.reduce((s, u) => s + u.value, 0n);
  throw new Error(`not enough BTC: need about ${sumFixed + fee(Math.max(1, utxos.length), false)} sats, have ${have}`);
}

/**
 * Why a MINT of `token` does not go out yet with the chain at `tip` (docs/audit/2026-11-24-vault.md, vault-1):
 * one that pays the deployer or burns its price waits until the DEPLOY is PAY_DEPTH blocks deep, since a
 * reorg that moves the DEPLOY can make it refused, and the price paid for a ticker that does not exist.
 * A free mint risks its network fee alone, and SH20 has no DEPLOY: neither waits. Null when it may go.
 */
export function mintDepthProblem(token, tip) {
  if (token.genesis || token.payMode === PAY_MODE.NONE) return null;
  const at = token.deployHeight === null || token.deployHeight === undefined ? null : Number(token.deployHeight);
  return payDepthProblem(`the DEPLOY of ${token.ticker}`, at, tip);
}

/**
 * Builds the MINT transaction and its PSBT.
 * payer = { address, publicKey (hex, optional for p2wpkh) }
 * utxos = [{ txid, vout, value: bigint }] at payer.address
 * opening = { npk } from the vault (a public note: rho = 0)
 * k = how many mints at once (1 to 10): one note of k × lim for k × price
 */
export function buildMint({ token, opening, payer, utxos, feeRate, tipHeight, k = 1 }) {
  const problems = mintProblems(token, tipHeight + 1, k);
  if (problems.length) throw new Error(problems.join('; '));
  const shallow = mintDepthProblem(token, tipHeight);
  if (shallow) throw new Error(shallow);
  // 42 bytes: npk alone, rho = 0 (v0.3); 43 with the count byte when k > 1
  const envelope = serializeEnvelope({ type: 'MINT', ticker: token.ticker, npk: opening.npk, k });
  const fixed = fixedOutputs(token, envelope, k);
  return {
    ...buildFunded({ fixed, payer, utxos, feeRate, tipHeight }),
    envelope,
    k,
    v: token.lim * BigInt(k), // the note's amount
    price: token.payMode === PAY_MODE.NONE ? 0n : fixed[token.payMode === PAY_MODE.BURN ? 0 : 1].value,
  };
}

/**
 * A transaction paying the `fixed` outputs from the payer's address, with change, and its PSBT for
 * the wallet: the MINT, the commit of a proof-carrying envelope, a DEPLOY without a burn.
 * payer = { address, publicKey (hex, optional for p2wpkh) }; utxos = [{ txid, vout, value }] there.
 */
export function buildFunded({ fixed, payer, utxos, feeRate, tipHeight, pre = [], locktime = tipHeight, sign, changeScript }) {
  if (!(feeRate > 0) || feeRate > MAX_FEE_RATE) throw new Error(`fee rate must be between 0 and ${MAX_FEE_RATE} sat/vB`);
  const payScript = addressToScript(payer.address);
  const inType = scriptType(payScript);
  if (!SUPPORTED_INPUTS.includes(inType)) throw new Error(`pay from a native segwit, nested segwit or taproot address, not ${inType}`);
  const changeTo = changeScript ?? payScript; // the payer's address unless told otherwise (a cancel)
  const { picked, change, fee } = selectCoins(utxos, fixed, inType, changeTo, feeRate, pre);

  // `pre` inputs come first, at the indexes their signatures expect (a seller's lock at 0)
  const tx = {
    version: 2,
    locktime, // the tip by default: anti fee-sniping, like Bitcoin Core; valid in the next block
    vin: [
      ...pre.map((i) => ({ txid: i.txid, vout: i.vout, sequence: i.sequence, scriptSig: new Uint8Array(0), witness: i.witness ?? [] })),
      ...picked.map((u) => ({ txid: u.txid, vout: u.vout, sequence: SEQUENCE, scriptSig: new Uint8Array(0), witness: [] })),
    ],
    vout: change > 0n ? [...fixed, { value: change, script: changeTo }] : fixed,
  };
  // a `pre` input signed over the whole transaction (SIGHASH_DEFAULT) is signed now that it is final
  const prevouts = [...pre.map((i) => ({ value: i.value, script: i.script })), ...picked.map((u) => ({ value: u.value, script: payScript }))];
  if (sign) pre.forEach((i, k) => { if (!i.witness) tx.vin[k].witness = sign(tx, k, prevouts); });

  const pub = payer.publicKey ? fromHex(payer.publicKey) : null;
  const meta = [...pre.map((i, k) => ({ witnessUtxo: { value: i.value, script: i.script }, finalScriptWitness: tx.vin[k].witness })), ...picked.map((u) => {
    const m = { witnessUtxo: { value: u.value, script: payScript } };
    if (inType === 'p2sh') {
      if (!pub || pub.length !== 33) throw new Error('nested segwit needs the 33-byte public key from the wallet');
      m.redeemScript = p2shP2wpkhRedeem(pub);
    }
    if (inType === 'p2tr' && pub) m.tapInternalKey = pub.length === 33 ? pub.subarray(1) : pub;
    return m;
  })];

  return {
    tx,
    psbt: createPsbt(tx, meta),
    fee,
    vsizeEstimate: estimateVsize([...pre.map(() => 'p2tr'), ...picked.map(() => inType)], tx.vout.map((o) => o.script)),
    inputIndexes: picked.map((_, i) => pre.length + i), // the wallet signs its own inputs only
  };
}
