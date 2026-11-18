// MINT: one transaction, OP_RETURN carrier (docs/SPEC-WIRE.md §3, §4, §5).
//
//   vout 0  OP_RETURN <"SH20" 00 02 ticker opening>     value = price if payMode 1 (burn), else 0
//   vout 1  payScript, value = price                    only if payMode 2
//   vout n  change to the payer                          only if above dust
//
// payMode 1 burns the price on the envelope output itself, so a burn mint has
// no extra output. Inputs come from the payer's address, as few as possible.

import { serializeEnvelope, PAY_MODE } from './sh20.js';
import {
  addressToScript, scriptType, dustLimit, opReturnScript, p2shP2wpkhRedeem, estimateVsize, createPsbt, SUPPORTED_INPUTS,
} from './btc.js';
import { fromHex } from './bytes.js';

export const MAX_FEE_RATE = 1000; // sat/vB: refuse anything above, whoever typed it

const SEQUENCE = 0xfffffffd; // RBF on, no relative lock

/**
 * Reasons a MINT confirming at `nextHeight` would be rejected (rejected mints are not refunded).
 * `token` as normalised by api.js.
 */
export function mintProblems(token, nextHeight) {
  const p = [];
  if (!token) return ['unknown ticker'];
  if (nextHeight < token.start) p.push(`mint opens at block ${token.start} (next block is ${nextHeight})`);
  if (token.end !== 0 && nextHeight > token.end) p.push(`mint closed at block ${token.end}`);
  const total = (token.max - token.pre) / token.lim;
  if (token.mints >= total) p.push('sold out');
  if (token.payMode === PAY_MODE.PAY && !token.payScript) p.push('token has payMode 2 but no payScript');
  return p;
}

export const mintsLeft = (t) => (t.max - t.pre) / t.lim - t.mints;

function fixedOutputs(token, envelope) {
  const outs = [{ value: token.payMode === PAY_MODE.BURN ? token.price : 0n, script: opReturnScript(envelope) }];
  if (token.payMode === PAY_MODE.PAY) {
    const script = fromHex(token.payScript);
    const d = dustLimit(script);
    outs.push({ value: token.price > d ? token.price : d, script }); // ≥ price is accepted; never below dust
  }
  return outs;
}

/**
 * Smallest set of UTXOs paying `fixed` outputs plus the fee at `feeRate`,
 * with a change output only when it is above dust.
 */
export function selectCoins(utxos, fixed, inType, changeScript, feeRate) {
  const sumFixed = fixed.reduce((s, o) => s + o.value, 0n);
  const scripts = fixed.map((o) => o.script);
  const fee = (n, change) => BigInt(Math.ceil(feeRate * estimateVsize(Array(n).fill(inType), change ? [...scripts, changeScript] : scripts)));
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
 * Builds the MINT transaction and its PSBT.
 * payer = { address, publicKey (hex, optional for p2wpkh) }
 * utxos = [{ txid, vout, value: bigint }] at payer.address
 * opening = { npk, rho } from the vault
 */
export function buildMint({ token, opening, payer, utxos, feeRate, tipHeight }) {
  const problems = mintProblems(token, tipHeight + 1);
  if (problems.length) throw new Error(problems.join('; '));
  if (!(feeRate > 0) || feeRate > MAX_FEE_RATE) throw new Error(`fee rate must be between 0 and ${MAX_FEE_RATE} sat/vB`);
  const payScript = addressToScript(payer.address);
  const inType = scriptType(payScript);
  if (!SUPPORTED_INPUTS.includes(inType)) throw new Error(`pay from a native segwit, nested segwit or taproot address, not ${inType}`);

  const envelope = serializeEnvelope({ type: 'MINT', ticker: token.ticker, npk: opening.npk, rho: opening.rho });
  const fixed = fixedOutputs(token, envelope);
  const { picked, change, fee } = selectCoins(utxos, fixed, inType, payScript, feeRate);

  const tx = {
    version: 2,
    locktime: tipHeight, // anti fee-sniping, like Bitcoin Core; valid in the next block
    vin: picked.map((u) => ({ txid: u.txid, vout: u.vout, sequence: SEQUENCE, scriptSig: new Uint8Array(0), witness: [] })),
    vout: change > 0n ? [...fixed, { value: change, script: payScript }] : fixed,
  };

  const pub = payer.publicKey ? fromHex(payer.publicKey) : null;
  const meta = picked.map((u) => {
    const m = { witnessUtxo: { value: u.value, script: payScript } };
    if (inType === 'p2sh') {
      if (!pub || pub.length !== 33) throw new Error('nested segwit needs the 33-byte public key from the wallet');
      m.redeemScript = p2shP2wpkhRedeem(pub);
    }
    if (inType === 'p2tr' && pub) m.tapInternalKey = pub.length === 33 ? pub.subarray(1) : pub;
    return m;
  });

  return {
    tx,
    psbt: createPsbt(tx, meta),
    envelope,
    fee,
    vsizeEstimate: estimateVsize(picked.map(() => inType), tx.vout.map((o) => o.script)),
    price: token.payMode === PAY_MODE.NONE ? 0n : fixed[token.payMode === PAY_MODE.BURN ? 0 : 1].value,
    inputIndexes: picked.map((_, i) => i),
  };
}
