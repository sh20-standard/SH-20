// Before a mint: do not take the indexer's word for the mint terms.
// The vault fetches the DEPLOY transaction named by the indexer (deployTxid)
// from Esplora, decodes its envelope with the indexer's own carrier and codec,
// and refuses the mint if the terms it would pay against differ.
//
// This catches an indexer that lies about a real DEPLOY (for example a payScript
// of its own). It does NOT verify:
//  - tokenNum, which is not in the envelope: it is the DEPLOY's rank among the
//    accepted ones. A lying indexer can pair the true terms of one DEPLOY with
//    the tokenNum of another token, and honest indexers would then credit (or
//    reject) the mint for that other token;
//  - which DEPLOY of a ticker came first (a later, rejected one can be named).
// Both need the whole history: compare several independent indexers (digest,
// tokenNum) until the vault can do that itself.

import { extractEnvelope, parseEnvelope } from './sh20.js';
import { parseTx, txid as txidOf } from './btc.js';
import { fromHex, toHex } from './bytes.js';

/** Indexer transaction format, as carrier.js expects it. */
const toCarrierTx = (tx) => ({
  vin: tx.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w)) })),
  vout: tx.vout.map((o) => ({ value: o.value, script: Buffer.from(o.script) })),
});

const FIELDS = ['ticker', 'max', 'lim', 'pre', 'start', 'end', 'price', 'payMode', 'payScript'];

/**
 * Compares the DEPLOY in `rawHex` with the indexer's `token`. Returns the list
 * of disagreements (empty when everything matches).
 */
export function deployMismatches(token, rawHex, height = null) {
  if (!token.deployTxid) return ['the indexer gives no deployTxid'];
  const tx = parseTx(fromHex(rawHex));
  if (txidOf(tx) !== token.deployTxid) return ['Esplora returned another transaction than deployTxid'];
  const found = extractEnvelope(toCarrierTx(tx));
  if (!found.bytes) return [`deployTxid carries no valid SH-20 envelope (${found.error ?? 'none'})`];
  let env;
  try {
    env = parseEnvelope(found.bytes).env;
  } catch (e) {
    return [`deployTxid envelope does not parse: ${e.message}`];
  }
  if (env.type !== 'DEPLOY') return [`deployTxid carries a ${env.type}, not a DEPLOY`];
  const onChain = { ...env, payScript: toHex(env.payScript) };
  const out = [];
  for (const k of FIELDS) {
    const a = String(onChain[k]);
    const b = String(token[k]);
    if (a !== b) out.push(`${k}: chain says ${a || '(empty)'}, indexer says ${b || '(empty)'}`);
  }
  if (height !== null && token.deployHeight !== null && Number(token.deployHeight) !== height) {
    out.push(`deploy height: chain says ${height}, indexer says ${token.deployHeight}`);
  }
  return out;
}

/** Fetches deployTxid from Esplora and throws if the indexer's terms are not the chain's. */
export async function verifyDeploy(esplora, token) {
  const [hex, status] = await Promise.all([esplora.txHex(token.deployTxid), esplora.txStatus(token.deployTxid)]);
  if (!status?.confirmed) throw new Error('the DEPLOY transaction is not confirmed');
  const bad = deployMismatches(token, hex, status.block_height);
  if (bad.length) throw new Error(`refusing to mint ${token.ticker}: the indexer disagrees with the DEPLOY on chain (${bad.join('; ')})`);
}
