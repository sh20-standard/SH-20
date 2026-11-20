// Before a mint: do not take the indexer's word for the mint terms.
// The vault fetches the DEPLOY transaction named by the indexer (deployTxid)
// from Esplora, decodes its envelope with the indexer's own carrier and codec,
// and refuses the mint if the terms it would pay against differ.
//
// This catches an indexer that lies about a real DEPLOY (for example a payScript
// of its own). Since spec v0.2 the MINT names its token by ticker and the note
// id is t = tickerT(ticker), both fixed by the DEPLOY itself, so no number from
// the indexer enters the mint. What it cannot see is which DEPLOY of a ticker
// came first (a later, rejected one can be named): that needs the whole history,
// so the vault compares several independent indexers (consensus.js).
//
// The genesis token SH20 has no DEPLOY: its terms are profile constants, and the
// vault checks them against its own copy (profile.js).

import { extractEnvelope, parseEnvelope, tickerT } from './sh20.js';
import { GENESIS, ACTIVATION_HEIGHT } from './profile.js';
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
export function deployMismatches(token, rawHex, height) {
  if (!token.deployTxid) return ['the indexer gives no deployTxid'];
  if (token.deployHeight === null || token.deployHeight === undefined) return ['the indexer gives no deployHeight'];
  if (!Number.isInteger(height)) return ['the DEPLOY confirmation height is unknown'];
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
  if (token.t !== null && token.t !== undefined && BigInt(token.t) !== tickerT(env.ticker)) {
    return [`t: the ticker gives ${tickerT(env.ticker)}, indexer says ${token.t}`];
  }
  const onChain = { ...env, payScript: toHex(env.payScript) };
  const out = [];
  for (const k of FIELDS) {
    const a = String(onChain[k]);
    const b = String(token[k]);
    if (a !== b) out.push(`${k}: chain says ${a || '(empty)'}, indexer says ${b || '(empty)'}`);
  }
  if (Number(token.deployHeight) !== height) {
    out.push(`deploy height: chain says ${height}, indexer says ${token.deployHeight}`);
  }
  return out;
}

/**
 * Compares the indexer's genesis token with the profile constants: its start is the vault's own
 * activation height (profile.js), never the one an indexer reports.
 */
export function genesisMismatches(token) {
  if (token.ticker !== GENESIS.ticker) return [`only ${GENESIS.ticker} is a genesis token; ${token.ticker} needs a DEPLOY`];
  const out = [];
  if (token.genesis !== true) out.push('the indexer does not mark it as the genesis token');
  if (token.deployTxid !== null) out.push(`the genesis token has no DEPLOY, indexer names ${token.deployTxid}`);
  if (token.t !== null && token.t !== undefined && BigInt(token.t) !== tickerT(GENESIS.ticker)) out.push(`t: the ticker gives ${tickerT(GENESIS.ticker)}, indexer says ${token.t}`);
  const want = { ...GENESIS, start: ACTIVATION_HEIGHT };
  for (const k of ['max', 'lim', 'pre', 'start', 'end', 'price', 'payMode', 'payScript']) {
    const a = String(want[k]);
    const b = String(token[k]);
    if (a !== b) out.push(`${k}: profile says ${a || '(empty)'}, indexer says ${b || '(empty)'}`);
  }
  return out;
}

/**
 * Throws unless the token's mint terms are the chain's: the DEPLOY transaction for
 * a deployed token, the profile constants for SH20. A token the indexer calls
 * genesis but is not SH20, or SH20 shown with a DEPLOY, is refused.
 */
export async function verifyMintTerms(esplora, token) {
  if (token.ticker === GENESIS.ticker || token.genesis) {
    const bad = genesisMismatches(token);
    if (bad.length) throw new Error(`refusing to mint ${token.ticker}: the indexer disagrees with the genesis profile (${bad.join('; ')})`);
    return 'genesis';
  }
  await verifyDeploy(esplora, token);
  return 'deploy';
}

/** Fetches deployTxid from Esplora and throws if the indexer's terms are not the chain's. */
export async function verifyDeploy(esplora, token) {
  const [hex, status] = await Promise.all([esplora.txHex(token.deployTxid), esplora.txStatus(token.deployTxid)]);
  if (!status?.confirmed) throw new Error('the DEPLOY transaction is not confirmed');
  const bad = deployMismatches(token, hex, status.block_height);
  if (bad.length) throw new Error(`refusing to mint ${token.ticker}: the indexer disagrees with the DEPLOY on chain (${bad.join('; ')})`);
}
