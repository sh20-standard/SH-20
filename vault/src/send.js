// Spends from the vault, end to end: a private TRANSFER, and a DEPLOY that burns D SH20.
//
//   plan     choose the notes, seal the three outputs, lay out the envelope, build the witness (spend.js)
//   prove    the WebAssembly prover (prover.js); the proof is checked here before anything is signed
//   carry    the witness carrier (taproot.js): the wallet signs the commit, the vault the reveal
//
// The anchor is the block the local tree was last synced to (sync.js): its root is the indexer's
// R[anchorHeight], and a spend is valid while anchorHeight ≥ H − W (W = 100 blocks), so the vault
// refuses to build one on a tree older than ANCHOR_MAX_AGE blocks.

import { buildSpend, withProof, pickInputs } from './spend.js';
import { commitment, commitValue, signReveal, oneTimeSecret } from './taproot.js';
import { buildFunded } from './mint.js';
import { addressToScript, opReturnScript } from './btc.js';
import { serializeEnvelope, decodeAddress, tickerT } from './sh20.js';
import { NETWORK_HRP } from './notekeys.js';
import { GENESIS } from './profile.js';
import { toHex, fromHex } from './bytes.js';

export const ANCHOR_MAX_AGE = 90; // blocks; the indexers accept 100 (anchorWindow)

/** Three outputs in random order, so their positions say nothing about which one is the change. */
function shuffled(xs) {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function anchor(sync, tip) {
  if (sync?.height === null || sync?.height === undefined) throw new Error('sync the notes first: a spend is anchored to the synced tree');
  if (Number.isInteger(tip) && tip - sync.height > ANCHOR_MAX_AGE) throw new Error(`the synced tree is ${tip - sync.height} blocks old: sync again`);
  return { anchorHeight: sync.height, root: sync.tree.root };
}

function spendFrom({ vault, sync, tip, ticker, need, outputs, vPub = 0n, tPub = 0n, envelope }) {
  const inputs = pickInputs(vault.state.notes, ticker, need);
  if (!inputs) throw new Error(`not enough ${ticker} in two unspent notes (a spend takes at most two)`);
  const { anchorHeight, root } = anchor(sync, tip);
  const paths = inputs.map((n) => sync.witness(n.pos, BigInt('0x' + n.leaf)).siblings); // checked against the local root
  const change = inputs.reduce((s, n) => s + BigInt(n.v), 0n) - need;
  const me = vault.wallet;
  const outs = outputs({ change, me: me.address });
  const built = buildSpend({ wallet: me, ticker, inputs, paths, root, anchorHeight, outputs: outs, vPub, tPub, envelope });
  return { ...built, inputs, change, anchorHeight };
}

/** A private TRANSFER of `amount` of `ticker` to the sh20 address `to` (a string). */
export function planTransfer({ vault, sync, tip, ticker, amount, to }) {
  const recipient = decodeAddress(NETWORK_HRP, to.trim()); // every check a payer owes (SPEC-NOTES §2)
  const v = BigInt(amount);
  if (v <= 0n) throw new Error('the amount must be positive');
  return spendFrom({
    vault, sync, tip, ticker, need: v,
    outputs: ({ change, me }) => shuffled([{ address: recipient, v }, { address: me, v: change }, { address: me, v: 0n }]),
    envelope: (spend) => ({ type: 'TRANSFER', spend }),
  });
}

/**
 * A DEPLOY that burns `D` SH20 (docs/SPEC-WIRE.md §5: a spend with vPub = D, tPub = t("SH20")).
 * `d` are the terms as deploy-plan.js checks them; `team` is the opening { npk } of the team note when pre > 0.
 */
export function planDeployBurn({ vault, sync, tip, d, D, team = null }) {
  if (!(D > 0n)) throw new Error('this profile burns nothing: a DEPLOY carries no spend');
  return spendFrom({
    vault, sync, tip, ticker: GENESIS.ticker, need: D, vPub: D, tPub: tickerT(GENESIS.ticker),
    outputs: ({ change, me }) => shuffled([{ address: me, v: change }, { address: me, v: 0n }, { address: me, v: 0n }]),
    envelope: (spend) => deployEnvelope(d, team, spend),
  });
}

export function deployEnvelope(d, team, spend = null) {
  return {
    type: 'DEPLOY', ticker: d.ticker, max: d.max, lim: d.lim, pre: d.pre, start: d.start, end: d.end, unlock: d.unlock,
    price: d.price, payMode: d.payMode, payScript: Buffer.from(d.payScript ?? []), team: d.pre > 0n ? team : null, spend,
  };
}

/** Proves a planned spend and checks the proof against its own public inputs. Returns the envelope bytes. */
export async function proveSpend(prover, built) {
  const proof = await prover.prove(built.witness);
  if (!proof) throw new Error('the prover refused the witness (the notes or the tree changed?): nothing was sent');
  if (!(await prover.verify(built.publics, proof))) throw new Error('the proof does not verify: nothing was sent');
  return withProof(built.env, proof);
}

/**
 * The two transactions that carry a proof-carrying `envelope`: the commit, paid by `payer` from
 * `utxos` (a PSBT for the wallet), and what the reveal needs once the commit's txid is known.
 * The one-time secret must be saved before the commit is signed (Vault.addPending).
 */
export function planCarrier({ envelope, payer, utxos, feeRate, tipHeight, secret = oneTimeSecret() }) {
  const c = commitment(secret, envelope);
  const returnScript = addressToScript(payer.address);
  const value = commitValue(c, returnScript, feeRate);
  const commit = buildFunded({ fixed: [{ value, script: c.scriptPubKey }], payer, utxos, feeRate, tipHeight });
  return { commit, c, secret, value, returnScript, feeRate };
}

/** The signed reveal for a commit that pays output 0. */
export function revealFor(plan, commitTxid) {
  return signReveal({ secret: plan.secret, c: plan.c, commitTxid, value: plan.value, returnScript: plan.returnScript, feeRate: plan.feeRate });
}

/** A DEPLOY without a burn (D = 0): one OP_RETURN transaction, like a MINT. */
export function buildPlainDeploy({ d, team, payer, utxos, feeRate, tipHeight }) {
  const envelope = serializeEnvelope(deployEnvelope(d, team));
  return { ...buildFunded({ fixed: [{ value: 0n, script: opReturnScript(envelope) }], payer, utxos, feeRate, tipHeight }), envelope };
}

/** What Vault.addPending keeps of a carrier plan: enough to sign and send the reveal again later. */
export const pendingRecord = (kind, plan, envelope, inputs) => ({
  kind,
  envelope: toHex(envelope),
  secret: toHex(plan.secret),
  value: plan.value.toString(),
  returnScript: toHex(plan.returnScript),
  feeRate: plan.feeRate,
  inputs: inputs.map((n) => n.id),
  status: 'prepared',
});

/** A carrier plan back from a pending record (to sign the reveal again). */
export function planFromPending(p) {
  const secret = fromHex(p.secret);
  return { c: commitment(secret, fromHex(p.envelope)), secret, value: BigInt(p.value), returnScript: fromHex(p.returnScript), feeRate: p.feeRate };
}
