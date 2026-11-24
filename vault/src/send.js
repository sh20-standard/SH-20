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
import { commitment, commitValue, signReveal, oneTimeSecret, keyPathOutput, signKeyPath, sigMsg } from './taproot.js';
import { buildFunded } from './mint.js';
import { addressToScript } from './btc.js';
import { serializeEnvelope, parseEnvelope, decodeAddress, tickerT } from './sh20.js';
import { NETWORK_HRP } from './notekeys.js';
import { GENESIS, PROFILE } from './profile.js';
import { toHex, fromHex } from './bytes.js';

export const ANCHOR_MAX_AGE = PROFILE.anchorWindow - 10; // blocks; the indexers accept W, and the spend takes a few blocks to confirm

/** Three outputs in random order, so their positions say nothing about which one is the change. */
export function shuffled(xs) {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export function anchor(sync, tip) {
  if (sync?.height === null || sync?.height === undefined) throw new Error('sync the notes first: a spend is anchored to the synced tree');
  if (Number.isInteger(tip) && tip - sync.height > ANCHOR_MAX_AGE) throw new Error(`the synced tree is ${tip - sync.height} blocks old: sync again`);
  // the spend confirms at tip + 1 at the earliest, and its anchor must be K_min blocks below that block
  if (Number.isInteger(tip) && sync.height > tip + 1 - PROFILE.anchorMinDepth) throw new Error(`the synced tree is less than K_min = ${PROFILE.anchorMinDepth} block(s) deep: wait for a block`);
  return { anchorHeight: sync.height, root: sync.tree.root };
}

export async function spendFrom({ vault, sync, tip, ticker, need, outputs, vPub = 0n, tPub = 0n, envelope }) {
  const inputs = pickInputs(vault.state.notes, ticker, need);
  if (!inputs) throw new Error(`not enough ${ticker} in two unspent notes (a spend takes at most two)`);
  const { anchorHeight, root } = anchor(sync, tip);
  const paths = inputs.map((n) => sync.witness(n.pos, BigInt('0x' + n.leaf)).siblings); // checked against the local root
  const change = inputs.reduce((s, n) => s + BigInt(n.v), 0n) - need;
  const me = vault.wallet;
  const outs = outputs({ change, me: me.address });
  const built = await buildSpend({ wallet: me, ticker, inputs, paths, root, anchorHeight, outputs: outs, vPub, tPub, envelope });
  return { ...built, inputs, change, anchorHeight };
}

/** A private TRANSFER of `amount` of `ticker` to the sh20 address `to` (a string). */
export async function planTransfer({ vault, sync, tip, ticker, amount, to }) {
  const recipient = await decodeAddress(NETWORK_HRP, to.trim()); // every check a payer owes (SPEC-NOTES §2)
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
export async function planDeployBurn({ vault, sync, tip, d, D, team = null }) {
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
export function planCarrier({ envelope, payer, utxos, feeRate, tipHeight, secret = oneTimeSecret(), outputs, sweep }) {
  const c = commitment(secret, envelope);
  const returnScript = addressToScript(payer.address);
  const value = commitValue(c, returnScript, feeRate, outputs);
  // `sweep`: an older commit output of this vault (pendingRecord), spent here by its key path, so a
  // DEPLOY proved again gets the sats of the commit it replaces back
  const pre = sweep ? [sweepInput(sweep)] : [];
  const commit = buildFunded({
    fixed: [{ value, script: c.scriptPubKey }], payer, utxos, feeRate, tipHeight, pre,
    sign: (tx, k, prevouts) => [signKeyPath(pre[k].secret, sigMsg(tx, k, prevouts))],
  });
  return { commit, c, secret, value, returnScript, feeRate, outputs };
}

/** The commit output of a pending record as an input its one-time key signs by the key path. */
function sweepInput(p) {
  const plan = planFromPending(p);
  return { txid: p.commitTxid, vout: 0, sequence: 0xfffffffd, value: plan.value, script: plan.c.scriptPubKey, secret: keyPathOutput(plan.secret, plan.c.leaf).secret };
}

/**
 * Whether a DEPLOY's ticker is still free before its reveal goes out, from every configured
 * indexer's /tokens (Promise.allSettled results): 'taken' if any lists it, 'free' if at least one
 * answered and none lists it, 'unknown' if none answered. An unknown answer holds the reveal back:
 * nobody said the ticker is free, and a reveal for a taken ticker is rejected and loses its fees.
 */
export function tickerState(settled, ticker) {
  const answers = settled.filter((r) => r.status === 'fulfilled' && Array.isArray(r.value)).map((r) => r.value);
  if (answers.some((list) => list.some((t) => t.ticker === ticker))) return 'taken';
  return answers.length ? 'free' : 'unknown';
}

/**
 * When a DEPLOY's reveal may go out (SPEC-WIRE §5, DEPLOY maturity): its commit must be confirmed
 * at a height ≤ H − N, H being the reveal's block, and a DEPLOY that burns D SH20 carries a proof
 * anchored at `anchorHeight`, valid while H − W ≤ anchorHeight. The reveal lands at tip + 1 at the
 * earliest. Returns { state, blocks }: 'unconfirmed' (the commit is not in a block), 'waiting'
 * (`blocks` more to go), 'ready', or 'expired' (the proof's anchor will be out of the window: prove again).
 */
export function revealSchedule({ commitHeight, tip, N, anchorHeight = null, W = 100 }) {
  if (!Number.isInteger(commitHeight)) return { state: 'unconfirmed', blocks: null };
  const earliest = Math.max(tip + 1, commitHeight + N);
  if (anchorHeight !== null && earliest - anchorHeight > W) return { state: 'expired', blocks: null };
  const blocks = commitHeight + N - (tip + 1);
  return blocks > 0 ? { state: 'waiting', blocks } : { state: 'ready', blocks: 0 };
}

/**
 * When a pending DEPLOY `p` may be revealed: revealSchedule with N and W of the vault's own profile
 * (profile.js). Neither the record (`p.deploy.N`, written by an older vault from the indexers) nor
 * an indexer can make the reveal go out before the commit is PROFILE.deployMaturity blocks deep.
 */
export const deploySchedule = (p, { commitHeight, tip }) =>
  revealSchedule({ commitHeight, tip, N: PROFILE.deployMaturity, anchorHeight: p.anchorHeight ?? null, W: PROFILE.anchorWindow });

/** Blocks a refused spend's reveal must be below the synced tip before its notes are given back. */
export const REFUSAL_DEPTH = 6;

// the statuses of a spend whose commit the wallet signed: from here on its reveal may be out, or go out
const SENT = ['signed', 'commit broadcast', 'broadcast'];

/** The anchor height of spend `p`: recorded with it, or read from its envelope. Null for one with no spend. */
export function anchorOf(p) {
  if (Number.isInteger(p.anchorHeight)) return p.anchorHeight;
  try {
    return parseEnvelope(Buffer.from(fromHex(p.envelope))).env.spend?.anchorHeight ?? null;
  } catch {
    return null;
  }
}

/**
 * Whether spend `p`, sent from this vault, can no longer take the notes it reserved, so that the caller gives
 * them back (Vault.releaseInputs), once every indexer agrees (consensus.js refusalAgreed, from refusalAt):
 * - refused: its reveal is confirmed at `revealHeight`, and the synced tree (with the full nullifier list) is
 *   REFUSAL_DEPTH blocks past it. A refused envelope records no nullifier (a DEPLOY refused for its commit's
 *   maturity, its ticker or its proof burns nothing);
 * - or never mined (docs/audit/2026-11-24-vault.md, vault-2: a commit or a reveal dropped or replaced): its reveal
 *   has no height, and the synced tree is W + REFUSAL_DEPTH blocks past its anchor. A spend lands only where
 *   anchorHeight ≥ H − W (SPEC-WIRE §5), so no block can take it any more, in this transaction or in a copy that
 *   anyone publishes, even after a reorg of REFUSAL_DEPTH − 1 blocks.
 * Either way no note it spends has its nullifier recorded there. `notes` must have been checked against that
 * tree (`spent`, `pathAt`).
 */
export function refusedSpend(p, notes, { revealHeight, syncHeight, nullifiersKnown, depth = REFUSAL_DEPTH, W = PROFILE.anchorWindow }) {
  if (!SENT.includes(p.status) || !p.inputs?.length || !nullifiersKnown || !Number.isInteger(syncHeight)) return false;
  if (Number.isInteger(revealHeight)) {
    if (p.status !== 'broadcast' || syncHeight - revealHeight + 1 < depth) return false;
  } else {
    const a = anchorOf(p);
    if (!Number.isInteger(a) || syncHeight - a < W + depth) return false;
  }
  const inputs = notes.filter((n) => p.inputs.includes(n.id));
  return inputs.length === p.inputs.length && inputs.every((n) => n.spent === 'no' && n.pathAt === syncHeight);
}

/**
 * The block every indexer must have passed before it can vouch that spend `p` spent nothing: REFUSAL_DEPTH − 1
 * past its reveal, or, for one never mined, past the last block that could have taken it (its anchor + W).
 */
export function refusalAt(p, revealHeight, { depth = REFUSAL_DEPTH, W = PROFILE.anchorWindow } = {}) {
  return (Number.isInteger(revealHeight) ? revealHeight : anchorOf(p) + W) + depth - 1;
}

/** The signed reveal for a commit that pays output 0. */
export function revealFor(plan, commitTxid) {
  return signReveal({ secret: plan.secret, c: plan.c, commitTxid, value: plan.value, returnScript: plan.returnScript, outputs: plan.outputs, feeRate: plan.feeRate });
}

/**
 * A DEPLOY without a burn (D = 0): no spend and no proof, but still a commit and a reveal in the
 * witness (SPEC-WIRE §5: a DEPLOY in an OP_RETURN is refused, its ticker would show before anything
 * is confirmed). Returns what carry needs: { env, envelope, inputs: [] }.
 */
export function planPlainDeploy({ d, team }) {
  const env = deployEnvelope(d, team);
  return { env, envelope: serializeEnvelope(env), inputs: [], anchorHeight: null };
}

/** What Vault.addPending keeps of a carrier plan: enough to sign and send the reveal again later. */
export const pendingRecord = (kind, plan, envelope, inputs) => ({
  kind,
  envelope: toHex(envelope),
  secret: toHex(plan.secret),
  value: plan.value.toString(),
  returnScript: toHex(plan.returnScript),
  outputs: plan.outputs?.map((o) => ({ value: o.value.toString(), script: toHex(o.script) })),
  feeRate: plan.feeRate,
  inputs: inputs.map((n) => n.id),
  status: 'prepared',
});

/** A carrier plan back from a pending record (to sign the reveal again). */
export function planFromPending(p) {
  const secret = fromHex(p.secret);
  const outputs = p.outputs?.map((o) => ({ value: BigInt(o.value), script: fromHex(o.script) }));
  return { c: commitment(secret, fromHex(p.envelope)), secret, value: BigInt(p.value), returnScript: fromHex(p.returnScript), outputs, feeRate: p.feeRate };
}
