// A batch on chain (docs/RELAYER.md §3, docs/SPEC-WIRE.md §3): a commit paid by the relayer's coins,
// and a reveal whose input 0 carries every envelope in its tapscript
//
//   <E> OP_CHECKSIG  then for each transfer  OP_0 OP_IF "SH20" <pushes of at most 520 bytes> OP_ENDIF
//
// With one envelope this is the vault's own script (vault/src/taproot.js envelopeScript), and the
// BIP341 parts (tweak, leaf hash, control block, signature message, reveal signature) are the vault's.

import { MAGIC } from '../../vault/src/sh20.js';
import { bip340PublicKey } from '../../vault/src/secp256k1.js';
import { LEAF_VERSION, leafHash, tweakKey, commitValue, signReveal, sigMsg, signKeyPath } from '../../vault/src/taproot.js';
import { selectCoins } from '../../vault/src/mint.js';
import { pushData, serializeTx, txid as txidOf, vsize } from '../../vault/src/btc.js';
import { concat, toHex } from '../../vault/src/bytes.js';

const SEQUENCE = 0xfffffffd;

/** The tapscript of a batch: the one-time key `e`, then each envelope in the order given. */
export function batchScript(e, envelopes) {
  if (!envelopes.length) throw new Error('a batch has at least one envelope');
  const parts = [pushData(e), Uint8Array.of(0xac)];
  for (const env of envelopes) {
    const rest = env.subarray(MAGIC.length);
    parts.push(Uint8Array.of(0x00, 0x63), pushData(Uint8Array.from(MAGIC)));
    for (let i = 0; i < rest.length; i += 520) parts.push(pushData(rest.subarray(i, i + 520)));
    parts.push(Uint8Array.of(0x68));
  }
  return concat(...parts);
}

/** The commit output of a batch for the one-time secret `secret`: { e, script, leaf, scriptPubKey, control }. */
export function batchCommitment(secret, envelopes) {
  const e = bip340PublicKey(secret);
  const script = batchScript(e, envelopes);
  const leaf = leafHash(script);
  const q = tweakKey(e, leaf); // one leaf: the merkle root is the leaf hash
  return { e, script, leaf, scriptPubKey: concat(Uint8Array.of(0x51, 0x20), q.key), control: concat(Uint8Array.of(LEAF_VERSION | q.parity), e) };
}

/**
 * The two signed transactions of a batch. `btc` is the relayer's key-path output ({ script, secret }),
 * `utxos` its coins there ([{ txid, vout, value }]), `secret` a fresh one-time key.
 * Returns { commit, reveal, c }, each transaction as { tx, hex, txid, vsize, fee }.
 */
export function buildBatch({ envelopes, secret, btc, utxos, feeRate, tipHeight }) {
  const c = batchCommitment(secret, envelopes);
  const value = commitValue(c, btc.script, feeRate); // the reveal's fee and the dust it returns
  const { picked, change, fee } = selectCoins(utxos, [{ value, script: c.scriptPubKey }], 'p2tr', btc.script, feeRate);
  const tx = {
    version: 2,
    locktime: tipHeight, // anti fee-sniping, as the vault's commits
    vin: picked.map((u) => ({ txid: u.txid, vout: u.vout, sequence: SEQUENCE, scriptSig: new Uint8Array(0), witness: [] })),
    vout: [{ value, script: c.scriptPubKey }, ...(change > 0n ? [{ value: change, script: btc.script }] : [])],
  };
  const prevouts = picked.map((u) => ({ value: u.value, script: btc.script }));
  tx.vin.forEach((input, k) => { input.witness = [signKeyPath(btc.secret, sigMsg(tx, k, prevouts))]; });
  const commit = { tx, hex: toHex(serializeTx(tx)), txid: txidOf(tx), vsize: vsize(tx), fee, spent: picked };
  const reveal = signReveal({ secret, c, commitTxid: commit.txid, value, returnScript: btc.script, feeRate });
  return { commit, reveal, c };
}
