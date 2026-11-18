// Converts Bitcoin Core `getblock <hash> 2` JSON into the indexer's block format.
// Any source works (your own node, Esplora, a file) as long as it yields this shape.

function btcToSats(value) {
  const [whole, frac = ''] = Number(value).toFixed(8).split('.');
  return BigInt(whole) * 100000000n + BigInt(frac.padEnd(8, '0'));
}

export function fromBitcoindBlock(json) {
  return {
    height: json.height,
    hash: json.hash,
    txs: json.tx.map((t) => ({
      txid: t.txid,
      vin: t.vin.map((i) =>
        i.coinbase
          ? { coinbase: true }
          : { txid: i.txid, vout: i.vout, witness: (i.txinwitness || []).map((h) => Buffer.from(h, 'hex')) },
      ),
      vout: t.vout.map((o) => ({ value: btcToSats(o.value), script: Buffer.from(o.scriptPubKey.hex, 'hex') })),
    })),
  };
}
