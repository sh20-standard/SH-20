// An Esplora API over a chain of blocks as `bitcoin-cli getblock <hash> 3` prints them (bin/chain-gen.js
// blockJson): what bin/api-diff.js and the tests of follow.js --data have the followers read. It serves only the
// routes the followers ask for; any other is answered 404 and named in `unknown`. `asked` counts the requests by
// shape (`/block/:hash/txs/:n`, …), so a test can tell which blocks a follower fetched.
//
//   const esplora = await fakeEsplora(blocks);   // esplora.url, then esplora.serve(otherBlocks) for a reorg
//   …
//   esplora.close();

import { createServer } from 'node:http';

const toSats = (btc) => Math.round(Number(btc) * 1e8);
const shape = (u) => u.replace(/[0-9a-f]{64}/g, ':hash').replace(/\d+$/, ':n');

const esploraTx = (t) => ({
  txid: t.txid,
  vin: t.vin.map((i) => (i.coinbase ? { is_coinbase: true, witness: i.txinwitness ?? [] } : { txid: i.txid, vout: i.vout, is_coinbase: false, witness: i.txinwitness ?? [] })),
  vout: t.vout.map((o) => ({ scriptpubkey: o.scriptPubKey.hex, value: toSats(o.value) })),
});

export async function fakeEsplora(initial) {
  let blocks = [];
  const byHash = new Map();
  const spentHeight = new Map(); // the output a DEPLOY spends → the height that confirmed it
  const unknown = new Set();
  const asked = new Map();
  const serve = (list) => {
    blocks = list;
    for (const b of list) {
      byHash.set(b.hash, b);
      for (const t of b.tx) if (t.vin[0]?.prevout?.height !== undefined) spentHeight.set(t.vin[0].txid, t.vin[0].prevout.height);
    }
  };
  serve(initial);

  const server = createServer((req, res) => {
    const send = (code, body, text = false) => {
      res.writeHead(code, { 'content-type': text ? 'text/plain' : 'application/json' });
      res.end(text ? String(body) : JSON.stringify(body));
    };
    const u = req.url;
    asked.set(shape(u), (asked.get(shape(u)) ?? 0) + 1);
    let m;
    if (u === '/blocks/tip/height') return send(200, blocks.at(-1).height, true);
    if (u === '/blocks/tip/hash') return send(200, blocks.at(-1).hash, true);
    if ((m = u.match(/^\/block-height\/(\d+)$/))) {
      const b = blocks.find((x) => x.height === Number(m[1]));
      return b ? send(200, b.hash, true) : send(404, 'Block not found', true);
    }
    if ((m = u.match(/^\/block\/([0-9a-f]{64})$/))) {
      const b = byHash.get(m[1]);
      if (!b) return send(404, 'Block not found', true);
      const prev = blocks.find((x) => x.height === b.height - 1) ?? [...byHash.values()].find((x) => x.height === b.height - 1);
      return send(200, { id: b.hash, height: b.height, tx_count: b.tx.length, previousblockhash: prev ? prev.hash : '00'.repeat(32) });
    }
    if ((m = u.match(/^\/block\/([0-9a-f]{64})\/txs(?:\/(\d+))?$/))) {
      const b = byHash.get(m[1]);
      if (!b) return send(404, 'Block not found', true);
      const start = Number(m[2] ?? 0);
      return send(200, b.tx.slice(start, start + 25).map(esploraTx));
    }
    if ((m = u.match(/^\/block\/([0-9a-f]{64})\/txids$/))) return byHash.has(m[1]) ? send(200, byHash.get(m[1]).tx.map((t) => t.txid)) : send(404, 'Block not found', true);
    if ((m = u.match(/^\/tx\/([0-9a-f]{64})\/status$/))) {
      const h = spentHeight.get(m[1]);
      return h === undefined ? send(404, 'Transaction not found', true) : send(200, { confirmed: true, block_height: h, block_hash: blocks.find((x) => x.height === h)?.hash });
    }
    unknown.add(shape(u));
    send(404, 'not served here', true);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    get blocks() {
      return blocks;
    },
    serve,
    unknown,
    asked,
    close: () => new Promise((r) => server.close(r)),
  };
}
