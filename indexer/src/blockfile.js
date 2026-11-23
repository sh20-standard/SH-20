// The block file: the chain data the follower has read, kept so that a restart applies it again from disk
// instead of asking the source for every block since the activation height (bin/follow.js --data).
//
// `blocks.jsonl` in the data folder, one JSON object per line, only ever appended to while it is in use:
//   - first line: {"sh20-indexer":"blocks","version":1,"activation":A}
//   - a block:    {"height":H,"hash":"…","prev":"…","txs":[…]}, transactions as below
//   - a rollback: {"rollback":H}: the block at H and those after it are gone (a reorg)
//
// Chain data only, no state: the indexer recomputes everything from these blocks when it starts, so a block file
// cannot carry a wrong root or digest from one version of the code to the next. A line cut short by a crash is
// dropped. When the file is opened, it is rewritten without its rollbacks, its cut line, and anything after a
// block that does not follow the one before it (a file edited by hand, or written for another chain): the
// follower then asks the source again from there.
//
// A transaction: {"txid", "vin": [{"coinbase":true} | {"txid","vout","witness":[hex],"prevHeight"?}],
// "vout": [{"value":"<sats>","script":hex}]}, values as decimal strings so that no amount goes through a float.

import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const FILE_NAME = 'blocks.jsonl';
const VERSION = 1;

const header = (activation) => ({ 'sh20-indexer': 'blocks', version: VERSION, activation });

const inputOut = (i) =>
  i.coinbase
    ? { coinbase: true }
    : { txid: i.txid, vout: i.vout, witness: (i.witness ?? []).map((w) => Buffer.from(w).toString('hex')), ...(i.prevHeight !== undefined ? { prevHeight: i.prevHeight } : {}) };
const inputIn = (i) =>
  i.coinbase
    ? { coinbase: true }
    : { txid: i.txid, vout: i.vout, witness: i.witness.map((w) => Buffer.from(w, 'hex')), ...(i.prevHeight !== undefined ? { prevHeight: i.prevHeight } : {}) };

/** One block as a line of the file (without its newline). */
export function blockLine(b) {
  return JSON.stringify({
    height: b.height,
    hash: b.hash,
    prev: b.prev ?? null,
    txs: b.txs.map((t) => ({
      txid: t.txid,
      vin: t.vin.map(inputOut),
      vout: t.vout.map((o) => ({ value: o.value.toString(), script: Buffer.from(o.script).toString('hex') })),
    })),
  });
}

/** A block line read back, in the indexer's format. */
export function blockOf(v) {
  if (!Number.isInteger(v.height) || typeof v.hash !== 'string' || !Array.isArray(v.txs)) throw new Error('not a block');
  return {
    height: v.height,
    hash: v.hash,
    prev: v.prev ?? null,
    txs: v.txs.map((t) => ({
      txid: t.txid,
      vin: t.vin.map(inputIn),
      vout: t.vout.map((o) => ({ value: BigInt(o.value), script: Buffer.from(o.script, 'hex') })),
    })),
  };
}

export class BlockFile {
  /**
   * Opens `<dir>/blocks.jsonl` (creating both when missing) and returns the file with the blocks it holds, in
   * order from the activation height. A file written for another activation height is refused.
   * @returns {{ file: BlockFile, blocks: object[], dropped: number }} `dropped`: lines left out (rollbacks undone,
   *   a cut line, blocks after a break), 0 when the file was already tidy
   */
  static open(dir, activation) {
    mkdirSync(dir, { recursive: true });
    const path = join(dir, FILE_NAME);
    let text = null;
    try {
      text = readFileSync(path, 'utf8');
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    const blocks = [];
    let dropped = 0;
    let tidy = text !== null;
    if (text !== null) {
      const lines = text.split('\n');
      if (lines.pop() !== '') {
        tidy = false; // the last line has no newline: cut short
        dropped++;
      }
      const first = lines.shift();
      let head = null;
      try {
        head = first === undefined ? null : JSON.parse(first);
      } catch {}
      if (head?.['sh20-indexer'] !== 'blocks' || head.version !== VERSION) throw new Error(`${path}: not a block file of this indexer (version ${VERSION})`);
      if (head.activation !== activation) throw new Error(`${path}: written for activation height ${head.activation}, not ${activation}`);
      let broken = false;
      for (const line of lines) {
        if (broken) {
          dropped++;
          continue;
        }
        let v;
        try {
          v = JSON.parse(line);
        } catch {
          broken = true;
          dropped++;
          continue;
        }
        if (Number.isInteger(v.rollback)) {
          while (blocks.length && blocks.at(-1).height >= v.rollback) {
            blocks.pop();
            dropped++;
          }
          tidy = false;
          dropped++;
          continue;
        }
        let b;
        try {
          b = blockOf(v);
        } catch {
          broken = true;
          dropped++;
          continue;
        }
        const last = blocks.at(-1);
        const follows = last ? b.height === last.height + 1 && b.prev === last.hash : b.height === activation;
        if (!follows) {
          broken = true;
          dropped++;
          continue;
        }
        blocks.push(b);
      }
      if (broken) tidy = false;
    }
    if (!tidy) BlockFile._write(path, activation, blocks);
    return { file: new BlockFile(path), blocks, dropped };
  }

  static _write(path, activation, blocks) {
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, [JSON.stringify(header(activation)), ...blocks.map(blockLine)].map((l) => `${l}\n`).join(''));
    renameSync(tmp, path);
  }

  constructor(path) {
    this.path = path;
  }

  /** Keeps a block the follower has applied. */
  append(block) {
    appendFileSync(this.path, `${blockLine(block)}\n`);
  }

  /** Records that the blocks from `height` on were undone. */
  rollback(height) {
    appendFileSync(this.path, `${JSON.stringify({ rollback: height })}\n`);
  }
}
