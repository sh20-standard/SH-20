// Deterministic packaging for releases, zero dependencies:
//   tar(entries, prefix) → a POSIX ustar archive with fixed metadata
//   ipfsCid(entries)     → the CIDv1 that `ipfs add -r --cid-version=1` gives the folder
//
// tar: entries sorted by path, mode 0644, uid/gid 0, mtime 0, no owner names,
// no directory entries, no compression (gzip output depends on the zlib build).
//
// CID: UnixFS as kubo writes it with --cid-version=1 (raw leaves, sha2-256,
// 256 KiB chunks): a file that fits in one chunk is a raw block; a directory
// is a dag-pb node whose links are sorted by name, with Tsize = the size of the
// whole subtree. Larger files and sharded directories are refused, not guessed.

import { createHash } from 'node:crypto';

// ---- tar ----------------------------------------------------------------------

function header(name, size) {
  if (Buffer.byteLength(name) > 100) throw new Error(`path too long for ustar: ${name}`);
  const h = Buffer.alloc(512);
  const put = (off, len, s) => h.write(s, off, len, 'utf8');
  const oct = (off, len, n) => put(off, len, n.toString(8).padStart(len - 1, '0') + '\0');
  put(0, 100, name);
  oct(100, 8, 0o644);
  oct(108, 8, 0);
  oct(116, 8, 0);
  oct(124, 12, size);
  oct(136, 12, 0);
  h.fill(0x20, 148, 156); // checksum field counts as spaces
  put(156, 1, '0');
  put(257, 6, 'ustar\0');
  put(263, 2, '00');
  let sum = 0;
  for (const b of h) sum += b;
  put(148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
  return h;
}

export function tar(entries, prefix) {
  const parts = [];
  for (const [p, b] of [...entries].sort(([a], [c]) => (a < c ? -1 : a > c ? 1 : 0))) {
    parts.push(header(`${prefix}/${p}`, b.length), b, Buffer.alloc((512 - (b.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

// ---- IPFS UnixFS CIDv1 ----------------------------------------------------------

const CHUNK = 262144;
const RAW = 0x55;
const DAG_PB = 0x70;

function varint(n) {
  const out = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  out.push(n);
  return Buffer.from(out);
}

const field = (num, bytes) => Buffer.concat([varint((num << 3) | 2), varint(bytes.length), bytes]);
const cidBytes = (codec, block) => Buffer.concat([Buffer.from([0x01]), varint(codec), Buffer.from([0x12, 0x20]), createHash('sha256').update(block).digest()]);

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
export function cidString(bytes) {
  let bits = 0;
  let val = 0;
  let s = 'b';
  for (const x of bytes) {
    val = (val << 8) | x;
    bits += 8;
    while (bits >= 5) {
      s += B32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) s += B32[(val << (5 - bits)) & 31];
  return s;
}

const UNIXFS_DIR = Buffer.from([0x08, 0x01]); // { Type: Directory }

/** A directory node from [{ name, cid, tsize }]; returns { cid, tsize }. */
function dirNode(links) {
  const sorted = [...links].sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
  const node = Buffer.concat([
    ...sorted.map((l) => field(2, Buffer.concat([field(1, l.cid), field(2, Buffer.from(l.name)), varint(3 << 3), varint(l.tsize)]))),
    field(1, UNIXFS_DIR),
  ]);
  if (node.length > CHUNK) throw new Error('directory too large: kubo would shard it');
  return { cid: cidBytes(DAG_PB, node), tsize: node.length + sorted.reduce((s, l) => s + l.tsize, 0) };
}

/** CIDv1 of the folder holding `entries` ([path, bytes]), as `ipfs add -r --cid-version=1` prints it. */
export function ipfsCid(entries) {
  const tree = { files: new Map(), dirs: new Map() };
  for (const [p, b] of entries) {
    if (b.length > CHUNK) throw new Error(`${p} is larger than one IPFS chunk: compute the CID with ipfs itself`);
    const parts = p.split('/');
    let d = tree;
    for (const seg of parts.slice(0, -1)) {
      if (!d.dirs.has(seg)) d.dirs.set(seg, { files: new Map(), dirs: new Map() });
      d = d.dirs.get(seg);
    }
    d.files.set(parts.at(-1), b);
  }
  const build = (d) => dirNode([
    ...[...d.files].map(([name, b]) => ({ name, cid: cidBytes(RAW, b), tsize: b.length })),
    ...[...d.dirs].map(([name, sub]) => ({ name, ...build(sub) })),
  ]);
  return cidString(build(tree).cid);
}
