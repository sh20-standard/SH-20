// Releases are reproducible, and the CID matches what IPFS computes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tar, ipfsCid, car, cidString } from '../tools/pack.js';
import { buildRelease } from '../release.js';

const sha = (b) => createHash('sha256').update(b).digest('hex');

test('IPFS CIDs match kubo (`ipfs add -r --cid-version=1`, checked with kubo 0.32.1), chunked files too', () => {
  assert.equal(ipfsCid([]), 'bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354'); // empty folder
  const tree = [['a/x.txt', Buffer.from('hello\n')], ['a/b/empty', Buffer.alloc(0)], ['top', Buffer.from('zz')]];
  assert.equal(ipfsCid(tree), 'bafybeicx6wui6j2nt5zsoq547ypvpt622avmtgk2hrolw2cbxixayjgpbu');
  assert.equal(ipfsCid([...tree].reverse()), ipfsCid(tree), 'order of input does not matter');
  // files above one 256 KiB chunk (the proving key, the prover): raw leaves under one dag-pb node
  const big = Buffer.alloc(600000);
  for (let i = 0; i < big.length; i++) big[i] = i % 251;
  assert.equal(ipfsCid([['big.bin', big], ['edge.bin', Buffer.alloc(262145, 7)]]), 'bafybeiclr3t3ig4gbcrwxqntk6ght47t4s7gvp5n5mncyxak253wos4k5q');
});

/** Reads a CARv1: its root and its blocks, each checked against its CID (sha2-256). */
function readCar(c) {
  let p = 0;
  const varint = () => { let n = 0, k = 0, b; do { b = c[p++]; n += (b & 0x7f) * 2 ** (7 * k++); } while (b & 0x80); return n; };
  const headerLen = varint();
  const header = c.subarray(p, p + headerLen);
  p += headerLen;
  const at = header.indexOf(Buffer.from([0xd8, 0x2a, 0x58]));
  const root = header.subarray(at + 5, at + 4 + header[at + 3]);
  assert.ok(header.includes(Buffer.from('version')) && header.at(-1) === 1, 'version 1');
  const blocks = [];
  while (p < c.length) {
    const end = varint() + p;
    const cid = c.subarray(p, p + 36); // CIDv1, one-byte codec, sha2-256
    const bytes = c.subarray(p + 36, end);
    assert.deepEqual(cid.subarray(4), createHash('sha256').update(bytes).digest(), 'the block is its CID');
    blocks.push({ cid: cidString(cid), codec: cid[1], bytes });
    p = end;
  }
  return { root: cidString(root), blocks };
}

test('the CAR of a release holds the blocks of its CID, the root first (imported by kubo 0.32.1: `ipfs dag import`)', () => {
  const tree = [['a/x.txt', Buffer.from('hello\n')], ['a/b/empty', Buffer.alloc(0)], ['top', Buffer.from('zz')]];
  const c = car(tree);
  assert.equal(sha(c), '6458a34b2f466a4d5fe2b315cea736cd457946eb9e42ce9a0f578655be936644', 'the same bytes every time');
  const r = readCar(c);
  assert.equal(r.root, ipfsCid(tree));
  assert.equal(r.blocks[0].cid, r.root);
  assert.deepEqual(r.blocks.map((b) => b.codec).sort((x, y) => x - y), [0x55, 0x55, 0x55, 0x70, 0x70, 0x70], 'three files, three folders');
  assert.equal(new Set(r.blocks.map((b) => b.cid)).size, r.blocks.length, 'each block once');
  // a file above one chunk: its leaves and its node, and a leaf repeated in two files is there once
  const big = Buffer.alloc(600000, 3);
  const r2 = readCar(car([['big.bin', big], ['copy.bin', big]]));
  assert.equal(r2.root, ipfsCid([['big.bin', big], ['copy.bin', big]]));
  assert.equal(r2.blocks.length, 1 + 1 + 2, 'root, one file node, two distinct leaves (256 KiB of 3s, and the rest)');
});

test('tar is a valid ustar with fixed metadata, independent of input order', () => {
  const entries = [['b.txt', Buffer.from('bee')], ['a/c.js', Buffer.from('x'.repeat(600))]];
  const t = tar(entries, 'pkg');
  assert.equal(t.length % 512, 0);
  assert.equal(sha(t), sha(tar([...entries].reverse(), 'pkg')));
  assert.equal(t.subarray(0, 8).toString(), 'pkg/a/c.');
  assert.equal(t.subarray(257, 263).toString(), 'ustar\0');
  const list = execFileSync('tar', ['-tvf', '-'], { input: t }).toString();
  assert.match(list, /pkg\/a\/c\.js/);
  assert.match(list, /pkg\/b\.txt/);
  assert.equal(execFileSync('tar', ['-xOf', '-', 'pkg/b.txt'], { input: t }).toString(), 'bee');
});

test('a release of the same commit is byte-identical, and has no external script', () => {
  const commit = execFileSync('git', ['rev-parse', 'HEAD']).toString().trim();
  // on the test profile: a release proper needs the signet's activation height (test/signet.test.js)
  const a = buildRelease(commit, { signet: false });
  const b = buildRelease(commit, { signet: false });
  assert.equal(a.sha256, b.sha256);
  assert.equal(a.cid, b.cid);
  assert.ok(a.pkg.equals(b.pkg));
  for (const [p, bytes] of a.entries) {
    if (!/\.(html|js|css)$/.test(p)) continue;
    const s = bytes.toString('utf8');
    assert.ok(!/<script[^>]+src=["']?(https?:)?\/\//i.test(s), `${p}: external script`);
    assert.ok(!/@import\s+url\(|url\(\s*["']?https?:/i.test(s), `${p}: external stylesheet or resource`);
    assert.ok(!/\bimport\s*\(?\s*['"]https?:/.test(s), `${p}: import from another domain`);
  }
});
