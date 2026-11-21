// Releases are reproducible, and the CID matches what IPFS computes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tar, ipfsCid } from '../tools/pack.js';
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
