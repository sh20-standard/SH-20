// Verifiable release of the vault.
//
//   npm run release                    build from the current git commit, write
//                                      release/, record SHA-256 and CID in RELEASES.md
//   node release.js --check <sha256>   rebuild from the current commit and compare
//
// The package is built from the git objects of the commit (`git cat-file`), not
// from the working tree, so local edits, line-ending settings or file dates
// cannot change it: the same commit always gives the same bytes, on any machine.
//
// Outputs, in vault/release/:
//   sh20-vault-<version>.tar   the package (ustar, fixed metadata, no compression)
//   sh20-vault-<version>/      the same files, ready for `ipfs add -r --cid-version=1`

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { site, writeSite, sha256 } from './build.js';
import { tar, ipfsCid } from './tools/pack.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const git = (...args) => execFileSync('git', args, { cwd: root, maxBuffer: 1 << 26 });

/** Reads repository files as stored in `commit`. */
export function gitReader(commit) {
  return {
    list: (dir) => git('ls-tree', '-r', '--name-only', commit, '--', dir).toString('utf8').split('\n').filter(Boolean).sort(),
    read: (p) => git('cat-file', 'blob', `${commit}:${p}`),
  };
}

export function buildRelease(commit) {
  const { version } = JSON.parse(git('cat-file', 'blob', `${commit}:vault/package.json`).toString('utf8'));
  const entries = site(gitReader(commit));
  const name = `sh20-vault-${version}`;
  const pkg = tar(entries, name);
  return { version, name, entries, pkg, sha256: sha256(pkg), cid: ipfsCid(entries), bytes: pkg.length };
}

const HEAD_TEXT = `# Vault releases

Each release is built by \`npm run release\` from the git objects of one commit, so anyone can
rebuild it and get the same bytes. The package holds exactly the static site: no script from
another domain, no CDN (see the CSP in \`vault/index.html\`).

## How to verify a release

\`\`\`sh
git clone https://github.com/sh20-standard/SH-20 && cd SH-20
git checkout <commit>
node vault/release.js --check <sha256>        # rebuilds; prints OK only if the bytes match
shasum -a 256 vault/release/sh20-vault-<version>.tar            # same SHA-256 (or sha256sum)
ipfs add -r --cid-version=1 --only-hash -Q vault/release/sh20-vault-<version>   # same CID
\`\`\`

The CID is the fingerprint of what IPFS serves: open \`https://<cid>.ipfs.dweb.link/vault/\`, or
better a local IPFS node (\`ipfs get <cid>\` checks every block against the CID).
A public gateway is trusted to serve the right blocks; a local node or a verifying client is not.
`;

function entryText(r, commit) {
  return `## ${r.version}

- Source commit: \`${commit}\`
- Package: \`${r.name}.tar\`, ${r.bytes} bytes, ${r.entries.length} files
- SHA-256: \`${r.sha256}\`
- IPFS CID: \`${r.cid}\`
`;
}

function record(r, commit) {
  const file = join(here, 'RELEASES.md');
  let text = existsSync(file) ? readFileSync(file, 'utf8') : HEAD_TEXT;
  const re = new RegExp(`## ${r.version.replace(/\./g, '\\.')}\\n[\\s\\S]*?SHA-256: \`([0-9a-f]{64})\``);
  const m = text.match(re);
  if (m && m[1] !== r.sha256) {
    throw new Error(`version ${r.version} is already released with SHA-256 ${m[1]}; bump the version in vault/package.json`);
  }
  if (m) return false; // same bytes: already recorded
  const at = text.indexOf('\n## ', text.indexOf('## How to verify') + 1);
  text = at < 0 ? `${text.trimEnd()}\n\n${entryText(r, commit)}` : `${text.slice(0, at + 1)}${entryText(r, commit)}\n${text.slice(at + 1)}`;
  writeFileSync(file, text);
  return true;
}

function main(argv) {
  const commit = git('rev-parse', 'HEAD').toString('utf8').trim();
  const dirty = git('status', '--porcelain', '--', 'vault', 'indexer/src', 'LICENSE').toString('utf8')
    .split('\n').filter((l) => l && !l.endsWith('vault/RELEASES.md') && !/ vault\/(dist|release)\//.test(l));
  if (dirty.length) console.warn(`note: uncommitted changes are NOT in the release (built from ${commit.slice(0, 12)}):\n${dirty.join('\n')}\n`);

  const r = buildRelease(commit);
  const i = argv.indexOf('--check');
  if (i >= 0) {
    const want = argv[i + 1];
    if (r.sha256 === want) {
      console.log(`OK ${r.name}: SHA-256 ${r.sha256}, IPFS CID ${r.cid} (commit ${commit})`);
      return;
    }
    console.error(`MISMATCH ${r.name}: built ${r.sha256}, expected ${want} (commit ${commit})`);
    process.exitCode = 1;
    return;
  }

  const out = join(here, 'release');
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, `${r.name}.tar`), r.pkg);
  writeSite(r.entries, join(out, r.name));
  const added = record(r, commit);
  console.log(`${r.name} from commit ${commit}`);
  console.log(`  release/${r.name}.tar  ${r.bytes} bytes, ${r.entries.length} files`);
  console.log(`  SHA-256   ${r.sha256}`);
  console.log(`  IPFS CID  ${r.cid}`);
  console.log(added ? '  recorded in vault/RELEASES.md: commit it' : '  already in vault/RELEASES.md');
  console.log(`  publish:  ipfs add -r --cid-version=1 --pin release/${r.name}   (must print the same CID)`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
