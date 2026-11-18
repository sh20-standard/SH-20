// Assembles the static site for IPFS in vault/dist/, keeping the repository
// layout so the vault imports the indexer's codec unchanged:
//
//   dist/index.html            → redirects to vault/
//   dist/vault/…               → this folder (page, styles, src/)
//   dist/indexer/src/…         → only the indexer modules the vault loads
//
// Publish with:  ipfs add -r --cid-version=1 vault/dist
// Zero dependencies; the output is byte-identical across runs.

import { cpSync, mkdirSync, rmSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const dist = join(here, 'dist');

// The indexer modules reachable from vault/src/sh20.js.
const INDEXER = ['codec.js', 'constants.js', 'notes.js', 'poseidon.js'];

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'vault'), { recursive: true });
mkdirSync(join(dist, 'indexer', 'src'), { recursive: true });

cpSync(join(here, 'index.html'), join(dist, 'vault', 'index.html'));
cpSync(join(here, 'style.css'), join(dist, 'vault', 'style.css'));
cpSync(join(here, 'src'), join(dist, 'vault', 'src'), { recursive: true });
for (const f of INDEXER) cpSync(join(root, 'indexer', 'src', f), join(dist, 'indexer', 'src', f));
cpSync(join(root, 'LICENSE'), join(dist, 'LICENSE'));
writeFileSync(join(dist, 'index.html'), '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=vault/"><title>SH-20 Vault</title><a href="vault/">SH-20 Vault</a>\n');

// Check that every relative import in dist resolves inside dist.
const files = [];
const walk = (d) => readdirSync(d).sort().forEach((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : files.push(join(d, f))));
walk(dist);
for (const f of files.filter((x) => x.endsWith('.js'))) {
  for (const [, spec] of readFileSync(f, 'utf8').matchAll(/(?:from|import)\s*\(?\s*'(\.[^']+)'/g)) {
    const target = join(dirname(f), spec);
    if (!files.includes(target)) throw new Error(`${relative(dist, f)} imports ${spec}, missing from dist`);
  }
}

let total = 0;
const manifest = files.map((f) => {
  const b = readFileSync(f);
  total += b.length;
  return `${createHash('sha256').update(b).digest('hex')}  ${relative(dist, f)}`;
});
console.log(manifest.join('\n'));
console.log(`\n${files.length} files, ${(total / 1024).toFixed(1)} KiB in ${relative(process.cwd(), dist) || '.'}`);
