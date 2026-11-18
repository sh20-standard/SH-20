// Assembles the static site, keeping the repository layout so the vault
// imports the indexer's codec unchanged:
//
//   index.html            → redirects to vault/
//   vault/…               → the page, styles and src/
//   indexer/src/…         → only the indexer modules the vault loads
//   circuit/js/…          → the wallet reference (note keys, addresses, sealing, signatures), unchanged
//   circuit/web/…         → the prover's host side and pool thread, unchanged
//   circuit/artifacts/spend.pk, vault/prover/*.wasm → the proving key and the two prover builds
//   LICENSE
//
// `npm run build` writes it to vault/dist/ from the working tree (development).
// `npm run release` builds the same file set from a git commit (release.js).
// Zero dependencies; the same inputs always give the same bytes.

import { mkdirSync, rmSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, posix } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// The indexer modules reachable from vault/src/sh20.js.
export const INDEXER = ['carrier.js', 'codec.js', 'constants.js', 'notes.js', 'poseidon.js', 'schnorr.js', 'tree.js'];
// The circuit/js modules reachable from vault/src/sh20.js (docs/SPEC-NOTES.md).
export const CIRCUIT_JS = ['address.js', 'babyjub.js', 'eddsa.js', 'notes.js', 'seal.js'];
// The prover's host side and pool thread, unchanged (circuit/web), and the shipped proving key.
export const CIRCUIT_WEB = ['host.js', 'thread-worker.js'];
export const PROVING_KEY = 'circuit/artifacts/spend.pk';
export const PROVER = ['sh20_circuit.wasm', 'sh20_circuit_threads.wasm']; // vault/prover/, tools/prover.sh

const REDIRECT = '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=vault/"><title>SH-20 Vault</title><a href="vault/">SH-20 Vault</a>\n';

/**
 * The site as sorted [path, bytes] pairs. `reader` gives repository files:
 *   list(dir) → repository paths of every file under dir (posix)
 *   read(path) → Buffer
 */
export function site(reader) {
  const files = new Map();
  for (const p of ['vault/index.html', 'vault/style.css', ...reader.list('vault/src'), ...INDEXER.map((f) => `indexer/src/${f}`), ...CIRCUIT_JS.map((f) => `circuit/js/${f}`), ...CIRCUIT_WEB.map((f) => `circuit/web/${f}`), PROVING_KEY, ...PROVER.map((f) => `vault/prover/${f}`), 'LICENSE']) {
    files.set(p, reader.read(p));
  }
  files.set('index.html', Buffer.from(REDIRECT));

  // every relative import must resolve inside the site
  for (const [p, b] of files) {
    if (!p.endsWith('.js')) continue;
    for (const [, spec] of b.toString('utf8').matchAll(/(?:from|import)\s*\(?\s*'(\.[^']+)'/g)) {
      const target = posix.normalize(posix.join(posix.dirname(p), spec));
      if (!files.has(target)) throw new Error(`${p} imports ${spec}, missing from the site`);
    }
  }
  return [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Reads the working tree. */
export function fsReader(base = root) {
  const list = (dir) => {
    const out = [];
    const walk = (d) => {
      for (const f of readdirSync(join(base, d)).sort()) {
        const p = `${d}/${f}`;
        if (statSync(join(base, p)).isDirectory()) walk(p);
        else out.push(p);
      }
    };
    walk(dir);
    return out;
  };
  return { list, read: (p) => readFileSync(join(base, p)) };
}

export function writeSite(entries, dir) {
  rmSync(dir, { recursive: true, force: true });
  for (const [p, b] of entries) {
    mkdirSync(join(dir, dirname(p)), { recursive: true });
    writeFileSync(join(dir, p), b);
  }
}

export const sha256 = (b) => createHash('sha256').update(b).digest('hex');

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const entries = site(fsReader());
  const dist = join(here, 'dist');
  writeSite(entries, dist);
  let total = 0;
  for (const [p, b] of entries) {
    total += b.length;
    console.log(`${sha256(b)}  ${p}`);
  }
  console.log(`\n${entries.length} files, ${(total / 1024).toFixed(1)} KiB in vault/dist (working tree; use npm run release for a release)`);
}
