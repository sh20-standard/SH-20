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
// `npm run build` writes it to vault/dist/ from the working tree (development), on the test profile;
// `node build.js --signet` on the signet profile. `npm run release` builds the same file set from a
// git commit (release.js), always on the signet profile.
//
// The profile is the one file that differs: vault/src/profile-name.js says 'test' in the source tree,
// and a signet build replaces it with SIGNET_NAME_MODULE. It refuses while vault/src/profile.js has
// no signet activation height (SIGNET_ACTIVATION_HEIGHT = null).
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
export const CIRCUIT_JS = ['address.js', 'babyjub.js', 'eddsa.js', 'notes.js', 'seal.js', 'subtle.js', 'webcrypto.js'];
// The prover's host side and pool thread, unchanged (circuit/web), and the shipped proving key.
export const CIRCUIT_WEB = ['host.js', 'thread-worker.js'];
export const PROVING_KEY = 'circuit/artifacts/spend.pk';
export const PROVER = ['sh20_circuit.wasm', 'sh20_circuit_threads.wasm']; // vault/prover/, tools/prover.sh

export const PROFILE_NAME_MODULE = 'vault/src/profile-name.js';
export const SIGNET_NAME_MODULE = `// Which profile of profile.js this page follows: a release, on the signet profile (build.js).
export const PROFILE_NAME = 'signet';
`;

/** The signet activation height in vault/src/profile.js as `reader` has it, or null while it is not fixed. */
export function signetActivation(reader) {
  const m = reader.read('vault/src/profile.js').toString('utf8').match(/^export const SIGNET_ACTIVATION_HEIGHT = (null|0|[1-9]\d*);$/m);
  if (!m) throw new Error('vault/src/profile.js: no SIGNET_ACTIVATION_HEIGHT line');
  return m[1] === 'null' ? null : Number(m[1]);
}

const REDIRECT = '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=vault/"><title>SH-20 Vault</title><a href="vault/">SH-20 Vault</a>\n';

/**
 * The site as sorted [path, bytes] pairs. `reader` gives repository files:
 *   list(dir) → repository paths of every file under dir (posix)
 *   read(path) → Buffer
 */
export function site(reader, { signet = false } = {}) {
  const files = new Map();
  for (const p of ['vault/index.html', 'vault/style.css', ...reader.list('vault/src'), ...INDEXER.map((f) => `indexer/src/${f}`), ...CIRCUIT_JS.map((f) => `circuit/js/${f}`), ...CIRCUIT_WEB.map((f) => `circuit/web/${f}`), PROVING_KEY, ...PROVER.map((f) => `vault/prover/${f}`), 'LICENSE']) {
    files.set(p, reader.read(p));
  }
  if (signet) {
    if (signetActivation(reader) === null) throw new Error('no signet build: the signet activation height is not fixed (vault/src/profile.js SIGNET_ACTIVATION_HEIGHT; vault/RELEASES.md)');
    if (!/^export const PROFILE_NAME = 'test';$/m.test(files.get(PROFILE_NAME_MODULE).toString('utf8'))) throw new Error(`${PROFILE_NAME_MODULE}: not the source tree's`);
    files.set(PROFILE_NAME_MODULE, Buffer.from(SIGNET_NAME_MODULE));
  }
  files.set('index.html', Buffer.from(REDIRECT));
  // the isolation service worker at the root, so that its scope covers circuit/web/ too (src/isolation.js)
  files.set('sw.js', reader.read('vault/sw.js'));

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
  const signet = process.argv.includes('--signet');
  const entries = site(fsReader(), { signet });
  const dist = join(here, 'dist');
  writeSite(entries, dist);
  let total = 0;
  for (const [p, b] of entries) {
    total += b.length;
    console.log(`${sha256(b)}  ${p}`);
  }
  console.log(`\n${entries.length} files, ${(total / 1024).toFixed(1)} KiB in vault/dist (working tree, ${signet ? 'signet' : 'test'} profile; use npm run release for a release)`);
}
