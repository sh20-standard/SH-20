// Reading the static mirror of the API (docs/API.md, "The static mirror"): the answer to an API route, worked out from
// the mirror's files, as the indexer the mirror was built from would give it. No dependency and no Node API: the
// explorer carries this file inside its page (explorer/build-demo.mjs inlines everything above the exports), and a
// wallet can do the same.
//
// `read(name)` fetches one file of the mirror (`status.json`, `block/12.json`, …) and resolves its JSON; for a file the
// mirror does not hold it rejects with an error whose `status` is 404, which mirrorGet passes on: the route's own 404.

const MIRROR_FORMAT = 'sh20-api-mirror/1';
// What a mirror is built with, by default; a reader takes the sizes from the mirror's own mirror.json.
const MIRROR_NOTE_PAGE = 1000; // leaves per notes/<k>.json
const MIRROR_BLOCK_PAGE = 200; // blocks in blocks.json, the newest with activity
const MIRROR_NOTE_LIMIT = 5000; // the API's own caps on `limit`
const MIRROR_BLOCK_LIMIT = 200;

/** A route the mirror does not serve (`/path/:pos`): ask a live indexer. Its `status` is 501. */
class NotInMirror extends Error {
  constructor(route) {
    super(`${route}: not in the mirror`);
    this.status = 501;
  }
}

function badRequest(route) {
  return Object.assign(new Error(`${route}: bad request`), { status: 400 });
}

const isMissing = (e) => e && e.status === 404;

/**
 * The answer to `route` (a path with its query, as given to a live indexer) from the files of a mirror.
 * @param {string} route
 * @param {(name: string) => Promise<any>} read
 */
async function mirrorGet(route, read) {
  const url = new URL(route, 'http://mirror.invalid');
  const path = url.pathname;
  const int = (name, def) => {
    const v = url.searchParams.get(name);
    if (v === null) return def;
    if (!/^[0-9]+$/.test(v)) throw badRequest(route);
    return Number(v);
  };
  let m;
  if (path === '/status' || path === '/tokens') return read(path.slice(1) + '.json');
  if ((m = /^\/token\/([^/]+)$/.exec(path))) {
    if (!/^[A-Z0-9]{4}$/.test(m[1])) throw badRequest(route);
    return read(`token/${m[1]}.json`);
  }
  if ((m = /^\/(listing|tx)\/([^/]+)$/.exec(path))) {
    if (!/^[0-9a-f]{64}$/.test(m[2])) throw badRequest(route);
    return read(`${m[1]}/${m[2]}.json`);
  }
  if ((m = /^\/(block|digest)\/([^/]+)$/.exec(path))) {
    if (!/^[0-9]+$/.test(m[2])) throw badRequest(route);
    return read(`${m[1]}/${Number(m[2])}.json`);
  }
  if (path === '/listings') {
    const state = url.searchParams.get('state');
    if (state !== null && !['ACTIVE', 'SOLD', 'CANCELLED', 'CLOSED', 'CLAIMED'].includes(state)) throw badRequest(route);
    const all = await read('listings.json');
    return state === null ? all : all.filter((l) => l.state === state);
  }
  if (path === '/nullifiers') {
    const all = await read('nullifiers.json');
    const from = int('from', all.from);
    return { from, height: all.height, nullifiers: all.nullifiers.filter((n) => n.height >= from) };
  }
  if ((m = /^\/nullifier\/([^/]+)$/.exec(path))) {
    if (!/^[0-9a-f]{64}$/.test(m[1])) throw badRequest(route);
    const all = await read('nullifiers.json');
    return { nullifier: m[1], spent: all.nullifiers.some((n) => n.nullifier === m[1]) };
  }
  if (path === '/roots') return roots(int('from', null), read);
  if (path === '/notes') return notes(int('from', 0), Math.min(int('limit', 1000), MIRROR_NOTE_LIMIT), read);
  if (path === '/blocks') return blocks(int('before', null), Math.min(int('limit', 20), MIRROR_BLOCK_LIMIT), read);
  throw new NotInMirror(route);
}

// roots.json holds the window (`/roots` with its default `from`, the tip − W); an older root is in its block's file.
async function roots(from, read) {
  const window = await read('roots.json');
  if (from === null) return window;
  const out = window.filter((r) => r.height >= from);
  const status = await read('status.json');
  if (status.height === null) return out;
  const first = window.length ? window[0].height : status.height + 1;
  const older = [];
  for (let h = Math.max(from, status.activationHeight); h < first; h++) {
    const b = await read(`block/${h}.json`);
    older.push({ height: h, root: b.root });
  }
  return [...older, ...out];
}

// notes/<k>.json is `/notes?from=k·P&limit=P`: the pages that cover [from, from + limit), cut to it.
async function notes(from, limit, read) {
  const P = (await read('mirror.json')).notePage;
  let total = null;
  const out = [];
  for (let k = Math.floor(from / P); limit > 0 && out.length < limit; k++) {
    if (total !== null && k * P >= total) break;
    let page;
    try {
      page = await read(`notes/${k}.json`);
    } catch (e) {
      if (!isMissing(e)) throw e;
      break; // past the last page
    }
    total = page.total;
    const start = Math.max(from - k * P, 0);
    out.push(...page.notes.slice(start, start + limit - out.length));
  }
  if (total === null) total = (await read('notes/0.json')).total;
  return { from, total, notes: out };
}

// blocks.json is `/blocks?limit=B` (B = 200), the newest blocks with activity; older ones are read block by block.
async function blocks(before, limit, read) {
  const page = await read('blocks.json');
  const out = page.filter((b) => before === null || b.height < before).slice(0, limit);
  if (out.length >= limit || page.length < (await read('mirror.json')).blockPage) return out;
  const status = await read('status.json');
  const lowest = page.length ? page[page.length - 1].height : status.height + 1;
  for (let h = Math.min(lowest, before ?? lowest) - 1; h >= status.activationHeight && out.length < limit; h--) {
    const b = await read(`block/${h}.json`);
    if (b.events.length || b.rejected.length) out.push(b);
  }
  return out;
}

// -- exports (not inlined) --
export { MIRROR_FORMAT, MIRROR_NOTE_PAGE, MIRROR_BLOCK_PAGE, NotInMirror, mirrorGet };
