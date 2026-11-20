// Cross-origin isolation, which gives the page shared memory and so the prover's thread pool
// (4.7 s a proof on a laptop instead of 26 s on one thread). Servers that send COOP/COEP isolate
// the page themselves; public IPFS gateways do not. On a subdomain gateway (<cid>.ipfs.<host>,
// one origin per CID) the vault registers the phone test page's service worker (the same bytes as
// circuit/web/sw.js), which re-serves the page's own responses with the headers, and reloads once.
// It is served at the root of the site (the build copies vault/sw.js there) with the root as its
// scope: the pool's threads are circuit/web/thread-worker.js, outside vault/, and a worker the
// service worker does not control would get no headers and no shared memory. On a subdomain
// gateway the root is the CID's: it covers this site's files and nothing else. Never on a path gateway (…/ipfs/<cid>/): there every site shares one origin, and a
// service worker of ours would sit in front of all of them.

export const canShare = () => globalThis.crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';

/** 'path' (…/ipfs/<cid>/), 'subdomain' (<cid>.ipfs.<host>, <name>.ipns.<host>) or 'other'. */
export function gatewayKind(loc = globalThis.location) {
  if (/^\/ip[fn]s\//.test(loc.pathname)) return 'path';
  if (/^[a-z0-9-]+\.ip[fn]s\.[^.]/i.test(loc.hostname)) return 'subdomain';
  return 'other';
}

/**
 * Where to open the page instead of a path gateway (docs/AUDIT.md §8.1), or null when `loc` is not
 * one: the same CID (or IPNS name) on a subdomain gateway, where it has an origin of its own, and
 * on a local IPFS node. The query string is left out: servers come from the settings, or from a
 * link the user confirms there.
 */
export function ownOrigins(loc = globalThis.location) {
  const m = /^\/(ip[fn]s)\/([^/]+)(\/.*)?$/.exec(loc.pathname);
  if (!m) return null;
  const [, ns, id, rest = '/'] = m;
  // a DNSLink name fits in one DNS label as the gateways inline it: '-' becomes '--', '.' becomes '-'
  const label = ns === 'ipns' && id.includes('.') ? id.replace(/-/g, '--').replace(/\./g, '-') : id;
  // a CIDv0 (Qm…) or another case-sensitive name is no DNS label: the gateway's path form redirects
  // to its subdomain form (base32), with an origin of its own
  if (/^[a-z0-9-]{1,63}$/.test(label)) return [`https://${label}.${ns}.dweb.link${rest}`, `http://${label}.${ns}.localhost:8080${rest}`];
  return [`https://dweb.link/${ns}/${id}${rest}`, `http://localhost:8080/${ns}/${id}${rest}`];
}

/**
 * 'headers' (isolated already), or why the page stays on one thread: 'not-a-subdomain-gateway',
 * 'unavailable', 'refused'. When the worker is put in place the page reloads through it and this
 * never returns, unless the browser drops the reload: after `reloadWaitMs` the page goes on with
 * one thread ('refused') rather than stay blank. The same steps as circuit/web/app.js
 * `ensureIsolation`, limited to subdomain gateways.
 */
export async function ensureIsolation({ reloadWaitMs = 5000 } = {}) {
  if (canShare()) return 'headers';
  if (gatewayKind() !== 'subdomain') return 'not-a-subdomain-gateway';
  if (!globalThis.isSecureContext || !('serviceWorker' in navigator)) return 'unavailable';
  try {
    const registration = await navigator.serviceWorker.register(new URL('../../sw.js', import.meta.url), { scope: new URL('../../', import.meta.url).href });
    if (navigator.serviceWorker.controller) return 'refused'; // already controlled and still not isolated
    if (sessionStorage.getItem('sh20-isolation-reload')) return 'refused';
    sessionStorage.setItem('sh20-isolation-reload', '1');
    await new Promise((done) => {
      const worker = registration.installing || registration.waiting || registration.active;
      if (!worker || worker.state === 'activated') done();
      else worker.addEventListener('statechange', () => worker.state === 'activated' && done());
    });
    location.reload(); // the reloaded page is served through the service worker, with the headers
    // the browser can drop this reload (headless Chrome, when the page reloads with requests in flight through the worker)
    await new Promise((done) => setTimeout(done, reloadWaitMs));
    return 'refused';
  } catch {
    return 'unavailable';
  }
}
