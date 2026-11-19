// Cross-origin isolation, which gives the page shared memory and so the prover's thread pool
// (4.7 s a proof on a laptop instead of 26 s on one thread). Servers that send COOP/COEP isolate
// the page themselves; public IPFS gateways do not. On a subdomain gateway (<cid>.ipfs.<host>,
// one origin per CID) the vault registers the phone test page's service worker (vault/sw.js, the
// same bytes as circuit/web/sw.js), which re-serves the page's own responses with the headers, and
// reloads once. Never on a path gateway (…/ipfs/<cid>/): there every site shares one origin, and a
// service worker of ours would sit in front of all of them.

export const canShare = () => globalThis.crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';

/** 'path' (…/ipfs/<cid>/), 'subdomain' (<cid>.ipfs.<host>, <name>.ipns.<host>) or 'other'. */
export function gatewayKind(loc = globalThis.location) {
  if (/^\/ip[fn]s\//.test(loc.pathname)) return 'path';
  if (/^[a-z0-9-]+\.ip[fn]s\.[^.]/i.test(loc.hostname)) return 'subdomain';
  return 'other';
}

/**
 * 'headers' (isolated already), 'reloading' (the worker is in place: the page reloads through it),
 * or why the page stays on one thread: 'not-a-subdomain-gateway', 'unavailable', 'refused'.
 * The same steps as circuit/web/app.js `ensureIsolation`, limited to subdomain gateways.
 */
export async function ensureIsolation() {
  if (canShare()) return 'headers';
  if (gatewayKind() !== 'subdomain') return 'not-a-subdomain-gateway';
  if (!globalThis.isSecureContext || !('serviceWorker' in navigator)) return 'unavailable';
  try {
    const registration = await navigator.serviceWorker.register(new URL('../sw.js', import.meta.url));
    if (navigator.serviceWorker.controller) return 'refused'; // already controlled and still not isolated
    if (sessionStorage.getItem('sh20-isolation-reload')) return 'refused';
    sessionStorage.setItem('sh20-isolation-reload', '1');
    await new Promise((done) => {
      const worker = registration.installing || registration.waiting || registration.active;
      if (!worker || worker.state === 'activated') done();
      else worker.addEventListener('statechange', () => worker.state === 'activated' && done());
    });
    location.reload(); // the reloaded page is served through the service worker, with the headers
    return 'reloading';
  } catch {
    return 'unavailable';
  }
}
