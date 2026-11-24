// SH-20 vault page. Plain DOM, no framework; data from the network is only
// ever written with textContent. The panels are in src/ui/, one module per screen or flow;
// this file runs the page's checks first, then starts them.

import { ensureIsolation, gatewayKind, ownOrigins } from './isolation.js';
import { available } from './sh20.js';
import { STORAGE_KEY } from './keys.js';
import { initContext, setIsolation, busy, $, h, st, staticWarnings, NET } from './ui/context.js';
import { initSettings } from './ui/settings-panel.js';
import { renderAll } from './ui/render.js';
import { refresh } from './ui/tokens-panel.js';
import { AUTO_LOCK_NOTE, lockHeld, lockVault, renderWallet } from './ui/vault-panel.js';
import { autoLock } from './autolock.js';
import { syncNotes } from './ui/notes-panel.js';
import { startDeployTimer } from './ui/deploy-panel.js';

if (window.top !== window.self) {
  document.documentElement.textContent = 'The SH-20 vault refuses to run inside a frame.';
  throw new Error('framed');
}

// On a path gateway (…/ipfs/<cid>/) every site of the gateway has this page's origin: it could read
// the stored vault, rewrite the saved servers, or script the page once unlocked (docs/AUDIT.md §8.1).
// Nothing runs there, not even the settings: the page says where the same release has an origin of its own.
if (gatewayKind() === 'path') {
  const [subdomain, local] = ownOrigins();
  const link = (u) => h('a', { href: u, class: 'mono', rel: 'noreferrer' }, u);
  let stored = false;
  try {
    stored = localStorage.getItem(STORAGE_KEY) !== null;
  } catch {}
  document.querySelector('main').replaceChildren(h('section', { id: 'path-gateway' },
    h('h2', {}, 'Open the vault from its own origin'),
    h('p', {}, 'This page is served from a path gateway (…/ipfs/<cid>/). Every site on this gateway shares one origin with it: any of them could read a vault stored here, change its servers, or drive it once unlocked. The vault does not create, restore or unlock anything here.'),
    h('p', {}, 'Open the same release from a subdomain gateway, where it has an origin of its own:'),
    h('ul', {}, h('li', {}, link(subdomain)), h('li', {}, 'a local IPFS node: ', link(local)), h('li', {}, 'or a local copy, checked as vault/RELEASES.md says')),
    h('p', { class: 'muted' }, 'Check that the CID is the one of a release listed in vault/RELEASES.md. The vault is empty at the new address: restore it from its 12 recovery words or its backup file.'),
    stored ? h('p', { class: 'warn err' }, 'A vault from an earlier version of this page is stored at this origin, where every site on this gateway can read it. Treat its recovery words as exposed: create a new vault at one of the addresses above and send your notes to it.') : null));
  document.getElementById('warnings').replaceChildren();
  await new Promise(() => {});
}

// On a subdomain gateway the page isolates itself with the service worker and reloads once
// (isolation.js), before anything else runs; never on a path gateway. If the reload is dropped, the
// page goes on with one thread.
const isolation = await ensureIsolation();

// Note keys and sealing go through WebCrypto's X25519 (circuit/js/webcrypto.js): without it, stop here.
if (!(await available())) {
  document.querySelector('main').replaceChildren();
  document.getElementById('warnings').textContent = window.isSecureContext
    ? 'This browser has no X25519 in WebCrypto, which the vault needs for its keys and sealed notes: use Chrome 133, Firefox 130, Safari 17 or newer.'
    : 'WebCrypto needs a secure context: open the vault over https, or from localhost.';
  document.getElementById('warnings').className = 'warn err';
  await new Promise(() => {});
}

setIsolation(isolation);
initContext(); // the servers, after the checks: a link's servers are confirmed in a dialog
$('network-tag').textContent = `${NET} · draft v0.3`; // the profile's network (profile.js CHAIN)

// ---- boot ------------------------------------------------------------------------

staticWarnings();
initSettings();
renderAll();
refresh();
$('refresh').addEventListener('click', busy($('refresh'), refresh));
$('scan').addEventListener('click', busy($('scan'), () => syncNotes()));
$('rescan').addEventListener('click', busy($('rescan'), () => syncNotes({ full: true })));
// extensions inject their providers a little after load
setTimeout(renderWallet, 600);
startDeployTimer();

// Another tab of this browser wrote the vault (a passphrase set or changed, notes recorded): this
// tab's copy is stale, and writing it back would undo that. It locks, to be unlocked again.
window.addEventListener('storage', (ev) => {
  if (ev.key !== STORAGE_KEY || !st.vault) return;
  st.vault.lock();
  lockVault('The vault was changed in another tab of this browser: this tab locked it. Unlock it again to see the same state.');
});

// Without use, the vault locks itself and its keys leave the page's memory (docs/AUDIT.md §8.8);
// never in the middle of an action, nor while a DEPLOY waits for the reveal this page sends.
autoLock({ unlocked: () => st.vault !== null, held: lockHeld, lock: () => lockVault(AUTO_LOCK_NOTE) });
