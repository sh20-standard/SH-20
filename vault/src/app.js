// SH-20 vault page. Plain DOM, no framework; data from the network is only
// ever written with textContent. The panels are in src/ui/, one module per screen or flow;
// this file runs the page's checks first, then starts them.

import { ensureIsolation } from './isolation.js';
import { available } from './sh20.js';
import { initContext, setIsolation, busy, $, staticWarnings } from './ui/context.js';
import { initSettings } from './ui/settings-panel.js';
import { renderAll } from './ui/render.js';
import { refresh } from './ui/tokens-panel.js';
import { renderWallet } from './ui/vault-panel.js';
import { syncNotes } from './ui/notes-panel.js';
import { startDeployTimer } from './ui/deploy-panel.js';

if (window.top !== window.self) {
  document.documentElement.textContent = 'The SH-20 vault refuses to run inside a frame.';
  throw new Error('framed');
}

// On a subdomain gateway the page isolates itself with the service worker and reloads once
// (isolation.js), before anything else runs; never on a path gateway.
const isolation = await ensureIsolation();
if (isolation === 'reloading') await new Promise(() => {});

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
