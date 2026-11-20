// The settings panel: the indexers and the Esplora server, saved in this browser.

import { $, applySettings, report, settings, staticWarnings, urlList } from './context.js';
import { refresh } from './tokens-panel.js';

// ---- settings --------------------------------------------------------------------

export function initSettings() {
  const f = $('settings-form');
  f.indexer.value = urlList(settings.indexer).join('\n');
  f.esplora.value = settings.esplora;
  f.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const list = urlList(f.indexer.value);
    const bad = [...list, f.esplora.value.trim()].filter((u) => !/^https?:\/\/[^/\s]+/.test(u));
    if (!list.length || bad.length) return report(new Error(`not an http(s) URL: ${bad.join(', ') || '(no indexer)'}`));
    applySettings({ indexer: list.join('\n'), esplora: f.esplora.value.trim() });
    staticWarnings();
    refresh();
  });
}
