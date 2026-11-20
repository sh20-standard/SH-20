import { renderDeploy } from './deploy-panel.js';
import { renderNotes } from './notes-panel.js';
import { renderSend } from './send-panel.js';
import { renderTokens } from './tokens-panel.js';
import { renderVault, renderWallet } from './vault-panel.js';

// renderAll: every panel, after a change of state.

export function renderAll() {
  renderVault();
  renderWallet();
  renderTokens();
  renderDeploy();
  renderNotes();
  renderSend();
}
