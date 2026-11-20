// The vault and wallet panels: create, unlock or restore the vault (12 recovery words, backup),
// and connect the Bitcoin wallet that pays the fees.

import { addressToScript, scriptType } from '../btc.js';
import { Vault } from '../keys.js';
import { WALLETS } from '../wallets.js';
import { busy, fill, h, report, st } from './context.js';
import { syncNotes } from './notes-panel.js';
import { renderAll } from './render.js';

// ---- vault ----------------------------------------------------------------------

export function renderVault() {
  if (st.vault) {
    const v = st.vault;
    fill('vault-body',
      h('p', {}, h('span', { class: 'ok' }, 'Unlocked. '), `${v.state.next} public note key(s) used, ${v.encrypted ? 'encrypted with your passphrase' : 'stored without passphrase'}.`),
      h('p', {}, 'Your sh20 address (signet), for receiving sealed notes: '),
      h('p', { class: 'mono', id: 'address' }, v.address),
      v.state.obsolete?.length ? h('p', { class: 'muted' }, `${v.state.obsolete.length} note(s) made with the provisional keys of draft v0.2 are kept aside in the backup: they cannot exist on a v0.3 chain.`) : null,
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'secondary', onclick: () => navigator.clipboard?.writeText(v.address).catch(report) }, 'Copy address'),
        v.words ? h('button', { type: 'button', class: 'secondary', onclick: () => { st.showWords = !st.showWords; renderVault(); } }, st.showWords ? 'Hide recovery words' : 'Show recovery words') : null,
        h('button', { type: 'button', class: 'secondary', onclick: downloadBackup }, 'Download backup'),
        h('button', { type: 'button', class: 'secondary', onclick: () => { v.lock(); st.vault = null; st.showWords = false; renderAll(); } }, 'Lock')),
      st.showWords && v.words ? wordsBox(v.words) : null,
      h('p', { class: 'muted' }, v.words
        ? 'The 12 recovery words restore everything (keys, notes, address) in any wallet that follows SPEC-NOTES. Write them on paper; anyone who reads them owns your notes. A new version of this page on IPFS has a new origin and an empty storage: restore there from the words or the backup.'
        : 'This vault was made before recovery words existed: only its backup file restores it (encrypted if you set a passphrase).'));
    return;
  }
  if (Vault.exists(localStorage)) {
    const pass = h('input', { type: 'password', placeholder: 'passphrase (empty if none)', autocomplete: 'current-password' });
    const btn = h('button', { type: 'submit' }, 'Unlock');
    const form = h('form', { class: 'row' }, pass, btn);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(btn, async () => {
        st.vault = await Vault.open(localStorage, pass.value);
        renderAll();
        syncNotes().catch(report);
      })();
    });
    fill('vault-body', h('p', {}, 'A vault exists on this device.'), form);
    return;
  }
  const pass = h('input', { type: 'password', placeholder: 'passphrase (recommended)', autocomplete: 'new-password' });
  const create = h('button', { type: 'submit' }, 'Create vault');
  const form = h('form', { class: 'row' }, pass, create);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    busy(create, async () => {
      if (!pass.value && !confirm('Create the vault without a passphrase? Anyone using this browser profile could read it.')) return;
      st.vault = await Vault.create(localStorage, pass.value);
      st.showWords = true; // shown once on creation, to be written down
      navigator.storage?.persist?.().catch(() => {});
      renderAll();
    })();
  });
  const file = h('input', { type: 'file', accept: '.json,application/json' });
  const rpass = h('input', { type: 'password', placeholder: 'backup passphrase', autocomplete: 'off' });
  const restore = h('button', { type: 'button', class: 'secondary' }, 'Restore backup');
  restore.addEventListener('click', busy(restore, async () => {
    if (!file.files[0]) throw new Error('choose a backup file');
    st.vault = await Vault.restore(localStorage, await file.files[0].text(), rpass.value);
    renderAll();
    syncNotes({ full: true }).catch(report); // a restored vault looks for its notes in every leaf
  }));
  const words = h('textarea', { rows: '2', name: 'words', spellcheck: 'false', autocomplete: 'off', placeholder: '12 recovery words' });
  const wpass = h('input', { type: 'password', placeholder: 'new passphrase for this device', autocomplete: 'new-password' });
  const fromWords = h('button', { type: 'button', class: 'secondary' }, 'Restore from words');
  fromWords.addEventListener('click', busy(fromWords, async () => {
    st.vault = await Vault.fromWords(localStorage, words.value, wpass.value);
    words.value = '';
    renderAll();
    syncNotes({ full: true }).catch(report); // looks for its notes in every leaf
  }));
  fill('vault-body',
    h('p', {}, 'No vault on this device. Its 12 recovery words are generated here and never leave it.'),
    form,
    h('p', { class: 'muted' }, 'Or restore one:'),
    h('label', {}, 'From its recovery words', words),
    h('div', { class: 'row' }, wpass, fromWords),
    h('div', { class: 'row' }, file, rpass, restore));
}

function wordsBox(words) {
  return h('div', { class: 'words' },
    h('p', {}, h('strong', {}, 'Recovery words. '), 'Write them down in this order and keep them offline.'),
    h('ol', { id: 'words' }, words.split(' ').map((w) => h('li', { class: 'mono' }, w))));
}

function downloadBackup() {
  const blob = new Blob([st.vault.exportBackup()], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'sh20-vault-backup.json' });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---- wallet ----------------------------------------------------------------------

export function renderWallet() {
  if (st.wallet) {
    const w = st.wallet;
    fill('wallet-body',
      h('p', {}, h('span', { class: 'ok' }, `${w.adapter.name} connected: `), h('code', {}, w.address), ` (${w.type})`),
      h('button', { type: 'button', class: 'secondary', onclick: () => { st.wallet = null; renderAll(); } }, 'Disconnect'));
    return;
  }
  fill('wallet-body', h('div', { class: 'row' }, WALLETS.map((ad) => {
    const b = h('button', { type: 'button', disabled: !ad.detect() }, ad.name);
    b.addEventListener('click', busy(b, async () => {
      const acc = await ad.connect();
      let type;
      try {
        type = scriptType(addressToScript(acc.address));
      } catch {
        throw new Error(`${ad.name} gave ${acc.address}, which is not a signet address. Switch the wallet to Signet.`);
      }
      // a second address of the wallet (Xverse's and Leather's taproot one): only a cancel's change goes there
      let otherAddress = null;
      try {
        if (acc.otherAddress && acc.otherAddress !== acc.address) otherAddress = (addressToScript(acc.otherAddress), acc.otherAddress);
      } catch {}
      st.wallet = { adapter: ad, ...acc, type, otherAddress };
      renderAll();
    }));
    return b;
  })), h('p', { class: 'muted' }, WALLETS.some((w) => w.detect()) ? 'Pick a wallet set to Signet.' : 'No wallet extension detected (Xverse, UniSat or Leather).'));
}
