// The vault and wallet panels: create, unlock or restore the vault (12 recovery words, backup),
// and connect the Bitcoin wallet that pays the fees.

import { addressToScript, scriptType } from '../btc.js';
import { Vault } from '../keys.js';
import { WALLETS } from '../wallets.js';
import { LOCK_AFTER_MS } from '../autolock.js';
import { unloadProver } from '../prover.js';
import { $, NET, NET_TITLE, activity, busy, fill, h, report, result, resultBox, st } from './context.js';
import { syncNotes } from './notes-panel.js';
import { renderAll } from './render.js';

// ---- vault ----------------------------------------------------------------------

/**
 * Locks the vault: its keys leave this page's memory (keys.js lock()), and so does the prover's,
 * which may hold the witness of the last proof. `note` stays on screen to say why.
 */
export function lockVault(note) {
  st.vault?.lock();
  st.vault = null;
  st.showWords = false;
  st.vaultForm = null;
  st.vaultFormNode = null;
  unloadProver();
  renderAll();
  if (note) $('warnings').append(h('div', { class: 'warn' }, note));
}

/** Why the vault must not lock itself now (autolock.js), or null. */
export function lockHeld() {
  if (activity.running > 0) return 'an action is under way';
  if (!st.vault || st.vault.locked) return null;
  if ((st.vault.state.pending ?? []).some((p) => p.status === 'waiting maturity')) return 'a DEPLOY waits for its reveal, which this page sends';
  return null;
}

export const AUTO_LOCK_NOTE = `The vault locked itself after ${LOCK_AFTER_MS / 60000} minutes without use: its keys are no longer in this page's memory. Unlock it to go on.`;

export function renderVault() {
  if (st.vault) {
    const v = st.vault;
    const lock = () => lockVault();
    const held = lockHeld();
    // an open form is the same node across renders (a sync renders every panel): what is typed stays
    if (!st.vaultForm) st.vaultFormNode = null; // a closed form is made anew, empty, when opened again
    const keep = (kind, make) => (st.vaultFormNode?.kind === kind ? st.vaultFormNode.el : (st.vaultFormNode = { kind, el: make() }).el);
    // the words of an encrypted vault are shown after its passphrase, not to whoever finds it unlocked (AUDIT §8.4)
    const showWords = () => {
      if (st.showWords) st.showWords = false;
      else if (v.encrypted) st.vaultForm = st.vaultForm === 'words' ? null : 'words';
      else st.showWords = true;
      renderVault();
    };
    fill('vault-body',
      h('p', {}, h('span', { class: 'ok' }, 'Unlocked. '), `${v.state.next} public note key(s) reserved, ${v.encrypted ? 'encrypted with your passphrase' : 'stored without passphrase'}.`),
      h('p', { class: 'muted', id: 'autolock' }, held === 'a DEPLOY waits for its reveal, which this page sends'
        ? 'It stays unlocked while a DEPLOY waits for its reveal (this page sends it), then locks itself after ' + `${LOCK_AFTER_MS / 60000} minutes without use.`
        : `It locks itself after ${LOCK_AFTER_MS / 60000} minutes without use.`),
      v.encrypted ? null : h('p', { class: 'warn' }, 'Stored in clear on this device: anyone using this browser profile can read its keys. Set a passphrase: it encrypts this copy, and a backup file needs it.'),
      h('p', {}, `Your sh20 address (${NET}), for receiving sealed notes: `),
      h('p', { class: 'mono', id: 'address' }, v.address),
      v.state.obsolete?.length ? h('p', { class: 'muted' }, `${v.state.obsolete.length} note(s) made with the provisional keys of draft v0.2 are kept aside in the backup: they cannot exist on a v0.3 chain.`) : null,
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'secondary', onclick: () => navigator.clipboard?.writeText(v.address).catch(report) }, 'Copy address'),
        v.words ? h('button', { type: 'button', class: 'secondary', name: 'words', onclick: showWords }, st.showWords ? 'Hide recovery words' : 'Show recovery words') : null,
        h('button', { type: 'button', class: 'secondary', name: 'passphrase', onclick: () => { st.vaultForm = st.vaultForm === 'pass' ? null : 'pass'; renderVault(); } }, v.encrypted ? 'Change passphrase' : 'Set a passphrase'),
        h('button', { type: 'button', class: 'secondary', name: 'backup', disabled: !v.encrypted, title: v.encrypted ? null : 'set a passphrase first: a backup is never written in clear', onclick: () => { try { downloadBackup(); } catch (e) { report(e); } } }, 'Download backup'),
        h('button', { type: 'button', class: 'secondary', onclick: lock }, 'Lock')),
      st.vaultForm === 'words' ? keep('words', () => wordsForm(v)) : null,
      st.vaultForm === 'pass' ? keep('pass', () => passphraseForm(v)) : null,
      resultBox('vault-out'),
      st.showWords && v.words ? wordsBox(v.words) : null,
      h('p', { class: 'muted' }, v.words
        ? 'The 12 recovery words restore everything (keys, notes, address) in any wallet that follows SPEC-NOTES. Write them on paper; anyone who reads them owns your notes. A new version of this page on IPFS has a new origin and an empty storage: restore there from the words or the backup.'
        : 'This vault was made before recovery words existed: only its backup file restores it (encrypted with your passphrase).'));
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
      if (!pass.value && !confirm('Create the vault without a passphrase? Anyone using this browser profile could read it, and no backup file can be made until you set one.')) return;
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
    st.vault = await Vault.fromWords(localStorage, words.value, wpass.value, { restored: true }); // counters checked against the chain first
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

/** The passphrase, asked again before the recovery words of an encrypted vault are shown. */
function wordsForm(v) {
  const pass = h('input', { type: 'password', name: 'words-pass', placeholder: 'passphrase', autocomplete: 'current-password' });
  const btn = h('button', { type: 'submit' }, 'Show the words');
  const form = h('form', { class: 'row' }, pass, btn);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    busy(btn, async () => {
      if (!(await v.checkPassphrase(pass.value))) throw new Error('wrong passphrase: the recovery words stay hidden');
      st.vaultForm = null;
      st.showWords = true;
      renderVault();
    })();
  });
  return form;
}

/** Adds a passphrase to a vault stored in clear, or changes it (the current one is asked first). */
function passphraseForm(v) {
  const current = v.encrypted ? h('input', { type: 'password', name: 'current-pass', placeholder: 'current passphrase', autocomplete: 'current-password' }) : null;
  const next = h('input', { type: 'password', name: 'new-pass', placeholder: 'new passphrase', autocomplete: 'new-password' });
  const again = h('input', { type: 'password', name: 'new-pass-again', placeholder: 'new passphrase again', autocomplete: 'new-password' });
  const btn = h('button', { type: 'submit' }, v.encrypted ? 'Change passphrase' : 'Set passphrase');
  const form = h('form', { class: 'row' }, current, next, again, btn);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    busy(btn, async () => {
      if (!next.value) throw new Error('the passphrase cannot be empty');
      if (next.value !== again.value) throw new Error('the two new passphrases differ');
      await v.setPassphrase(next.value, current?.value ?? '');
      st.vaultForm = null;
      renderVault();
      result('vault-out', h('p', { class: 'ok' }, 'Passphrase set: the vault on this device is encrypted with it, and so is every backup from now on. A backup downloaded before stays as it was.'));
    })();
  });
  return h('div', {}, form, h('p', { class: 'muted' }, 'It protects the copy on this device and its backup files. It is not part of the 12 words, which restore the vault without it.'));
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
        throw new Error(`${ad.name} gave ${acc.address}, which is not a ${NET} address. Switch the wallet to ${NET_TITLE}.`);
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
