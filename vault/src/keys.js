// The vault: a 32-byte seed generated on this device, never sent anywhere.
// Every note key derives from it (see npk.js), so the seed alone recovers every
// public note by rescanning the indexer. The state lives in localStorage,
// encrypted with AES-GCM under a PBKDF2 passphrase key when a passphrase is set.

import { deriveNpk } from './npk.js';
import { hashToFr, frHex } from './fr.js';
import { noteLeaf } from './sh20.js';
import { toHex, fromHex, toBase64, fromBase64, utf8 } from './bytes.js';

export const STORAGE_KEY = 'sh20.vault.v0';
const PBKDF2_ITER = 600000;

async function aesKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', utf8(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Opening (npk, rho) of note `index`; rho is derived too, so the seed recovers it. */
export function noteOpening(seed, index) {
  const { npk, scheme } = deriveNpk(seed, index);
  const rho = hashToFr('sh20/vault/v0/rho', seed, index);
  return { index, npk, rho, scheme };
}

export class Vault {
  #seed;
  #key; // AES key, null when stored in clear
  #salt;

  constructor(storage, state, seed, key, salt) {
    this.storage = storage;
    this.state = state; // { v, network, next, notes } — seed kept apart, in #seed
    this.#seed = seed;
    this.#key = key;
    this.#salt = salt;
  }

  static exists(storage) {
    return storage.getItem(STORAGE_KEY) !== null;
  }

  get encrypted() {
    return this.#key !== null;
  }

  static async create(storage, passphrase = '') {
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = passphrase ? await aesKey(passphrase, salt) : null;
    const v = new Vault(storage, { v: 0, network: 'signet', next: 0, notes: [] }, seed, key, salt);
    await v.save();
    return v;
  }

  /** Opens a stored record (or a backup text). Wrong passphrase throws. */
  static async open(storage, passphrase = '', text = storage.getItem(STORAGE_KEY)) {
    if (text === null) throw new Error('no vault on this device');
    const rec = JSON.parse(text);
    if (rec.v !== 0) throw new Error('unknown vault format');
    let inner;
    let key = null;
    let salt = null;
    if (rec.plain) {
      inner = rec.plain;
    } else {
      if (!passphrase) throw new Error('this vault needs its passphrase');
      salt = fromBase64(rec.salt);
      key = await aesKey(passphrase, salt);
      let clear;
      try {
        clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(rec.iv) }, key, fromBase64(rec.ct));
      } catch {
        throw new Error('wrong passphrase');
      }
      inner = JSON.parse(new TextDecoder().decode(clear));
    }
    const { seed, ...state } = inner;
    return new Vault(storage, state, fromHex(seed), key, salt ?? crypto.getRandomValues(new Uint8Array(16)));
  }

  /** Restores a backup file on this device (replaces nothing: fails if a vault exists). */
  static async restore(storage, text, passphrase = '') {
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    const v = await Vault.open(storage, passphrase, text);
    await v.save();
    return v;
  }

  async #record() {
    const inner = { ...this.state, seed: toHex(this.#seed) };
    if (!this.#key) return { v: 0, plain: inner };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.#key, utf8(JSON.stringify(inner)));
    return { v: 0, salt: toBase64(this.#salt), iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
  }

  async save() {
    this.storage.setItem(STORAGE_KEY, JSON.stringify(await this.#record()));
  }

  /** The backup is the stored record itself: encrypted when the vault has a passphrase. */
  exportBackup() {
    return this.storage.getItem(STORAGE_KEY);
  }

  /** Reserves a fresh note index (saved at once, so an index is never used twice). */
  async reserveNote() {
    const index = this.state.next;
    this.state.next = index + 1;
    await this.save();
    return noteOpening(this.#seed, index);
  }

  opening(index) {
    return noteOpening(this.#seed, index);
  }

  /** Records a public note the vault created (MINT): tokenNum, v and the expected leaf. */
  async addNote({ index, scheme, npk, rho, tokenNum, ticker, v, txid, status }) {
    const leaf = noteLeaf(tokenNum, v, npk, rho);
    const note = {
      index, scheme, tokenNum, ticker, v: v.toString(), npk: frHex(npk), rho: frHex(rho), leaf: frHex(leaf),
      txid, status, pos: null,
    };
    this.state.notes.push(note);
    await this.save();
    return note;
  }

  async updateNote(index, patch) {
    const n = this.state.notes.find((x) => x.index === index);
    if (!n) return;
    Object.assign(n, patch);
    await this.save();
  }

  /** npk (hex) of the first `count` indices beyond the used ones, for recovery scans. */
  npkWindow(gap = 20) {
    const out = new Map();
    for (let i = 0; i < this.state.next + gap; i++) out.set(frHex(this.opening(i).npk), i);
    return out;
  }

  lock() {
    this.#seed.fill(0);
    this.#seed = null;
    this.#key = null;
  }
}
