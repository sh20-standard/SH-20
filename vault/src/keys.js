// The vault: a 32-byte seed generated on this device, never sent anywhere. It is
// the master secret of docs/SPEC-NOTES.md §1: every key derives from it (notekeys.js),
// so the seed alone recovers every note, public or sealed, by rescanning the indexer.
// The state lives in localStorage, encrypted with AES-GCM under a PBKDF2 passphrase
// key when a passphrase is set.
//
// A note is identified by its tree position, never by its leaf (SPEC-NOTES §4): its id is
// `pub:<i>` for the vault's i-th public note (a MINT), `out:<pos>` for a sealed output it received.

import { NOTE_SCHEME, wallet, publicNote, scanOutput, nullifierOf } from './notekeys.js';
import { frHex } from './fr.js';
import { noteLeaf, tickerT, PUBLIC_RHO } from './sh20.js';
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

/** Opening of public note `index` (SPEC-NOTES §5): npk alone, rho = 0. */
export function noteOpening(seed, index) {
  const { npk, secrets } = publicNote(wallet(seed), index);
  return { index, npk, rho: PUBLIC_RHO, secrets, scheme: NOTE_SCHEME };
}

/** Restore scans public notes until this many unused indices in a row (SPEC-NOTES §5). */
export const RESTORE_GAP = 50;

export class Vault {
  #seed;
  #key; // AES key, null when stored in clear
  #salt;
  #wallet = null; // keys derived from the seed, on first use
  #openings = new Map(); // index -> public opening, cached (each costs two BabyJubJub multiplications, ~170 ms)

  constructor(storage, state, seed, key, salt) {
    this.storage = storage;
    this.state = state; // { v, network, scheme, next, notes, obsolete? } — seed kept apart, in #seed
    this.#seed = seed;
    this.#key = key;
    this.#salt = salt;
    if (state.scheme !== NOTE_SCHEME) {
      // notes of the provisional keys (v0.2) cannot exist on a v0.3 chain: kept aside, never matched
      state.obsolete = [...(state.obsolete ?? []), ...(state.notes ?? [])];
      state.notes = [];
      state.next = 0;
      state.scheme = NOTE_SCHEME;
    }
  }

  get #w() {
    return (this.#wallet ??= wallet(this.#seed));
  }

  /** The keys, for building a spend (send.js); they never leave the page. */
  get wallet() {
    return this.#w;
  }

  /** The vault's sh20 address on signet (tsh20…): payers seal notes to it. */
  get address() {
    return this.#w.addressString;
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
    const v = new Vault(storage, { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [] }, seed, key, salt);
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

  /** Reserves a fresh public-note index (saved at once: SPEC-NOTES §5, the counter never repeats). */
  async reserveNote() {
    const index = this.state.next;
    this.state.next = index + 1;
    await this.save();
    return this.opening(index);
  }

  /**
   * npk (hex) of public note `index`. Computed once and kept in the (encrypted) state: deriving it
   * takes about 170 ms in a browser, and a sync looks at the next RESTORE_GAP of them.
   */
  npkAt(index) {
    const cache = (this.state.npks ??= []);
    if (!cache[index]) cache[index] = frHex(this.opening(index).npk);
    return cache[index];
  }

  opening(index) {
    if (!this.#openings.has(index)) {
      const { npk, secrets } = publicNote(this.#w, index);
      this.#openings.set(index, { index, npk, rho: PUBLIC_RHO, secrets, scheme: NOTE_SCHEME });
    }
    return this.#openings.get(index);
  }

  /** Nullifier of an owned note at its position; the nullifier key never leaves the vault. */
  nullifier(note) {
    const secrets = note.tauN ? { tauA: BigInt(note.tauA), tauN: BigInt(note.tauN) } : this.opening(note.index).secrets;
    return nullifierOf(this.#w, secrets, BigInt('0x' + note.leaf), note.pos);
  }

  /** Records a public note the vault created (MINT): ticker, v and the expected leaf (rho = 0). */
  async addNote({ index, ticker, v, txid, status, pos = null }) {
    const { npk, secrets } = this.opening(index);
    const leaf = noteLeaf(tickerT(ticker), v, npk, PUBLIC_RHO);
    // a second leaf with this npk (anyone can make one: SPEC-NOTES §6) is a second note, told apart by its position
    const id = this.state.notes.some((n) => n.id === `pub:${index}`) ? `pub:${index}@${pos}` : `pub:${index}`;
    const note = {
      id, kind: 'public', index, scheme: NOTE_SCHEME, ticker, v: v.toString(), npk: frHex(npk), leaf: frHex(leaf),
      tauA: secrets.tauA.toString(), tauN: secrets.tauN.toString(), // kept, so a nullifier costs one Poseidon
      txid, status, pos,
    };
    this.state.notes.push(note);
    if (this.state.next <= index) this.state.next = index + 1;
    await this.save();
    return note;
  }

  /**
   * Opens a sealed output `{ pos, leaf, pkEph, ct, txid }` found by a sync. Records it and returns
   * the note when it is this vault's, has a value (v = 0 is an unused output, kept out of the
   * balance) and hashes to its leaf; otherwise null. Already known positions are not added twice.
   */
  async receive(out) {
    const id = `out:${out.pos}`;
    if (this.state.notes.some((n) => n.id === id)) return null;
    const got = scanOutput(this.#w, { leaf: out.leaf, pkEph: out.pkEph, ct: out.ct });
    if (!got || got.v === 0n) return null;
    const note = {
      id, kind: 'sealed', index: null, scheme: NOTE_SCHEME, ticker: got.ticker, v: got.v.toString(), npk: frHex(got.npk),
      rho: frHex(got.secrets.rho), tauA: got.secrets.tauA.toString(), tauN: got.secrets.tauN.toString(),
      leaf: frHex(out.leaf), txid: out.txid ?? null, status: 'in tree', pos: out.pos,
    };
    this.state.notes.push(note);
    await this.save();
    return note;
  }

  /**
   * A spend under way (send.js pendingRecord): saved before the wallet signs the commit, since its
   * one-time key is the only way to send the reveal or to take the commit output back.
   */
  async addPending(rec) {
    const id = `spend:${Date.now()}:${(this.state.pending ?? []).length}`;
    (this.state.pending ??= []).push({ id, ...rec });
    for (const nid of rec.inputs ?? []) {
      const n = this.state.notes.find((x) => x.id === nid);
      if (n) n.status = 'spending';
    }
    await this.save();
    return id;
  }

  async updatePending(id, patch) {
    const p = (this.state.pending ?? []).find((x) => x.id === id);
    if (!p) return;
    Object.assign(p, patch);
    await this.save();
  }

  /** Forgets a note (a sealed output no longer in the tree: scanning finds it again wherever it is). */
  async dropNote(id) {
    this.state.notes = this.state.notes.filter((n) => n.id !== id);
    await this.save();
  }

  async updateNote(id, patch) {
    const n = this.state.notes.find((x) => x.id === id);
    if (!n) return;
    Object.assign(n, patch);
    await this.save();
  }

  /**
   * npk (hex) → index of the used public notes and the next RESTORE_GAP, for recovery scans.
   * Keys not yet cached are derived one by one, yielding between them (`onProgress(done, todo)`),
   * then saved: a new vault pays this once (about 8 s for 50 keys in a browser), later syncs ~nothing.
   */
  async npkWindow({ gap = RESTORE_GAP, onProgress, yieldEvery = () => new Promise((r) => setTimeout(r, 0)) } = {}) {
    const n = this.state.next + gap;
    const todo = Array.from({ length: n }, (_, i) => i).filter((i) => !this.state.npks?.[i]);
    for (const [k, i] of todo.entries()) {
      this.npkAt(i);
      onProgress?.(k + 1, todo.length);
      await yieldEvery();
    }
    if (todo.length) await this.save();
    const out = new Map();
    for (let i = 0; i < n; i++) out.set(this.npkAt(i), i);
    return out;
  }

  lock() {
    this.#seed.fill(0);
    this.#seed = null;
    this.#key = null;
    this.#wallet = null;
    this.#openings.clear();
  }
}
