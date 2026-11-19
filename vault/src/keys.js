// The vault: 12 BIP39 words generated on this device, never sent anywhere. They give the
// master secret m of docs/SPEC-NOTES.md §1 (bip39.js), every key derives from m (notekeys.js),
// so the words alone recover every note, public or sealed, by rescanning the indexer.
// (A vault made before the words existed has a random m and no words: its backup file restores it.)
// The state lives in localStorage, encrypted with AES-GCM under a PBKDF2 passphrase
// key when a passphrase is set. A passphrase can be added or changed at any time; a backup file is
// only ever written encrypted (docs/AUDIT.md §8.4).
//
// A note is identified by its tree position, never by its leaf (SPEC-NOTES §4): its id is
// `pub:<i>` for the vault's i-th public note (a MINT), `out:<pos>` for a sealed output it received.

import { NOTE_SCHEME, wallet, publicNote, scanOutput, nullifierOf } from './notekeys.js';
import { frHex } from './fr.js';
import { noteLeaf, tickerT, PUBLIC_RHO, masterSecret, hmacSha512 } from './sh20.js';
import { newMnemonic, mnemonicToSeed } from './bip39.js';
import { keyPathOutput } from './taproot.js';
import { gatewayKind } from './isolation.js';

const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** How many lock keys past the last one used a restored vault looks for among the listings. */
export const LOCK_GAP = 10;
import { toHex, fromHex, toBase64, fromBase64, utf8, concat, u32le, bytesToBig, bigTo32 } from './bytes.js';

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

/**
 * On a path gateway (…/ipfs/<cid>/) every site of the gateway shares the page's origin, so its
 * storage and its window (docs/AUDIT.md §8.1): no vault is created, restored or opened there.
 */
function refuseSharedOrigin() {
  if (globalThis.location && gatewayKind(globalThis.location) === 'path') {
    throw new Error('the vault does not open on a path gateway (…/ipfs/<cid>/): every site on that gateway shares its origin. Open it from a subdomain gateway or a local IPFS node.');
  }
}

/** Opening of public note `index` (SPEC-NOTES §5): npk alone, rho = 0. */
export async function noteOpening(seed, index) {
  const { npk, secrets } = await publicNote(await wallet(seed), index);
  return { index, npk, rho: PUBLIC_RHO, secrets, scheme: NOTE_SCHEME };
}

/** Restore scans public notes until this many unused indices in a row (SPEC-NOTES §5). */
export const RESTORE_GAP = 50;

export class Vault {
  #seed; // the master secret m
  #words; // the 12 recovery words, or null for a vault made before them
  #key; // AES key, null when stored in clear
  #salt;
  #wallet = null; // keys derived from the seed, on first use
  #openings = new Map(); // index -> public opening, cached (each costs two BabyJubJub multiplications, ~170 ms)
  #locks = new Map(); // index -> lock output (market.js), cached

  constructor(storage, state, seed, key, salt, words = null) {
    this.storage = storage;
    this.state = state; // { v, network, scheme, next, notes, obsolete?, npks?, pending? } — secrets kept apart
    this.#seed = seed;
    this.#words = words;
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

  /** Derives the keys (asynchronous: WebCrypto); every constructor path awaits it. */
  async #init() {
    this.#wallet = await wallet(this.#seed);
    return this;
  }

  get #w() {
    if (!this.#wallet) throw new Error('the vault is locked');
    return this.#wallet;
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

  /** A new vault with fresh recovery words (shown once to be written down: `words`). */
  static async create(storage, passphrase = '') {
    return Vault.fromWords(storage, newMnemonic(), passphrase);
  }

  /**
   * A vault from recovery words: new ones, or the words of a vault to restore (it then rescans
   * every leaf to find its notes). `passphrase` encrypts the vault on this device; it is not a
   * BIP39 passphrase (none is used).
   */
  static async fromWords(storage, words, passphrase = '') {
    refuseSharedOrigin();
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    const m = Uint8Array.from(await masterSecret(await mnemonicToSeed(words)));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = passphrase ? await aesKey(passphrase, salt) : null;
    const v = await new Vault(storage, { v: 0, network: 'signet', scheme: NOTE_SCHEME, next: 0, notes: [] }, m, key, salt, words.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ')).#init();
    await v.save();
    return v;
  }

  /** The recovery words, or null for a vault made before them (its backup file restores it). */
  get words() {
    return this.#words;
  }

  /** Opens a stored record (or a backup text). Wrong passphrase throws. */
  static async open(storage, passphrase = '', text = storage.getItem(STORAGE_KEY)) {
    refuseSharedOrigin();
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
    const { seed, words = null, ...state } = inner;
    return new Vault(storage, state, fromHex(seed), key, salt ?? crypto.getRandomValues(new Uint8Array(16)), words).#init();
  }

  /**
   * Restores a backup file on this device (replaces nothing: fails if a vault exists). A backup
   * written in clear (by an earlier version) is encrypted with `passphrase` when one is given,
   * never silently kept in clear under a passphrase the user believes protects it.
   */
  static async restore(storage, text, passphrase = '') {
    refuseSharedOrigin();
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    const v = await Vault.open(storage, passphrase, text);
    if (!v.encrypted && passphrase) await v.setPassphrase(passphrase);
    else await v.save();
    return v;
  }

  /** True when `passphrase` opens the record stored on this device (an encrypted vault only). */
  async checkPassphrase(passphrase) {
    if (!this.#key || !passphrase) return false;
    const rec = JSON.parse(this.storage.getItem(STORAGE_KEY));
    try {
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(rec.iv) }, await aesKey(passphrase, fromBase64(rec.salt)), fromBase64(rec.ct));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Sets the passphrase that encrypts the vault on this device and its backups: adds one to a vault
   * stored in clear, or changes it (`current` must open the stored record). A new salt each time.
   */
  async setPassphrase(passphrase, current = '') {
    if (!passphrase) throw new Error('the passphrase cannot be empty');
    if (this.#key && !(await this.checkPassphrase(current))) throw new Error('wrong current passphrase');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.#key = await aesKey(passphrase, salt);
    this.#salt = salt;
    await this.save();
  }

  async #record() {
    const inner = { ...this.state, seed: toHex(this.#seed), ...(this.#words ? { words: this.#words } : {}) };
    if (!this.#key) return { v: 0, plain: inner };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.#key, utf8(JSON.stringify(inner)));
    return { v: 0, salt: toBase64(this.#salt), iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
  }

  async save() {
    this.storage.setItem(STORAGE_KEY, JSON.stringify(await this.#record()));
  }

  /**
   * The backup is the stored record itself, and only when it is encrypted: a file in the downloads
   * folder, synced or mailed, must not hold the master secret and the words in clear.
   */
  exportBackup() {
    const text = this.storage.getItem(STORAGE_KEY);
    if (!this.#key || JSON.parse(text).plain) throw new Error('no backup in clear: set a passphrase first, it encrypts the backup and the copy on this device');
    return text;
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
  async npkAt(index) {
    const cache = (this.state.npks ??= []);
    if (!cache[index]) cache[index] = frHex((await this.opening(index)).npk);
    return cache[index];
  }

  async opening(index) {
    if (!this.#openings.has(index)) {
      const { npk, secrets } = await publicNote(this.#w, index);
      this.#openings.set(index, { index, npk, rho: PUBLIC_RHO, secrets, scheme: NOTE_SCHEME });
    }
    return this.#openings.get(index);
  }

  /** Nullifier of an owned note at its position; the nullifier key never leaves the vault. */
  async nullifier(note) {
    const secrets = note.tauN ? { tauA: BigInt(note.tauA), tauN: BigInt(note.tauN) } : (await this.opening(note.index)).secrets;
    return nullifierOf(this.#w, secrets, BigInt('0x' + note.leaf), note.pos);
  }

  /** Records a public note the vault created (MINT): ticker, v and the expected leaf (rho = 0). */
  async addNote({ index, ticker, v, txid, status, pos = null }) {
    const { npk, secrets } = await this.opening(index);
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
    const got = await scanOutput(this.#w, { leaf: out.leaf, pkEph: out.pkEph, ct: out.ct });
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
   * The lock output of listing `index` (market.js): a BIP86 key-path output of
   * HMAC-SHA512("sh20/vault/lock", m ‖ u32le(index)), so the recovery words restore it.
   * Returns { script, key, secret } (secret: the tweaked key that signs offers, cancels and claims).
   */
  async lockOutput(index) {
    if (this.#locks.has(index)) return this.#locks.get(index);
    const wide = await hmacSha512(new TextEncoder().encode('sh20/vault/lock'), concat(this.#seed, u32le(index)));
    const out = keyPathOutput(bigTo32((bytesToBig(wide.subarray(0, 32)) % (SECP_N - 1n)) + 1n));
    this.#locks.set(index, out);
    return out;
  }

  /** Reserves the next lock index (saved at once: a lock key is used for one listing only). */
  async reserveLock() {
    const index = this.state.nextLock ?? 0;
    this.state.nextLock = index + 1;
    await this.save();
    return index;
  }

  /** The vault's listings: { id, lockIndex, ticker, amount, price, payScript, listTxid, state }. */
  async addListing(rec) {
    (this.state.listings ??= []).push({ id: `list:${rec.lockIndex}`, ...rec });
    await this.save();
  }

  async updateListing(id, patch) {
    const l = (this.state.listings ?? []).find((x) => x.id === id);
    if (!l) return;
    Object.assign(l, patch);
    await this.save();
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

  /** Gives back the notes a spend under way had reserved (a DEPLOY whose ticker was taken meanwhile). */
  async releaseInputs(ids = []) {
    for (const n of this.state.notes) if (ids.includes(n.id) && n.status === 'spending') n.status = 'in tree';
    await this.save();
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
      await this.npkAt(i);
      onProgress?.(k + 1, todo.length);
      await yieldEvery();
    }
    if (todo.length) await this.save();
    const out = new Map();
    for (let i = 0; i < n; i++) out.set(await this.npkAt(i), i);
    return out;
  }

  lock() {
    this.#seed.fill(0);
    this.#seed = null;
    this.#words = null;
    this.#key = null;
    this.#wallet = null;
    this.#openings.clear();
    this.#locks.clear();
  }
}
