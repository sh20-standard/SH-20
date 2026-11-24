// The vault: 12 BIP39 words generated on this device, never sent anywhere. They give the
// master secret m of docs/SPEC-NOTES.md §1 (bip39.js), every key derives from m (notekeys.js),
// so the words alone recover every note, public or sealed, by rescanning the indexer.
// (A vault made before the words existed has a random m and no words: its backup file restores it.)
// The state lives in localStorage, encrypted with AES-GCM under a PBKDF2 passphrase
// key when a passphrase is set: one record for the keys, the counters, the listings and the spends,
// and one record for each note, in IndexedDB (notestore.js), each encrypted on its own under the same
// key and written when it changes, and only then (docs/audit/2026-11-24-vault.md, vault-3). What a
// sync recomputes each time (a note's path and spent status) is not stored. A passphrase can be added
// or changed at any time; a backup file is only ever written encrypted (docs/AUDIT.md §8.4), whole.
//
// A note is identified by its tree position, never by its leaf (SPEC-NOTES §4): its id is
// `pub:<i>` for the vault's i-th public note (a MINT), `out:<pos>` for a sealed output it received.

import { NOTE_SCHEME, NETWORK_HRP, wallet, publicNote, scanOutput, nullifierOf } from './notekeys.js';
import { frHex } from './fr.js';
import { noteLeaf, tickerT, PUBLIC_RHO, masterSecret, hmacSha512 } from './sh20.js';
import { newMnemonic, mnemonicToSeed } from './bip39.js';
import { keyPathOutput } from './taproot.js';
import { keyFromBytes } from './secp256k1.js';
import { gatewayKind } from './isolation.js';
import { CHAIN } from './profile.js';
import { defaultNoteStore } from './notestore.js';

/** How many lock keys past the last one used a restored vault looks for among the listings. */
export const LOCK_GAP = 10;
/**
 * How far a restored vault moves its counters past the last index it finds on chain (docs/AUDIT.md
 * §8.9): room for the MINTs and LISTs another device may have had broadcast and not yet mined when
 * this one was restored. Below RESTORE_GAP and LOCK_GAP, so that a later restore from the words still
 * finds what comes after.
 */
export const RESTORE_SKIP = 10;
export const LOCK_SKIP = 3;
import { toHex, fromHex, toBase64, fromBase64, utf8, concat, u32le } from './bytes.js';

// One record for each network (docs/audit/2026-11-24-vault.md, vault-14): a page finds its own network's vault or
// none, never the other one's in its way. Signet (and the test chains) keep the key every vault has had so far.
const keyFor = (bitcoin) => (bitcoin === 'signet' ? 'sh20.vault.v0' : `sh20.vault.${bitcoin}.v0`);
export const STORAGE_KEY = keyFor(CHAIN.bitcoin);
const NETWORK_NAMES = { signet: 'signet', bitcoin: 'mainnet' };
const PBKDF2_ITER = 600000;
// what a sync computes again each time from the local tree (ui/notes-panel.js checkOwned): never written
const VOLATILE = ['pathAt', 'spent'];
const persisted = (note) => JSON.stringify(note, (k, x) => (VOLATILE.includes(k) ? undefined : x));

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
  #state; // { v, network, scheme, next, notes, obsolete?, npks?, pending? }, null once locked
  #notes; // the note store (notestore.js): one record a note
  #stored; // the vault's record as this copy last read or wrote it (null: none stored): it writes over nothing else (vault-7)
  #queue = Promise.resolve(); // this copy's writes, one after another
  #written = new Map(); // id → the note as last stored (its persisted JSON), to write only what changed

  constructor(storage, state, seed, key, salt, words = null, notes = defaultNoteStore(storage, STORAGE_KEY), written = new Map(), stored = null) {
    this.storage = storage;
    // what was stored when this copy was read, or null for a new or restored vault: never read again here, after
    // the awaits that led here, where another tab's write would be taken for this copy's own
    this.#stored = stored;
    this.#notes = notes;
    this.#written = written;
    /** Notes the vault record names and the note store does not hold (a store cleared apart): a full rescan finds them. */
    this.missingNotes = 0;
    this.#state = state;
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

  /** The vault's records: its notes (with their tweaks), listings and spends under way (with their one-time keys). */
  get state() {
    if (!this.#state) throw new Error('the vault is locked');
    return this.#state;
  }

  get locked() {
    return this.#state === null;
  }

  /** The keys, for building a spend (send.js); they never leave the page. */
  get wallet() {
    return this.#w;
  }

  /** The vault's sh20 address on the profile's network (tsh20… on signet, sh20… on mainnet): payers seal notes to it. */
  get address() {
    return this.#w.addressString;
  }

  static exists(storage) {
    return storage.getItem(STORAGE_KEY) !== null;
  }

  /** The network of a vault stored at this origin for another network than the page's, or null (vault-14). */
  static otherNetwork(storage) {
    for (const [bitcoin, name] of Object.entries(NETWORK_NAMES)) if (bitcoin !== CHAIN.bitcoin && storage.getItem(keyFor(bitcoin)) !== null) return name;
    return null;
  }

  get encrypted() {
    return this.#key !== null;
  }

  /** A new vault with fresh recovery words (shown once to be written down: `words`). */
  static async create(storage, passphrase = '') {
    return Vault.fromWords(storage, newMnemonic(), passphrase);
  }

  /** The counters a restore must check against the chain before it reserves an index (§8.9). */
  static #unchecked = () => ({ notes: true, locks: true });

  /**
   * A vault from recovery words: new ones, or the words of a vault to restore (it then rescans
   * every leaf to find its notes). `passphrase` encrypts the vault on this device; it is not a
   * BIP39 passphrase (none is used). `restored`: the words of a vault that may have been used, whose
   * counters start at 0 and are checked against the chain before an index is reserved (reserveNote).
   */
  static async fromWords(storage, words, passphrase = '', { restored = false, notes = defaultNoteStore(storage, STORAGE_KEY) } = {}) {
    refuseSharedOrigin();
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    const m = Uint8Array.from(await masterSecret(await mnemonicToSeed(words), NETWORK_HRP));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = passphrase ? await aesKey(passphrase, salt) : null;
    await notes.clear(); // records of a vault no longer stored here are not this one's
    const v = await new Vault(storage, { v: 0, network: CHAIN.bitcoin, scheme: NOTE_SCHEME, next: 0, notes: [], ...(restored ? { unchecked: Vault.#unchecked() } : {}) }, m, key, salt, words.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' '), notes).#init();
    await v.save();
    return v;
  }

  /** The recovery words, or null for a vault made before them (its backup file restores it). */
  get words() {
    if (this.locked) throw new Error('the vault is locked');
    return this.#words;
  }

  /**
   * Opens a stored record (or a backup text). Wrong passphrase throws. A record of format 1 names its
   * notes, read from the note store; one of format 0 (a backup, or a vault stored before vault-3) holds
   * them, and its next save moves them to the store.
   */
  static async open(storage, passphrase = '', text = storage.getItem(STORAGE_KEY), notes = defaultNoteStore(storage, STORAGE_KEY), seen = storage.getItem(STORAGE_KEY)) {
    refuseSharedOrigin();
    if (text === null) throw new Error('no vault on this device');
    const rec = JSON.parse(text);
    if (rec.v !== 0 && rec.v !== 1) throw new Error('unknown vault format');
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
    const { seed, words = null, noteIds, ...state } = inner;
    const written = new Map();
    let missing = 0;
    if (rec.v === 1) {
      // its notes, from the store, in the vault's order; a record that does not open under this key and this id is refused
      const texts = await notes.read(noteIds ?? []);
      state.notes = [];
      for (const id of noteIds ?? []) {
        if (!texts.has(id)) {
          missing++;
          continue;
        }
        const note = await Vault.#openNote(key, id, texts.get(id));
        state.notes.push(note);
        written.set(id, persisted(note));
      }
    }
    // its notes, listings and spends are those of one network: a vault (or a backup) of another is not
    // opened here. Its words give other keys on this network (SPEC-NOTES §1): restoring from them makes another vault.
    const made = state.network ?? 'signet'; // a vault written before the network was recorded is a signet one
    // never "restore it from its words" (vault-14): since sealing-4 (SPEC-NOTES §1) the same words give another
    // wallet on mainnet than on the test networks, so on this network they would make a different, empty vault
    if (made !== CHAIN.bitcoin) {
      const there = NETWORK_NAMES[made] ?? made;
      throw new Error(`this vault belongs to ${there}, and this page follows ${CHAIN.label}: it opens in the ${there} vault, or from its backup file there. A vault holds the notes of one network, and its 12 words give another, empty wallet on ${CHAIN.label}`);
    }
    const v = new Vault(storage, state, fromHex(seed), key, salt ?? crypto.getRandomValues(new Uint8Array(16)), words, notes, written, seen);
    v.missingNotes = missing;
    return v.#init();
  }

  /** A note record (notestore.js): in clear, or AES-GCM under the vault's key with its id as associated data. */
  async #sealNote(id, json) {
    if (!this.#key) return JSON.stringify({ plain: JSON.parse(json) });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(id) }, this.#key, utf8(json));
    return JSON.stringify({ iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) });
  }

  static async #openNote(key, id, text) {
    const r = JSON.parse(text);
    let note;
    if (r.plain) {
      if (key) throw new Error(`note ${id} is stored in clear in an encrypted vault`);
      note = r.plain;
    } else {
      if (!key) throw new Error(`note ${id} is encrypted in a vault stored in clear`);
      let clear;
      try {
        clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(r.iv), additionalData: utf8(id) }, key, fromBase64(r.ct));
      } catch {
        throw new Error(`note ${id} does not open under this vault's key`);
      }
      note = JSON.parse(new TextDecoder().decode(clear));
    }
    if (note.id !== id) throw new Error(`the record of note ${id} holds note ${note.id}`);
    return note;
  }

  /**
   * Restores a backup file on this device (replaces nothing: fails if a vault exists). A backup
   * written in clear (by an earlier version) is encrypted with `passphrase` when one is given,
   * never silently kept in clear under a passphrase the user believes protects it.
   */
  static async restore(storage, text, passphrase = '', { notes = defaultNoteStore(storage, STORAGE_KEY) } = {}) {
    refuseSharedOrigin();
    if (Vault.exists(storage)) throw new Error('a vault already exists on this device');
    await notes.clear(); // records of a vault no longer stored here are not this one's
    const v = await Vault.open(storage, passphrase, text, notes, null); // nothing was stored: anything stored since locks it
    // a backup's counters are those of the day it was written: the indices used since are on chain
    v.state.unchecked = Vault.#unchecked();
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
    this.#checkUnchanged();
    if (this.#key && !(await this.checkPassphrase(current))) throw new Error('wrong current passphrase');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.#key = await aesKey(passphrase, salt);
    this.#salt = salt;
    await this.#write({ all: true }); // every note again, under the new key
  }

  /**
   * The vault's record: format 1 (the ids of its notes, which are records of their own) for the device,
   * format 0 (the whole state, its notes in it) for a backup, which any version restores.
   */
  async #record({ whole = false } = {}) {
    const { notes, ...rest } = this.state;
    const inner = {
      ...rest,
      ...(whole ? { notes: notes.map((n) => JSON.parse(persisted(n))) } : { noteIds: notes.map((n) => n.id) }),
      seed: toHex(this.#seed), ...(this.#words ? { words: this.#words } : {}),
    };
    const v = whole ? 0 : 1;
    if (!this.#key) return { v, plain: inner };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.#key, utf8(JSON.stringify(inner)));
    return { v, salt: toBase64(this.#salt), iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
  }

  /**
   * Writes the state, but never over a record this instance did not write: if another tab set or
   * changed the passphrase, the record there has another salt (or is no longer in clear), and an
   * older key here would rewrite it in clear or under the old passphrase. The vault locks instead.
   */
  async save() {
    this.#checkUnchanged();
    await this.#write();
  }

  /**
   * The notes that changed since they were last stored (`all`: every one), in one write of the note store,
   * then the vault's record, which names them: a note is stored before the record that lists it.
   */
  async #write(opts) {
    // one write at a time in this copy, in the order asked; and where the browser has Web Locks, one at a time
    // across its tabs, so that the check below and the write it allows are never split by another tab's (vault-7)
    const run = this.#queue.then(() => (globalThis.navigator?.locks?.request ? navigator.locks.request(STORAGE_KEY, () => this.#writeNow(opts)) : this.#writeNow(opts)));
    this.#queue = run.catch(() => {});
    return run;
  }

  async #writeNow({ all = false } = {}) {
    const now = new Map(this.state.notes.map((n) => [n.id, persisted(n)]));
    const put = [];
    for (const [id, json] of now) if (all || this.#written.get(id) !== json) put.push([id, await this.#sealNote(id, json)]);
    const del = [...this.#written.keys()].filter((id) => !now.has(id));
    const record = JSON.stringify(await this.#record());
    this.#checkUnchanged(); // after the encryption: another copy may have written meanwhile
    if (put.length || del.length) await this.#notes.write(put, del);
    this.#checkUnchanged();
    this.storage.setItem(STORAGE_KEY, record);
    this.#stored = record;
    for (const [id] of put) this.#written.set(id, now.get(id));
    for (const id of del) this.#written.delete(id);
  }

  /**
   * Refuses to write over a record this copy did not read or write last (vault-7): another tab's spend, note,
   * counter or passphrase. Comparing the salt alone let a stale copy drop what another had just recorded, a
   * public-note index (used twice, two notes linked) or a spend's one-time key. This copy locks instead.
   */
  #checkUnchanged() {
    if (!this.#seed) throw new Error('the vault is locked');
    if (this.storage.getItem(STORAGE_KEY) !== this.#stored) {
      this.lock();
      throw new Error('the vault was changed in another tab (a spend, a note, a counter or its passphrase): this one is locked, unlock it again');
    }
  }

  /**
   * The backup: the whole state in one record of format 0, its notes in it, and only encrypted: a file
   * in the downloads folder, synced or mailed, must not hold the master secret and the words in clear.
   */
  async exportBackup() {
    this.#checkUnchanged();
    if (!this.#key) throw new Error('no backup in clear: set a passphrase first, it encrypts the backup and the copy on this device');
    return JSON.stringify(await this.#record({ whole: true }));
  }

  /**
   * After a restore, the counters are checked against the chain before any index is reserved: a
   * backup is older than the notes and listings made since, and the words start from 0. The page
   * calls this once a sync has read every leaf (`notes`) and the full list of listings (`locks`),
   * the indices found moving the counters on. Each then also skips RESTORE_SKIP or LOCK_SKIP more,
   * past the last index used: room for what was broadcast elsewhere and not yet mined.
   */
  async chainChecked(kind) {
    const u = this.state.unchecked;
    if (!u?.[kind]) return;
    if (kind === 'notes') {
      // the keys of its notes, and those an indexer reported with a note that did not check out (match.js)
      const used = Math.max(this.state.seenNext ?? 0, Math.max(-1, ...this.state.notes.filter((n) => n.kind === 'public').map((n) => n.index)) + 1);
      this.state.next = Math.max(this.state.next, used + RESTORE_SKIP);
    } else {
      const used = Math.max(-1, ...(this.state.listings ?? []).map((l) => l.lockIndex), (this.state.nextLock ?? 0) - 1) + 1;
      this.state.nextLock = Math.max(this.state.nextLock ?? 0, used + LOCK_SKIP);
    }
    delete u[kind];
    if (!u.notes && !u.locks) delete this.state.unchecked;
    await this.save();
  }

  #requireChecked(kind) {
    if (this.state.unchecked?.[kind]) {
      throw new Error(kind === 'notes'
        ? 'sync first: this vault was restored, and the public-note keys it used since its backup (or since its words were new) are not known yet. A key used twice links two notes.'
        : 'sync first, with an indexer that lists the listings: this vault was restored, and the lock keys it used since are not known yet. A lock key used twice links two listings.');
    }
  }

  /** Reserves a fresh public-note index (saved at once: SPEC-NOTES §5, the counter never repeats). */
  async reserveNote() {
    this.#requireChecked('notes');
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
   * `save: false` leaves the write to the caller's next save (a sync makes one, vault-3).
   */
  async receive(out, { save = true } = {}) {
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
    if (save) await this.save();
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
    const out = keyPathOutput(keyFromBytes(wide.subarray(0, 32))); // (x mod (n − 1)) + 1, in constant time
    this.#locks.set(index, out);
    return out;
  }

  /** Reserves the next lock index (saved at once: a lock key is used for one listing only). */
  async reserveLock() {
    this.#requireChecked('locks');
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

  /**
   * Gives up spend `id` while it is still `prepared`: the wallet never signed its commit, so the vault never
   * signed its reveal and its envelope went nowhere. Its notes come back, and the record keeps its one-time
   * key (a commit a wallet broadcast anyway can still be swept). Returns false for any other status (vault-2).
   */
  async givePendingUp(id, status = 'given up') {
    const p = (this.state.pending ?? []).find((x) => x.id === id);
    if (!p || p.status !== 'prepared') return false;
    p.status = status;
    for (const n of this.state.notes) if ((p.inputs ?? []).includes(n.id) && n.status === 'spending') n.status = 'in tree';
    await this.save();
    return true;
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
  async dropNote(id, { save = true } = {}) {
    this.state.notes = this.state.notes.filter((n) => n.id !== id);
    if (save) await this.save();
  }

  /**
   * Changes note `id`. A path or a spent status alone (VOLATILE: a sync computes them again each time)
   * writes nothing; anything else is saved, at once or with the caller's next save (`save: false`).
   */
  async updateNote(id, patch, { save = true } = {}) {
    const n = this.state.notes.find((x) => x.id === id);
    if (!n) return;
    Object.assign(n, patch);
    if (save && Object.keys(patch).some((k) => !VOLATILE.includes(k))) await this.save();
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

  /**
   * Locks the vault (the Lock button, the inactivity lock of autolock.js, another tab's write):
   * what can be overwritten is zeroed (the master secret, the viewing key, the lock keys), the rest
   * is let go (the state with its note tweaks and one-time keys, the derived scalars, the words, the
   * passphrase key): a BigInt or a string cannot be overwritten in JavaScript, only left to the
   * garbage collector. Nothing here reads the vault again until it is opened from storage.
   */
  lock() {
    this.#seed?.fill(0);
    this.#wallet?.ivk?.fill(0);
    for (const o of this.#locks.values()) o.secret.fill(0);
    this.#seed = null;
    this.#words = null;
    this.#key = null;
    this.#wallet = null;
    this.#state = null;
    this.#openings.clear();
    this.#locks.clear();
  }
}
