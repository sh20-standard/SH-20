// Where the vault keeps its notes: one record each (docs/audit/2026-11-24-vault.md, vault-3; -sealing.md, sealing-3).
// The vault's own record in localStorage (keys.js) holds its keys, counters, listings and spends, and the ids of its
// notes in order; each note is a record of its own here, written when it changes and only then. Anyone who knows an
// address can send it notes of one unit: one record per note keeps a sync's writes to what changed, and IndexedDB
// has the room that localStorage (about 5 MB an origin) has not.
//
// A record is the text keys.js makes of a note: in clear, or AES-GCM under the vault's key. The store sees ids
// (`pub:<i>`, `out:<pos>`) and those texts, never a key.
//
//   read(ids)            Map id → text of the records stored for those ids (a missing one is not in the map)
//   write(put, del)      puts [[id, text]…] and deletes [id…], in one transaction
//   clear()              every record (a vault erased, or replaced by a restore)

/** IndexedDB, one object store; one database for each vault record key (keys.js STORAGE_KEY). */
export function idbNoteStore(name) {
  let db;
  const open = () =>
    (db ??= new Promise((resolve, reject) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('notes');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    }));
  const tx = async (mode, fn) => {
    const t = (await open()).transaction('notes', mode);
    const out = fn(t.objectStore('notes'));
    await new Promise((resolve, reject) => {
      t.oncomplete = resolve;
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error ?? new Error('the note store refused the write'));
    });
    return out;
  };
  return {
    async read(ids) {
      const got = new Map();
      await tx('readonly', (s) => {
        for (const id of ids) {
          const r = s.get(id);
          r.onsuccess = () => {
            if (typeof r.result === 'string') got.set(id, r.result);
          };
        }
      });
      return got;
    },
    write: (put, del = []) => tx('readwrite', (s) => {
      for (const id of del) s.delete(id);
      for (const [id, text] of put) s.put(text, id);
    }).then(() => {}),
    clear: () => tx('readwrite', (s) => s.clear()).then(() => {}),
  };
}

/** The same records as keys of a localStorage-like `storage` (tests, and a browser without IndexedDB). */
export function storageNoteStore(storage, prefix) {
  const key = (id) => `${prefix}.note:${id}`;
  return {
    async read(ids) {
      const got = new Map();
      for (const id of ids) {
        const t = storage.getItem(key(id));
        if (t !== null) got.set(id, t);
      }
      return got;
    },
    async write(put, del = []) {
      for (const id of del) storage.removeItem?.(key(id));
      for (const [id, text] of put) storage.setItem(key(id), text);
    },
    async clear() {
      const all = [];
      for (let i = 0; i < (storage.length ?? 0); i++) if (storage.key(i)?.startsWith(`${prefix}.note:`)) all.push(storage.key(i));
      for (const k of all) storage.removeItem(k);
    },
  };
}

/** In memory: what IndexedDB is to the page, for tests. `writes` counts the write transactions. */
export function memoryNoteStore() {
  const m = new Map();
  const store = {
    records: m,
    writes: 0,
    read: async (ids) => new Map(ids.filter((id) => m.has(id)).map((id) => [id, m.get(id)])),
    async write(put, del = []) {
      store.writes++;
      for (const id of del) m.delete(id);
      for (const [id, text] of put) m.set(id, text);
    },
    clear: async () => void m.clear(),
  };
  return store;
}

/** The note store of a vault kept in `storage` under `prefix`: IndexedDB beside the page's localStorage, else `storage` itself. */
export function defaultNoteStore(storage, prefix) {
  if (globalThis.indexedDB && globalThis.localStorage && storage === globalThis.localStorage) return idbNoteStore(`${prefix}.notes`);
  return storageNoteStore(storage, prefix);
}
