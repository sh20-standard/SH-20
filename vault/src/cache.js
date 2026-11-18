// Local cache of public chain data (tree leaves, spent nullifiers), so a sync
// only downloads new blocks. It holds nothing secret: every leaf and every
// nullifier, not which ones are yours. IndexedDB in the browser (localStorage is
// too small for a large tree); a Map in tests. Values are structured-cloned.

export function memoryCache() {
  const m = new Map();
  return {
    get: async (k) => (m.has(k) ? structuredClone(m.get(k)) : undefined),
    set: async (k, v) => void m.set(k, structuredClone(v)),
    delete: async (k) => void m.delete(k),
  };
}

export function idbCache(name = 'sh20-vault-cache') {
  let db;
  const open = () =>
    (db ??= new Promise((resolve, reject) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    }));
  const run = async (mode, fn) => {
    const store = (await open()).transaction('kv', mode).objectStore('kv');
    return new Promise((resolve, reject) => {
      const r = fn(store);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  };
  return {
    get: (k) => run('readonly', (s) => s.get(k)),
    set: (k, v) => run('readwrite', (s) => s.put(v, k)).then(() => {}),
    delete: (k) => run('readwrite', (s) => s.delete(k)).then(() => {}),
  };
}

/** IndexedDB when it works (it can be missing or blocked), else memory only. */
export async function defaultCache() {
  try {
    const c = idbCache();
    await c.get('probe');
    return c;
  } catch {
    return memoryCache();
  }
}
