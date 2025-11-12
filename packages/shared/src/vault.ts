// Minimal sealed storage for the enclave origin.
// Persists a non-extractable AES-GCM key in IndexedDB and seals blobs with AAD.
//
// API:
//   const v = await initVault({ aad: sessionId });
//   await v.seal('token', new TextEncoder().encode('supersecret'));
//   const pt = await v.unseal('token'); // Uint8Array
//   await v.delete('token');
//   await v.clear();
//   const s = await v.stats();

type Bytes = Uint8Array;

type VaultOptions = {
  dbName?: string;           // default: 'soft-enclave-vault'
  keyStore?: string;         // default: 'keys'
  itemStore?: string;        // default: 'items'
  kid?: string;              // default: 'k1'
  aad?: string;              // default: ''
};

export type Vault = {
  seal: (name: string, data: Bytes, aadOverride?: string) => Promise<void>;
  unseal: (name: string, aadOverride?: string) => Promise<Bytes>;
  delete: (name: string) => Promise<void>;
  clear: () => Promise<void>;
  stats: () => Promise<{ items: number; hasKey: boolean }>;
};

const te = new TextEncoder();
const td = new TextDecoder();

function openDB(name: string, keyStore: string, itemStore: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(keyStore)) db.createObjectStore(keyStore, { keyPath: 'kid' });
      if (!db.objectStoreNames.contains(itemStore)) db.createObjectStore(itemStore, { keyPath: 'name' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getKey(db: IDBDatabase, keyStore: string, kid: string): Promise<CryptoKey | null> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(keyStore, 'readonly');
    const store = tx.objectStore(keyStore);
    const g = store.get(kid);
    g.onsuccess = () => resolve(g.result?.key ?? null);
    g.onerror = () => reject(g.error);
  });
}

async function putKey(db: IDBDatabase, keyStore: string, kid: string, key: CryptoKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(keyStore, 'readwrite');
    const store = tx.objectStore(keyStore);
    const p = store.put({ kid, key, createdAt: Date.now() });
    p.onsuccess = () => resolve();
    p.onerror = () => reject(p.error);
  });
}

async function ensureAesKey(db: IDBDatabase, keyStore: string, kid: string): Promise<CryptoKey> {
  const existing = await getKey(db, keyStore, kid);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false /* NOT extractable */, ['encrypt', 'decrypt']);
  // Note: IndexedDB can persist CryptoKey objects directly even when non-extractable
  await putKey(db, keyStore, kid, key);
  return key;
}

function randIV(): Bytes {
  return crypto.getRandomValues(new Uint8Array(12));
}

async function putItem(db: IDBDatabase, itemStore: string, rec: any): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(itemStore, 'readwrite');
    const store = tx.objectStore(itemStore);
    const p = store.put(rec);
    p.onsuccess = () => resolve();
    p.onerror = () => reject(p.error);
  });
}

async function getItem(db: IDBDatabase, itemStore: string, name: string): Promise<any | null> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(itemStore, 'readonly');
    const store = tx.objectStore(itemStore);
    const g = store.get(name);
    g.onsuccess = () => resolve(g.result ?? null);
    g.onerror = () => reject(g.error);
  });
}

async function delItem(db: IDBDatabase, itemStore: string, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(itemStore, 'readwrite');
    const store = tx.objectStore(itemStore);
    const d = store.delete(name);
    d.onsuccess = () => resolve();
    d.onerror = () => reject(d.error);
  });
}

async function countItems(db: IDBDatabase, itemStore: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(itemStore, 'readonly');
    const store = tx.objectStore(itemStore);
    const c = store.count();
    c.onsuccess = () => resolve(c.result);
    c.onerror = () => reject(c.error);
  });
}

export async function initVault(opts: VaultOptions = {}): Promise<Vault> {
  if (!isSecureContext) throw new Error('Vault requires a secure context');
  const dbName = opts.dbName ?? 'soft-enclave-vault';
  const keyStore = opts.keyStore ?? 'keys';
  const itemStore = opts.itemStore ?? 'items';
  const kid = opts.kid ?? 'k1';
  const defaultAAD = opts.aad ?? '';

  const db = await openDB(dbName, keyStore, itemStore);
  const key = await ensureAesKey(db, keyStore, kid);

  async function seal(name: string, data: Bytes, aadOverride?: string) {
    const aad = te.encode(aadOverride ?? defaultAAD);
    const iv = randIV();
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, data));
    await putItem(db, itemStore, {
      name,
      kid,
      v: 1,
      iv: Array.from(iv),
      ct: Array.from(ct),
      aad: aadOverride ?? defaultAAD,
      createdAt: Date.now()
    });
  }

  async function unseal(name: string, aadOverride?: string): Promise<Bytes> {
    const rec = await getItem(db, itemStore, name);
    if (!rec) throw new Error(`Not found: ${name}`);
    if (rec.kid !== kid) throw new Error(`Key mismatch`);
    const aad = te.encode(aadOverride ?? rec.aad ?? defaultAAD);
    const iv = new Uint8Array(rec.iv);
    const ct = new Uint8Array(rec.ct);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));
    return pt;
  }

  async function remove(name: string) { await delItem(db, itemStore, name); }

  async function clear() {
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction(itemStore, 'readwrite');
      const store = tx.objectStore(itemStore);
      const r = store.clear();
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
    });
  }

  async function stats() {
    const items = await countItems(db, itemStore);
    const hasKey = !!(await getKey(db, keyStore, kid));
    return { items, hasKey };
  }

  return { seal, unseal, delete: remove, clear, stats };
}
