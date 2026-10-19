/**
 * Where AES keys come from. Encryption in the browser does not stop a
 * targeted XSS (it can call decrypt like your code does). It does stop blind
 * exfiltration by scripts that dump storage, and plaintext in profile backups,
 * but only if the key itself cannot be read, hence non-extractable keys.
 * For session tokens an httpOnly cookie beats all of this.
 */
export interface Keyring {
  /** The key for new values. */
  current(): Promise<KeyHandle>;
  /** A key by version, or null when it is gone (treat as unreadable, never as empty). */
  byVersion(version: string): Promise<KeyHandle | null>;
  /** Forget the keys. Call on logout. */
  destroy(): Promise<void>;
}

export interface KeyHandle {
  version: string;
  key: CryptoKey;
}

export class KeyringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyringError';
  }
}

const generate = () =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

/** Per tab, nothing on disk. Data is lost on reload: for things you can re-fetch, and for shared machines. */
export function memoryKeyring(): Keyring {
  let handle: Promise<KeyHandle> | null = null;
  return {
    current: () => (handle ??= generate().then((key) => ({ version: 'mem', key }))),
    async byVersion(version) {
      return version === 'mem' && handle ? handle : null;
    },
    destroy: async () => {
      handle = null;
    },
  };
}

export interface PersistentKeyringOptions {
  /** Separates apps that share an origin. Default `default`. */
  namespace?: string;
  /** Default 90. The previous key is kept, so values written under it stay readable. */
  rotateAfterDays?: number;
}

interface StoredKey {
  version: string;
  key: CryptoKey;
  createdAt: number;
}

/**
 * A non-extractable key kept in IndexedDB (structured clone keeps the
 * `CryptoKey`; `exportKey` on it throws). A dump of IndexedDB yields a handle
 * that is useless off this device and origin. Throws `KeyringError` when
 * IndexedDB is missing; choose `memoryKeyring` there.
 */
export function persistentKeyring(options: PersistentKeyringOptions = {}): Keyring {
  const slot = `keyring:${options.namespace ?? 'default'}`;
  const rotateAfterMs = (options.rotateAfterDays ?? 90) * 86_400_000;
  const cache = new Map<string, CryptoKey>();
  // One in-flight load, so concurrent first calls cannot each generate and overwrite a key.
  let inflight: Promise<KeyHandle> | null = null;

  async function load(): Promise<KeyHandle> {
    const db = await openDb();
    try {
      const stored = await request<StoredKey[] | undefined>(db, 'readonly', (s) => s.get(slot));
      const keys = Array.isArray(stored) ? stored : [];
      const newest = keys[0];
      if (newest && Date.now() - newest.createdAt < rotateAfterMs) {
        for (const k of keys) cache.set(k.version, k.key);
        return newest;
      }
      const fresh: StoredKey = { version: `k${Date.now().toString(36)}`, key: await generate(), createdAt: Date.now() };
      const retained = [fresh, ...keys].slice(0, 2);
      await request(db, 'readwrite', (s) => s.put(retained, slot));
      for (const k of retained) cache.set(k.version, k.key);
      return fresh;
    } finally {
      db.close();
    }
  }

  const current = () =>
    (inflight ??= load().catch((error: unknown) => {
      // A transient failure (private mode, a blocked upgrade) must not disable encryption for the tab.
      inflight = null;
      throw error;
    }));

  return {
    current,
    async byVersion(version) {
      if (!cache.has(version)) await current();
      const key = cache.get(version);
      return key ? { version, key } : null;
    },
    async destroy() {
      inflight = null;
      cache.clear();
      const db = await openDb();
      try {
        await request(db, 'readwrite', (s) => s.delete(slot));
      } finally {
        db.close();
      }
    },
  };
}

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new KeyringError('IndexedDB is unavailable; use memoryKeyring() or passphraseKeyring().'));
  }
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('warden-security', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(new KeyringError('IndexedDB could not be opened.'));
    open.onblocked = () => reject(new KeyringError('IndexedDB upgrade is blocked by another tab.'));
  });
}

function request<T>(db: IDBDatabase, mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = run(db.transaction('keys', mode).objectStore('keys'));
    req.onsuccess = () => resolve(req.result as T);
    req.onerror = () => reject(new KeyringError('IndexedDB request failed.'));
  });
}

/**
 * PBKDF2 from something the user knows: data survives a reload but is
 * unreadable without the user present. Only as strong as the passphrase, and
 * browser PBKDF2 is far weaker than server-side key management.
 */
export function passphraseKeyring(passphrase: string, options: { salt: string; iterations?: number }): Keyring {
  const iterations = options.iterations ?? 600_000;
  let handle: Promise<KeyHandle> | null = null;
  const derive = async (): Promise<KeyHandle> => {
    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase.normalize('NFC')),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode(options.salt), iterations, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    return { version: `pb${iterations}`, key };
  };
  return {
    current: () => (handle ??= derive()),
    async byVersion(version) {
      const h = await (handle ??= derive());
      return h.version === version ? h : null;
    },
    destroy: async () => {
      handle = null;
    },
  };
}

/**
 * Raw key bytes, for tests and non-browser use. In browser code the key is
 * then in your bundle and the encryption is decorative.
 */
export function rawKeyring(secret: Uint8Array<ArrayBuffer>, version = 'raw'): Keyring {
  if (secret.byteLength < 32) throw new KeyringError('A raw key must be at least 32 bytes.');
  let handle: Promise<KeyHandle> | null = null;
  const load = () =>
    (handle ??= crypto.subtle
      .importKey('raw', secret.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt'])
      .then((key) => ({ version, key })));
  return {
    current: load,
    async byVersion(v) {
      const h = await load();
      return h.version === v ? h : null;
    },
    destroy: async () => {
      handle = null;
    },
  };
}
