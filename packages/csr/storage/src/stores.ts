import { emit, type KeyValueStore, type SecurityEventHandler } from '@sanaafshani/warden-csr';

/** Lives as long as the tab; never touches disk; invisible to other tabs. The most private choice. */
export function memoryStore(): KeyValueStore {
  const map = new Map<string, string>();
  return {
    get: (key) => Promise.resolve(map.get(key) ?? null),
    set: (key, value) => Promise.resolve(void map.set(key, value)),
    remove: (key) => Promise.resolve(void map.delete(key)),
    keys: () => Promise.resolve([...map.keys()]),
  };
}

/**
 * `localStorage` (survives everything, shared by tabs, plaintext on disk) or
 * `sessionStorage` (one tab, survives reload). Falls back to memory where
 * Web Storage is missing or throws on access (server rendering, sandboxed
 * iframes, disabled site data), reporting `storage.unavailable`, so a
 * security library never crashes the page.
 */
export function webStorage(
  kind: 'local' | 'session',
  options: { onEvent?: SecurityEventHandler } = {},
): KeyValueStore {
  let storage: Storage;
  try {
    storage = kind === 'local' ? globalThis.localStorage : globalThis.sessionStorage;
    const probe = '__warden_probe__';
    storage.setItem(probe, '1');
    storage.removeItem(probe);
  } catch {
    emit(options.onEvent, { type: 'storage.unavailable', reason: kind });
    return memoryStore();
  }
  const attempt = <T>(run: () => T, fallback: T): Promise<T> => {
    try {
      return Promise.resolve(run());
    } catch {
      // Quota exceeded or revoked access: the caller sees a miss, which it must handle anyway.
      return Promise.resolve(fallback);
    }
  };
  return {
    get: (key) => attempt(() => storage.getItem(key), null),
    set: (key, value) => attempt(() => storage.setItem(key, value), undefined),
    remove: (key) => attempt(() => storage.removeItem(key), undefined),
    keys: () =>
      attempt(() => Array.from({ length: storage.length }, (_, i) => storage.key(i)).filter((k) => k !== null), []),
  };
}
