import type { KeyValueStore } from '@wardenjs/csr';

/** Removes every key the store can see. On a `namespaced` store, only that namespace. Call on logout. */
export async function clearStore(store: KeyValueStore): Promise<void> {
  for (const key of await store.keys()) await store.remove(key);
}

export interface JsonStore<Schema extends Record<string, unknown>> {
  get<K extends keyof Schema & string>(key: K): Promise<Schema[K] | null>;
  set<K extends keyof Schema & string>(key: K, value: Schema[K]): Promise<void>;
  remove(key: keyof Schema & string): Promise<void>;
}

/**
 * Typed values over a string store. The schema is a type parameter, so a
 * misspelt key is a compile error instead of a `null` that reads as logged out.
 * The type is a promise about what you wrote, not a validation of what is read.
 */
export function jsonStore<Schema extends Record<string, unknown>>(store: KeyValueStore): JsonStore<Schema> {
  return {
    async get(key) {
      const raw = await store.get(key);
      if (raw === null) return null;
      try {
        return JSON.parse(raw) as Schema[typeof key];
      } catch {
        await store.remove(key);
        return null;
      }
    },
    set: (key, value) => store.set(key, JSON.stringify(value)),
    remove: (key) => store.remove(key),
  };
}

/**
 * `{ getItem, setItem, removeItem }` for redux-persist and zustand's persist.
 * Persisted state collects things nobody meant to persist (tokens, emails,
 * last admin response); routing it through an encrypted store fixes that once.
 */
export function persistStorage(store: KeyValueStore) {
  return {
    getItem: (key: string) => store.get(key),
    setItem: (key: string, value: string) => store.set(key, value),
    removeItem: (key: string) => store.remove(key),
  };
}
