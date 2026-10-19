import { useCallback, useEffect, useRef, useState } from 'react';
import type { JsonStore } from './adapters.js';

export interface StoredValue<T> {
  value: T | null;
  /** True until the first read resolves. */
  loading: boolean;
  set(value: T): Promise<void>;
  remove(): Promise<void>;
}

/** `useState` over an async (typically encrypted) store. Unreadable values arrive as null. */
export function useStoredValue<Schema extends Record<string, unknown>, K extends keyof Schema & string>(
  store: JsonStore<Schema>,
  key: K,
): StoredValue<Schema[K]> {
  const [value, setValue] = useState<Schema[K] | null>(null);
  const [loading, setLoading] = useState(true);
  // A read that resolves after `key` changed must not overwrite the newer value.
  const generation = useRef(0);

  useEffect(() => {
    const mine = ++generation.current;
    setLoading(true);
    void store
      .get(key)
      .catch(() => null)
      .then((next) => {
        if (generation.current !== mine) return;
        setValue(next);
        setLoading(false);
      });
  }, [store, key]);

  const set = useCallback(
    async (next: Schema[K]) => {
      await store.set(key, next);
      // After the write, so a failed write is not shown as stored.
      setValue(next);
    },
    [store, key],
  );
  const remove = useCallback(async () => {
    await store.remove(key);
    setValue(null);
  }, [store, key]);

  return { value, loading, set, remove };
}
