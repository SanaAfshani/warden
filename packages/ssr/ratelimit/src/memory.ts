import type { RateLimitStore } from './limiter.js';

export interface MemoryStoreOptions {
  /** Keys contain client-controlled data, so the map must be bounded. Default 50 000. */
  maxEntries?: number;
}

/**
 * Per-process counters. Correct for one long-lived process and for tests.
 * Wrong behind a load balancer (each instance has its own budget, so N
 * instances allow N× the limit) and on serverless (every cold start is a
 * fresh budget). Use a shared store there.
 */
export function memoryStore(options: MemoryStoreOptions = {}): RateLimitStore & { size(): number } {
  const max = options.maxEntries ?? 50_000;
  const map = new Map<string, { value: number; expiresAt: number }>();

  // Only at the cap, and without sorting: Map iterates in insertion order, so
  // the front is the oldest. A sort here made eviction itself the DoS.
  const sweep = (now: number) => {
    for (const [key, entry] of map) if (entry.expiresAt <= now) map.delete(key);
    if (map.size < max) return;
    let evict = Math.ceil(max / 10);
    for (const key of map.keys()) {
      map.delete(key);
      if (--evict <= 0) break;
    }
  };

  return {
    increment(key, amount, ttlSeconds) {
      const now = Date.now();
      if (map.size >= max) sweep(now);
      const entry = map.get(key);
      if (!entry || entry.expiresAt <= now) {
        map.set(key, { value: amount, expiresAt: now + ttlSeconds * 1000 });
        return Promise.resolve(amount);
      }
      entry.value += amount;
      return Promise.resolve(entry.value);
    },
    get(key) {
      const entry = map.get(key);
      return Promise.resolve(entry && entry.expiresAt > Date.now() ? entry.value : 0);
    },
    reset(key) {
      map.delete(key);
      return Promise.resolve();
    },
    size: () => map.size,
  };
}
