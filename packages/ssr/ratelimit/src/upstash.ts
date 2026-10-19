import { emit, type SecurityEventHandler } from '@sanaafshani/warden-ssr';
import type { RateLimitStore } from './limiter.js';

export interface UpstashStoreOptions {
  url: string;
  token: string;
  /**
   * When the store is unreachable. `closed` denies (login, payments: if the
   * limit cannot be enforced the endpoint must not be served). `open` allows
   * (reads, where availability matters more). No default: it is a decision.
   */
  fail: 'open' | 'closed';
  /** Default 1000 ms. Without a timeout a hanging store hangs every request. */
  timeoutMs?: number;
  onEvent?: SecurityEventHandler;
}

/**
 * Upstash Redis over its REST API: plain `fetch`, so it runs on Edge too.
 * INCRBY and `EXPIRE … NX` go in one MULTI/EXEC, so the TTL is never lost and
 * never pushed forward by later requests.
 */
export function upstashStore(options: UpstashStoreOptions): RateLimitStore {
  if (!options.url || !options.token) throw new Error('upstashStore: `url` and `token` are required.');
  const base = options.url.replace(/\/+$/, '');

  async function call(path: string, body: unknown): Promise<unknown> {
    const response = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${options.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(options.timeoutMs ?? 1000),
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`Upstash HTTP ${response.status}`);
    return response.json();
  }

  const unavailable = (operation: string) =>
    emit(options.onEvent, {
      type: 'ratelimit.store_unavailable',
      outcome: 'failure',
      reason: operation,
      data: { fail: options.fail },
    });

  return {
    async increment(key, amount, ttlSeconds) {
      try {
        const replies = (await call('/multi-exec', [
          ['INCRBY', key, amount],
          ['EXPIRE', key, ttlSeconds, 'NX'],
        ])) as { result?: unknown; error?: string }[];
        const value = Number(replies[0]?.result);
        if (replies[0]?.error || !Number.isFinite(value)) throw new Error('bad reply');
        return value;
      } catch {
        unavailable('increment');
        // Expressed as data, so the limiter answers a clean 429 instead of a 500.
        return options.fail === 'closed' ? Number.POSITIVE_INFINITY : 0;
      }
    },
    async get(key) {
      try {
        const reply = (await call('', ['GET', key])) as { result?: unknown };
        const value = Number(reply.result ?? 0);
        return Number.isFinite(value) ? value : 0;
      } catch {
        // Losing the previous window only degrades sliding to fixed-window.
        unavailable('get');
        return 0;
      }
    },
    async reset(key) {
      try {
        await call('', ['DEL', key]);
      } catch {
        unavailable('reset');
      }
    },
  };
}
