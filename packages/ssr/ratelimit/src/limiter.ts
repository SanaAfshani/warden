import {
  clientIp,
  defineDecorator,
  emit,
  HttpError,
  withHeaders,
  type ClientIpOptions,
  type Decorator,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

export interface RateLimitRule {
  limit: number;
  windowSeconds: number;
}

/**
 * Anything with an atomic increment. Redis `INCRBY`, DynamoDB `ADD`, Postgres
 * `INSERT … ON CONFLICT DO UPDATE … RETURNING` all qualify; a read-then-write
 * does not, because concurrent requests then all read the same count.
 */
export interface RateLimitStore {
  /** Add `amount`, set the TTL only if the key is new, return the new value. */
  increment(key: string, amount: number, ttlSeconds: number): Promise<number>;
  get(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Unix ms when the current window closes. */
  resetAt: number;
  /** 0 when allowed, at least 1 when blocked. */
  retryAfterSeconds: number;
}

export interface LimitOptions<Context extends object> extends RateLimitRule {
  /** Separates budgets, so a cheap endpoint cannot spend login's. */
  scope: string;
  /** Default: the client IP. Must be bounded in length; it becomes a store key. */
  key?: (request: Request, context: Context) => string | Promise<string>;
}

export interface RateLimiterOptions {
  store: RateLimitStore;
  /** How to find the client IP behind your proxies. See `clientIp`. */
  ip?: ClientIpOptions;
  onEvent?: SecurityEventHandler;
}

export interface RateLimiter {
  check(key: string, rule: RateLimitRule): Promise<RateLimitResult>;
  reset(key: string, rule: RateLimitRule): Promise<void>;
  /** Rejects with 429 + Retry-After; adds RateLimit headers to every response. */
  limit<Context extends object = object>(options: LimitOptions<Context>): Decorator<Context>;
}

/**
 * Sliding-window counter: `current + previous × overlap`. A fixed window lets
 * a client spend the whole budget twice across a boundary; exact sliding
 * windows need a timestamp per request (memory as a DoS vector). Two integers
 * per key is the right trade for abuse prevention.
 */
export function rateLimiter(options: RateLimiterOptions): RateLimiter {
  const { store } = options;

  const keys = (key: string, rule: RateLimitRule, now: number) => {
    const windowMs = rule.windowSeconds * 1000;
    const window = Math.floor(now / windowMs);
    // The window number is in the key, so old windows expire by TTL alone.
    const base = `rl:${rule.windowSeconds}:${key}`;
    return { windowMs, window, current: `${base}:${window}`, previous: `${base}:${window - 1}` };
  };

  const check: RateLimiter['check'] = async (key, rule) => {
    const now = Date.now();
    const k = keys(key, rule, now);
    // Two windows of TTL: the previous one must survive while it still overlaps.
    const [current, previous] = await Promise.all([
      store.increment(k.current, 1, rule.windowSeconds * 2),
      store.get(k.previous),
    ]);
    const overlap = 1 - (now - k.window * k.windowMs) / k.windowMs;
    const estimate = current + previous * overlap;
    const allowed = estimate <= rule.limit;
    const resetAt = (k.window + 1) * k.windowMs;
    return {
      allowed,
      limit: rule.limit,
      remaining: Math.max(0, Math.floor(rule.limit - estimate)),
      resetAt,
      // Never 0: `Retry-After: 0` turns a 429 into a busy loop.
      retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((resetAt - now) / 1000)),
    };
  };

  return {
    check,
    async reset(key, rule) {
      const k = keys(key, rule, Date.now());
      await Promise.all([store.reset(k.current), store.reset(k.previous)]);
    },
    limit<Context extends object = object>(limit: LimitOptions<Context>): Decorator<Context> {
      return defineDecorator<Context>('rateLimit', async (request, context, next) => {
        const id = limit.key ? await limit.key(request, context) : clientIp(request, options.ip);
        const result = await check(`${limit.scope}:${id}`, limit);
        const headers = rateLimitHeaders(result);
        if (!result.allowed) {
          emit(options.onEvent, {
            type: 'ratelimit.exceeded',
            outcome: 'blocked',
            target: limit.scope,
            request,
          });
          throw new HttpError(429, 'rate_limited', 'Too many requests.', { headers });
        }
        return withHeaders(await next(), headers);
      });
    },
  };
}

/** IETF `RateLimit-*` plus `Retry-After` when blocked. Sent on allowed responses too, so clients can slow down. */
export function rateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    'RateLimit-Limit': String(result.limit),
    'RateLimit-Remaining': String(result.remaining),
    'RateLimit-Reset': String(Math.max(0, Math.ceil((result.resetAt - Date.now()) / 1000))),
  };
  if (!result.allowed) headers['Retry-After'] = String(result.retryAfterSeconds);
  return headers;
}
