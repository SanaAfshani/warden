/**
 * Same shape as `RateLimitStore` from `@sanaafshani/warden-ssr-ratelimit`, so
 * those stores work here; declared locally so authn does not depend on it.
 * Must be shared across instances, or each instance has its own budget.
 */
export interface CounterStore {
  increment(key: string, amount: number, ttlSeconds: number): Promise<number>;
  get(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}

export interface LockoutOptions {
  store: CounterStore;
  /** Failures before delays start. Default 5. */
  softThreshold?: number;
  /** Failures before a hard lock. Default 20. */
  hardThreshold?: number;
  /** Failure-counting window. Default 900 s. */
  windowSeconds?: number;
  /** Default 900 s. */
  lockSeconds?: number;
  /** Delay = base × 2^(failures − soft), capped. Defaults 250 ms and 8000 ms. */
  backoffBaseMs?: number;
  backoffMaxMs?: number;
}

export interface LockoutState {
  attempts: number;
  locked: boolean;
  lockedForSeconds: number;
  /** Hold the response this long before answering (see `lockout().delay`). */
  delayMs: number;
}

export interface Lockout {
  /** Before verifying the password. */
  check(identifier: string): Promise<LockoutState>;
  /** After a failed verification. */
  recordFailure(identifier: string): Promise<LockoutState>;
  /** After a successful one. Does not touch IP rate limits. */
  recordSuccess(identifier: string): Promise<void>;
  delay(state: LockoutState): Promise<void>;
}

/**
 * Graduated, because "lock after 5 failures" lets anyone who knows an email
 * address lock its owner out. Delays destroy an attacker's throughput while a
 * user who mistypes three times notices nothing; the hard lock is far beyond
 * human error. The delay is capped: an unbounded sleep holds a connection per
 * request and turns the defence into the DoS. Key by account AND check an IP
 * rate limit too: per-account alone misses credential stuffing.
 */
export function lockout(options: LockoutOptions): Lockout {
  const soft = options.softThreshold ?? 5;
  const hard = options.hardThreshold ?? 20;
  const window = options.windowSeconds ?? 900;
  const lockSeconds = options.lockSeconds ?? 900;
  const base = options.backoffBaseMs ?? 250;
  const max = options.backoffMaxMs ?? 8000;
  const { store } = options;
  const failKey = (id: string) => `authn:fail:${id}`;
  const lockKey = (id: string) => `authn:lock:${id}`;

  const delayFor = (attempts: number) =>
    attempts <= soft ? 0 : Math.min(base * 2 ** (attempts - soft - 1), max);

  async function check(identifier: string): Promise<LockoutState> {
    const [attempts, lockedUntil] = await Promise.all([
      store.get(failKey(identifier)),
      store.get(lockKey(identifier)),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const locked = lockedUntil > now;
    return {
      attempts,
      locked,
      lockedForSeconds: locked ? Math.min(lockedUntil - now, lockSeconds) : 0,
      delayMs: delayFor(attempts),
    };
  }

  return {
    check,
    async recordFailure(identifier) {
      const attempts = await store.increment(failKey(identifier), 1, window);
      if (attempts >= hard && !(await check(identifier)).locked) {
        // An absolute unlock time, set once per lock: concurrent requests cannot shorten it.
        // Reset first: an elapsed lock whose key has not yet expired would otherwise be added to.
        await store.reset(lockKey(identifier));
        await store.increment(lockKey(identifier), Math.floor(Date.now() / 1000) + lockSeconds, lockSeconds);
      }
      return check(identifier);
    },
    async recordSuccess(identifier) {
      await Promise.all([store.reset(failKey(identifier)), store.reset(lockKey(identifier))]);
    },
    delay: (state) =>
      state.delayMs > 0
        ? new Promise((resolve) => setTimeout(resolve, Math.min(state.delayMs, max)))
        : Promise.resolve(),
  };
}
