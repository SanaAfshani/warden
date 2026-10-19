import type { Decorator, Fetcher } from '@sanaafshani/warden-csr';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function targetUrl(input: RequestInfo | URL): URL | null {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  try {
    return new URL(raw, globalThis.location?.href);
  } catch {
    return null;
  }
}

/** True when the request goes to one of `origins` (default: this page's origin). */
export function isOwnOrigin(input: RequestInfo | URL, origins?: readonly string[]): boolean {
  const url = targetUrl(input);
  if (!url) return false;
  const allowed = origins ?? (globalThis.location ? [globalThis.location.origin] : []);
  return allowed.includes(url.origin);
}

function methodOf(input: RequestInfo | URL, init?: RequestInit): string {
  return (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
}

export interface CsrfFetchOptions {
  /** Read at send time, so a token rotated by a refresh is picked up by the retry. */
  token: () => string | null;
  header?: string;
  /** Only these origins receive the token. Default: this page's origin. */
  origins?: readonly string[];
}

/**
 * Adds the CSRF token to unsafe-method requests to your own API. Never to
 * other origins: the token is a credential, and a third-party API is not
 * owed one.
 */
export function withCsrf(options: CsrfFetchOptions): Decorator<Fetcher> {
  const header = options.header ?? 'x-csrf-token';
  return (inner) => (input, init) => {
    if (SAFE_METHODS.has(methodOf(input, init)) || !isOwnOrigin(input, options.origins)) return inner(input, init);
    const token = options.token();
    if (!token) return inner(input, init);
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set(header, token);
    return inner(input, { ...init, headers });
  };
}

export interface SessionRefreshOptions {
  /** Must deduplicate concurrent calls (a rotating refresh token survives one use). */
  refresh: () => Promise<boolean>;
  /** Called when the refresh fails; the 401 is still returned to the caller. */
  onExpired?: (input: RequestInfo | URL) => void;
  origins?: readonly string[];
}

/**
 * On a 401 from your own API: one refresh, one retry. Never a loop (a loop
 * turns a signed-out user into a request storm against your IdP), and never
 * for other origins (their 401 says nothing about your session). Streaming
 * bodies cannot be replayed, so those 401s are returned as is.
 */
export function withSessionRefresh(options: SessionRefreshOptions): Decorator<Fetcher> {
  return (inner) => async (input, init) => {
    if (!isOwnOrigin(input, options.origins)) return inner(input, init);
    const replayable = !(init?.body instanceof ReadableStream);
    const spare = input instanceof Request ? input.clone() : input;
    const response = await inner(input, init);
    if (response.status !== 401 || !replayable) return response;
    if (!(await options.refresh())) {
      options.onExpired?.(input);
      return response;
    }
    return inner(spare, init);
  };
}
