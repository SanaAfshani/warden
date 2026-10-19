import { decorate, emit, type Fetcher, type SecurityEventHandler } from '@sanaafshani/warden-csr';
import { sessionChannel, type SessionChannel } from './channel.js';
import { withCsrf, withSessionRefresh } from './fetch.js';
import { safeReturnTo } from './return-to.js';

export interface BffEndpoints {
  /** Navigated to (not fetched); your server runs the OIDC code + PKCE flow. */
  login: string;
  logout: string;
  /** GET: the session as JSON, or 401. */
  session: string;
  /** POST: renews the cookie. Omit when the server renews on every request. */
  refresh?: string;
}

/** Your session endpoint's answer. The user model is yours; narrow it with the type parameter. */
export interface SessionState<User = unknown> {
  authenticated: boolean;
  user: User | null;
  /** Unix milliseconds; enables refreshing before expiry. */
  expiresAt?: number;
  csrfToken?: string;
}

export interface BffSessionOptions {
  endpoints: BffEndpoints;
  /** Default `x-csrf-token`. */
  csrfHeader?: string;
  /** Read the token from this readable cookie when the session response does not carry one. */
  csrfCookie?: string;
  /** Refresh this long before `expiresAt`. Default 60. */
  refreshSkewSeconds?: number;
  /** Logout fan-out across tabs. Default `sessionChannel('app')`. */
  channel?: SessionChannel;
  /** Origins that are "your API" (receive CSRF, trigger refresh on 401). Default: this page's origin. */
  origins?: readonly string[];
  fetch?: Fetcher;
  navigate?: (url: string) => void;
  onEvent?: SecurityEventHandler;
}

export interface BffSession<User = unknown> {
  load(): Promise<SessionState<User>>;
  current(): SessionState<User> | null;
  login(returnTo?: string): void;
  logout(): Promise<void>;
  /** Concurrent calls share one request. */
  refresh(): Promise<boolean>;
  /** Your API, with CSRF and one refresh-and-retry on 401. */
  fetch: Fetcher;
  onChange(handler: (state: SessionState<User>) => void): () => void;
  destroy(): void;
}

const SIGNED_OUT: SessionState<never> = { authenticated: false, user: null };
// setTimeout overflows to "now" above 2^31-1 ms, which would refresh in a loop.
const MAX_DELAY = 2 ** 31 - 1;

/**
 * The browser half of a backend-for-frontend: tokens stay on your server
 * behind an httpOnly cookie, so XSS can act while the tab is open but cannot
 * take a token home. Nothing here verifies or stores a token.
 */
export function bffSession<User = unknown>(options: BffSessionOptions): BffSession<User> {
  const { endpoints, refreshSkewSeconds = 60, onEvent } = options;
  const base = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const navigate = options.navigate ?? ((url: string) => globalThis.location.assign(url));
  const channel = options.channel ?? sessionChannel('app');
  const handlers = new Set<(state: SessionState<User>) => void>();
  let state: SessionState<User> | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let refreshedFor: number | undefined;
  let inflightLoad: Promise<SessionState<User>> | null = null;
  let inflightRefresh: Promise<boolean> | null = null;

  const csrfToken = (): string | null => state?.csrfToken ?? (options.csrfCookie ? readCookie(options.csrfCookie) : null);
  const csrfOnly = decorate(base, withCsrf({ token: csrfToken, ...header(options.csrfHeader), ...origins(options.origins) }));
  // Refresh outside CSRF, so the retry carries the token the refresh may have rotated.
  const api = decorate(
    base,
    withSessionRefresh({
      refresh,
      onExpired: () => {
        setState(SIGNED_OUT);
        emit(onEvent, { type: 'sso.session_expired' });
      },
      ...origins(options.origins),
    }),
    withCsrf({ token: csrfToken, ...header(options.csrfHeader), ...origins(options.origins) }),
  );

  const unsubscribe = channel.onLogout(() => setState(SIGNED_OUT));

  function setState(next: SessionState<User>): void {
    state = next;
    schedule();
    for (const handler of handlers) {
      try {
        handler(next);
      } catch {
        // A failing subscriber must not take the session down.
      }
    }
  }

  function schedule(): void {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    const expiresAt = state?.authenticated ? state.expiresAt : undefined;
    if (expiresAt === undefined) return;
    const delay = expiresAt - Date.now() - refreshSkewSeconds * 1000;
    // A deadline that is already past gets one attempt; if it comes back unchanged
    // (clock skew, seconds instead of milliseconds) we stop rather than loop.
    if (delay <= 0 && refreshedFor === expiresAt) return;
    timer = setTimeout(() => {
      refreshedFor = expiresAt;
      void refresh();
    }, Math.min(Math.max(delay, 0), MAX_DELAY));
  }

  async function requestSession(): Promise<SessionState<User>> {
    try {
      const response = await base(endpoints.session, {
        credentials: 'include',
        headers: { accept: 'application/json' },
        cache: 'no-store',
      });
      if (response.status === 401 || response.status === 403) return SIGNED_OUT;
      // A 500 or a network failure is not a logout.
      if (!response.ok) return state ?? SIGNED_OUT;
      const body = (await response.json()) as Partial<SessionState<User>>;
      return {
        authenticated: body.authenticated ?? (body.user !== null && body.user !== undefined),
        user: body.user ?? null,
        ...(typeof body.expiresAt === 'number' ? { expiresAt: body.expiresAt } : {}),
        ...(typeof body.csrfToken === 'string' ? { csrfToken: body.csrfToken } : {}),
      };
    } catch {
      return state ?? SIGNED_OUT;
    }
  }

  async function load(): Promise<SessionState<User>> {
    inflightLoad ??= requestSession().finally(() => {
      inflightLoad = null;
    });
    const next = await inflightLoad;
    setState(next);
    return next;
  }

  // Deduplicated: eight parallel 401s must not fire eight refreshes against a rotating token.
  function refresh(): Promise<boolean> {
    const url = endpoints.refresh;
    if (url === undefined) return load().then((next) => next.authenticated);
    return (inflightRefresh ??= (async () => {
      try {
        const response = await csrfOnly(url, { method: 'POST', credentials: 'include', cache: 'no-store' });
        if (!response.ok) return false;
        return (await load()).authenticated;
      } catch {
        return false;
      }
    })().finally(() => {
      inflightRefresh = null;
    }));
  }

  return {
    load,
    current: () => state,
    login(returnTo) {
      // Even our own value: a returnTo read from the URL is attacker-influenced.
      const url = new URL(endpoints.login, globalThis.location?.href);
      url.searchParams.set('returnTo', safeReturnTo(returnTo));
      navigate(url.toString());
    },
    async logout() {
      // Other tabs first: if the request hangs, the screens are already clear.
      channel.broadcastLogout();
      setState(SIGNED_OUT);
      emit(onEvent, { type: 'sso.logout' });
      try {
        await csrfOnly(endpoints.logout, { method: 'POST', credentials: 'include' });
      } catch {
        // Best effort; local state is already gone.
      }
    },
    refresh,
    fetch: (input, init) => api(input, { credentials: 'include', ...init }),
    onChange(handler) {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    destroy() {
      if (timer !== null) clearTimeout(timer);
      timer = null;
      handlers.clear();
      unsubscribe();
      if (!options.channel) channel.close();
      state = null;
    },
  };
}

const header = (name: string | undefined) => (name === undefined ? {} : { header: name });
const origins = (list: readonly string[] | undefined) => (list === undefined ? {} : { origins: list });

/** The double-submit token is the one cookie meant to be readable: it is compared, not trusted. */
function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  for (const part of document.cookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) {
      try {
        return decodeURIComponent(rest.join('='));
      } catch {
        return null;
      }
    }
  }
  return null;
}
