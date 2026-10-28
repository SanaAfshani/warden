import { afterEach, describe, expect, it, vi } from 'vitest';
import { decorate, type Fetcher } from '@wardenjs/csr';
import { bffSession, idleTimeout, safeReturnTo, sessionChannel, withCsrf, withSessionRefresh } from '../src/index.js';

const here = globalThis.location.origin;
const urlOf = (input: RequestInfo | URL) => (input instanceof Request ? input.url : input.toString());

afterEach(() => {
  vi.useRealTimers();
});

describe('safeReturnTo', () => {
  it.each([
    'https://evil.example/',
    '//evil.example',
    '/\\evil.example',
    '/%2f%2fevil.example',
    '/%5Cevil.example',
    '\t//evil.example',
    '/\t/evil.example',
    'javascript:alert(1)',
    '/%E0%A4%A',
  ])('rejects %j', (value) => {
    expect(safeReturnTo(value)).toBe('/');
  });

  it('keeps relative paths with query and hash', () => {
    expect(safeReturnTo('/orders/1?tab=items#top')).toBe('/orders/1?tab=items#top');
  });
});

const recorder = (status = 200) => {
  const calls: { url: string; headers: Headers }[] = [];
  const fetcher: Fetcher = async (input, init) => {
    calls.push({ url: urlOf(input), headers: new Headers(init?.headers) });
    return new Response(null, { status });
  };
  return { calls, fetcher };
};

describe('withCsrf', () => {
  it('adds the token to unsafe same-origin requests only', async () => {
    const { calls, fetcher } = recorder();
    const api = decorate(fetcher, withCsrf({ token: () => 'tok' }));
    await api(`${here}/api/x`, { method: 'POST' });
    await api(`${here}/api/x`);
    await api('https://third-party.example/collect', { method: 'POST' });
    expect(calls.map((c) => c.headers.get('x-csrf-token'))).toEqual(['tok', null, null]);
  });
});

describe('withSessionRefresh', () => {
  it('refreshes once and retries once on a 401 from your API', async () => {
    let first = true;
    const inner: Fetcher = async () => {
      const status = first ? 401 : 200;
      first = false;
      return new Response(null, { status });
    };
    const refresh = vi.fn(async () => true);
    const api = decorate(inner, withSessionRefresh({ refresh }));
    expect((await api(`${here}/api/x`)).status).toBe(200);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('ignores a 401 from another origin: it says nothing about your session', async () => {
    const refresh = vi.fn(async () => true);
    const api = decorate(recorder(401).fetcher, withSessionRefresh({ refresh }));
    await api('https://third-party.example/x');
    expect(refresh).not.toHaveBeenCalled();
  });

  it('reports expiry and returns the 401 when the refresh fails', async () => {
    const onExpired = vi.fn();
    const api = decorate(recorder(401).fetcher, withSessionRefresh({ refresh: async () => false, onExpired }));
    expect((await api(`${here}/api/x`)).status).toBe(401);
    expect(onExpired).toHaveBeenCalledTimes(1);
  });
});

describe('bffSession', () => {
  const endpoints = { login: '/auth/login', logout: '/auth/logout', session: '/auth/session', refresh: '/auth/refresh' };

  it('shares one refresh between parallel 401s (a rotating refresh token survives one use)', async () => {
    let refreshed = false;
    const fetch = vi.fn<Fetcher>(async (input) => {
      const url = urlOf(input);
      if (url.endsWith('/auth/refresh')) {
        refreshed = true;
        return new Response(null, { status: 204 });
      }
      if (url.endsWith('/auth/session')) return Response.json({ authenticated: true, user: { id: 'u1' } });
      return new Response(null, { status: refreshed ? 200 : 401 });
    });
    const session = bffSession({ endpoints, fetch, channel: sessionChannel('test-refresh') });
    const results = await Promise.all(Array.from({ length: 8 }, () => session.fetch(`${here}/api/x`)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(fetch.mock.calls.filter(([input]) => urlOf(input).endsWith('/auth/refresh'))).toHaveLength(1);
    session.destroy();
  });

  it('validates returnTo before navigating to login', () => {
    const navigate = vi.fn();
    const session = bffSession({ endpoints, navigate, fetch: recorder().fetcher, channel: sessionChannel('test-login') });
    session.login('//evil.example');
    expect(new URL(navigate.mock.calls[0]?.[0] as string).searchParams.get('returnTo')).toBe('/');
    session.destroy();
  });

  it('does not refresh in a loop when the server reports an expiry already in the past', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn<Fetcher>(async (input) =>
      urlOf(input).endsWith('/auth/session')
        ? Response.json({ authenticated: true, user: {}, expiresAt: 1_700_000_000 })
        : new Response(null, { status: 204 }),
    );
    const session = bffSession({ endpoints, fetch, channel: sessionChannel('test-loop') });
    await session.load();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetch.mock.calls.filter(([input]) => urlOf(input).endsWith('/auth/refresh')).length).toBeLessThanOrEqual(1);
    session.destroy();
  });

  it('signs out other tabs on logout', async () => {
    const other = sessionChannel('test-logout');
    const heard = new Promise<void>((resolve) => other.onLogout(resolve));
    const session = bffSession({ endpoints, fetch: recorder().fetcher, channel: sessionChannel('test-logout') });
    await session.logout();
    await heard;
    expect(session.current()).toEqual({ authenticated: false, user: null });
    other.close();
    session.destroy();
  });
});

describe('idleTimeout', () => {
  it('times out after inactivity and resets on activity', () => {
    vi.useFakeTimers();
    const onTimeout = vi.fn();
    const target = new EventTarget();
    const idle = idleTimeout({ idleSeconds: 60, tickSeconds: 1, onTimeout, target, crossTab: false });
    idle.start();
    vi.advanceTimersByTime(50_000);
    target.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(50_000);
    expect(onTimeout).not.toHaveBeenCalled();
    vi.advanceTimersByTime(11_000);
    expect(onTimeout).toHaveBeenCalledWith('idle');
  });

  it('removes its listeners with the same capture flag it added them with', () => {
    const target = new EventTarget();
    const add = vi.spyOn(target, 'addEventListener');
    const remove = vi.spyOn(target, 'removeEventListener');
    const idle = idleTimeout({ idleSeconds: 60, onTimeout: () => undefined, target, crossTab: false });
    idle.start();
    idle.stop();
    expect(remove.mock.calls.map((c) => [c[0], c[2]])).toEqual(add.mock.calls.map((c) => [c[0], c[2]]));
  });

  it('does not count the tab being hidden as activity', () => {
    vi.useFakeTimers();
    const onTimeout = vi.fn();
    const idle = idleTimeout({ idleSeconds: 60, tickSeconds: 1, onTimeout, target: new EventTarget(), crossTab: false });
    idle.start();
    vi.advanceTimersByTime(55_000);
    document.dispatchEvent(new Event('visibilitychange'));
    vi.advanceTimersByTime(6_000);
    expect(onTimeout).toHaveBeenCalledWith('idle');
  });
});
