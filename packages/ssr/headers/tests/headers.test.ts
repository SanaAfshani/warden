import { describe, expect, it } from 'vitest';
import { chain, HttpError } from '@sanaafshani/warden-ssr';
import { buildCsp, cors, secureHeaders } from '../src/index.js';

const request = (init: RequestInit & { headers?: Record<string, string> } = {}) => new Request('https://api.test/x', init);

describe('secureHeaders', () => {
  it('also hardens rejections from inner decorators', async () => {
    const handler = chain()
      .use(secureHeaders())
      .handle(() => {
        throw new HttpError(401, 'unauthenticated', 'No.');
      });
    const response = await handler(request());
    expect(response.status).toBe(401);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('strict-transport-security')).toContain('max-age=');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('marks per-user responses uncacheable and varies on credentials, so a shared cache cannot serve them to another user', async () => {
    const response = await chain()
      .use(secureHeaders())
      .handle(() => new Response('me', { headers: { vary: 'Accept' } }))(request());
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('vary')).toBe('Accept, Cookie, Authorization');
  });

  it('lets the handler override a header it set itself', async () => {
    const response = await chain()
      .use(secureHeaders())
      .handle(() => new Response(null, { headers: { 'x-frame-options': 'SAMEORIGIN' } }))(request());
    expect(response.headers.get('x-frame-options')).toBe('SAMEORIGIN');
  });
});

describe('buildCsp', () => {
  it('uses nonce + strict-dynamic (no bypassable host allowlist) and closes plugin and base-tag injection', () => {
    const csp = buildCsp({ nonce: 'abc' });
    expect(csp).toMatch(/script-src 'nonce-abc' 'strict-dynamic'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).not.toContain('unsafe-eval');
  });
});

describe('cors', () => {
  const allow = cors({ origins: ['https://app.test'], credentials: true });

  it('reflects only listed origins, and always varies on Origin', async () => {
    const handler = chain().use(allow).handle(() => new Response('ok'));
    const evil = await handler(request({ headers: { origin: 'https://app.test.evil.example' } }));
    expect(evil.headers.get('access-control-allow-origin')).toBeNull();
    expect(evil.headers.get('vary')).toBe('Origin');
    const good = await handler(request({ headers: { origin: 'https://app.test' } }));
    expect(good.headers.get('access-control-allow-origin')).toBe('https://app.test');
  });

  it('answers preflight without running the handler', async () => {
    let ran = false;
    const response = await chain()
      .use(allow)
      .handle(() => {
        ran = true;
        return new Response();
      })(request({ method: 'OPTIONS', headers: { origin: 'https://app.test', 'access-control-request-method': 'POST' } }));
    expect(response.status).toBe(204);
    expect(ran).toBe(false);
  });

  it('refuses a wildcard origin', () => {
    expect(() => cors({ origins: ['*'] })).toThrow();
  });
});
