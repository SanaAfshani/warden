import { afterEach, describe, expect, it, vi } from 'vitest';
import { chain } from '@wardenjs/ssr';
import { sessions } from '../src/index.js';

const secret = 'k9$Lm2#Qp7@Zx4!Rt8&Wv1^Ny6*Bc3%Hd5';
const issuer = 'https://app.test';
const user = { userId: 'u1', role: 'user', version: 1 };

const withCookie = (token: string) =>
  new Request('https://app.test/me', { headers: { cookie: `__Host-session=${token}` } });
const tokenFrom = (response: Response) =>
  response.headers.getSetCookie().find((c) => c.startsWith('__Host-session='))?.split(';')[0]?.split('=')[1];
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');

afterEach(() => {
  vi.useRealTimers();
});

describe('sessions', () => {
  it('admits a valid session and gives the handler the principal', async () => {
    const s = sessions({ secret, issuer });
    const handler = chain().use(s.required()).handle((_r, c) => Response.json(c.principal));
    const response = await handler(withCookie(await s.create(user)));
    expect(await response.json()).toEqual({ id: 'u1', role: 'user' });
  });

  it('rejects alg=none tokens: the algorithm is pinned, not read from the token', async () => {
    const s = sessions({ secret, issuer });
    const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'admin', role: 'admin', iss: issuer, aud: issuer })}.`;
    expect(await s.verify(forged)).toMatchObject({ valid: false });
  });

  it('rejects a token signed for another issuer (staging token in production)', async () => {
    const staging = sessions({ secret, issuer: 'https://staging.app.test' });
    const production = sessions({ secret, issuer });
    expect(await production.verify(await staging.create(user))).toEqual({ valid: false, reason: 'invalid' });
  });

  it('answers an invalid cookie with 401 and clears it', async () => {
    const s = sessions({ secret, issuer });
    const response = await chain().use(s.required()).handle(() => new Response())(withCookie('a.b.c'));
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie().some((c) => c.includes('Max-Age=0'))).toBe(true);
  });

  it('renews an active session past half its idle life, without moving the absolute deadline', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const s = sessions({ secret, issuer, idleTtlSeconds: 600, absoluteTtlSeconds: 3600 });
    const handler = chain().use(s.required()).handle(() => new Response());
    const token = await s.create(user);
    // Fresh tokens are not re-issued: a Set-Cookie on every response breaks caching.
    expect(tokenFrom(await handler(withCookie(token)))).toBeUndefined();

    vi.advanceTimersByTime(400_000);
    const renewed = tokenFrom(await handler(withCookie(token)));
    const before = await s.verify(token);
    const after = await s.verify(renewed);
    if (!before.valid || !after.valid) throw new Error('expected both tokens to be valid');
    expect(after.session.absoluteExpiresAt).toBe(before.session.absoluteExpiresAt);
    expect(after.session.sessionId).toBe(before.session.sessionId);
    expect(after.session.expiresAt).toBeGreaterThan(before.session.expiresAt);
  });

  it('expires at the absolute deadline even for a session renewed all along', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const s = sessions({ secret, issuer, idleTtlSeconds: 600, absoluteTtlSeconds: 1200 });
    let token = await s.create(user);
    const handler = chain().use(s.required()).handle(() => new Response());
    for (let i = 0; i < 4; i++) {
      vi.advanceTimersByTime(350_000);
      const response = await handler(withCookie(token));
      token = tokenFrom(response) ?? token;
    }
    expect((await handler(withCookie(token))).status).toBe(401);
  });

  it('lets a handler that sets the session cookie (logout) have the last word', async () => {
    const s = sessions({ secret, issuer });
    const logout = chain()
      .use(s.required())
      .handle(() => new Response(null, { headers: { 'set-cookie': s.clearCookie() } }));
    const response = await logout(withCookie(await s.create(user)));
    expect(response.headers.getSetCookie()).toHaveLength(1);
  });

  it('logs out every device when load() reports a bumped version', async () => {
    const s = sessions({ secret, issuer, load: (session) => (session.version === 2 ? { id: session.userId, role: session.role } : null) });
    const response = await chain().use(s.required()).handle(() => new Response())(withCookie(await s.create(user)));
    expect(response.status).toBe(401);
  });
});
