import { describe, expect, it } from 'vitest';
import { chain } from '@sanaafshani/warden-ssr';
import { memoryStore, rateLimiter } from '../src/index.js';

const fromIp = (ip: string) => new Request('https://api.test/login', { headers: { 'x-forwarded-for': ip } });

describe('rateLimiter', () => {
  it('blocks past the limit with a 429 and a Retry-After of at least 1', async () => {
    const limiter = rateLimiter({ store: memoryStore() });
    const handler = chain()
      .use(limiter.limit({ scope: 'login', limit: 2, windowSeconds: 60 }))
      .handle(() => new Response('ok'));
    expect((await handler(fromIp('203.0.113.1'))).status).toBe(200);
    const second = await handler(fromIp('203.0.113.1'));
    expect(second.headers.get('ratelimit-remaining')).toBe('0');
    const third = await handler(fromIp('203.0.113.1'));
    expect(third.status).toBe(429);
    expect(Number(third.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  });

  it('keeps budgets per client and per scope', async () => {
    const limiter = rateLimiter({ store: memoryStore() });
    const login = chain().use(limiter.limit({ scope: 'login', limit: 1, windowSeconds: 60 })).handle(() => new Response());
    const search = chain().use(limiter.limit({ scope: 'search', limit: 1, windowSeconds: 60 })).handle(() => new Response());
    await login(fromIp('203.0.113.1'));
    expect((await login(fromIp('203.0.113.2'))).status).toBe(200);
    expect((await search(fromIp('203.0.113.1'))).status).toBe(200);
  });

  it('cannot be dodged by rotating the spoofable left side of X-Forwarded-For', async () => {
    const limiter = rateLimiter({ store: memoryStore() });
    const handler = chain().use(limiter.limit({ scope: 'login', limit: 1, windowSeconds: 60 })).handle(() => new Response());
    await handler(fromIp('1.1.1.1, 203.0.113.7'));
    expect((await handler(fromIp('2.2.2.2, 203.0.113.7'))).status).toBe(429);
  });

  it('memoryStore stays bounded under key flooding', async () => {
    const store = memoryStore({ maxEntries: 100 });
    for (let i = 0; i < 1000; i++) await store.increment(`k${i}`, 1, 60);
    expect(store.size()).toBeLessThanOrEqual(100);
  });
});
