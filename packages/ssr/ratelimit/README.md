# @sanaafshani/warden-ssr-ratelimit

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Sliding-window rate limiting as a decorator.

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-ratelimit
```

```ts
import { memoryStore, rateLimiter, upstashStore } from '@sanaafshani/warden-ssr-ratelimit';

const limiter = rateLimiter({
  store: process.env.UPSTASH_URL
    ? upstashStore({ url: process.env.UPSTASH_URL, token: process.env.UPSTASH_TOKEN!, fail: 'closed' })
    : memoryStore(),
  ip: { trustedHops: 1 }, // proxies that append to X-Forwarded-For
});

export const POST = chain()
  .use(limiter.limit({ scope: 'login', limit: 5, windowSeconds: 60 }))
  .handle(login);

// Per user instead of per IP, after authentication:
chain().use(session.required()).use(limiter.limit({ scope: 'export', limit: 10, windowSeconds: 3600, key: (_r, c) => c.principal.id }));
```

- Blocks with 429, `Retry-After` (never 0) and IETF `RateLimit-*` headers;
  allowed responses carry the headers too.
- `memoryStore` is per process and bounded (`maxEntries`); use a shared store
  with more than one instance.
- `upstashStore` is atomic (`INCRBY` + `EXPIRE NX` in one transaction). `fail`
  is required: `'closed'` blocks during an outage (for login), `'open'` allows.
- Any `RateLimitStore` with an atomic increment works.
- Configure `ip` for your proxy setup. The left side of `X-Forwarded-For` is
  client-controlled and never used.
