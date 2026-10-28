# @wardenjs/ssr-headers

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Security headers, CSP and CORS.

```bash
npm i @wardenjs/ssr @wardenjs/ssr-headers
```

```ts
import { buildCsp, cors, cspNonce, secureHeaders } from '@wardenjs/ssr-headers';

// JSON API: the default CSP forbids loading or framing anything.
const api = chain().use(secureHeaders());

// HTML: nonce + strict-dynamic, a fresh nonce per response.
const nonce = cspNonce();
const page = chain().use(secureHeaders({ csp: buildCsp({ nonce }), noStore: false }));

// Only when another, named origin calls this API.
const partner = chain().use(secureHeaders()).use(cors({ origins: ['https://app.example.com'], credentials: true }));
```

- `secureHeaders` sets HSTS, nosniff, Referrer-Policy, Permissions-Policy,
  COOP, CORP, X-Frame-Options, CSP and `no-store` with `Vary: Cookie,
  Authorization`, on rejections too. A header the handler set itself wins.
- `securityHeaders()` returns the static set as a record, for `next.config`
  headers that also cover static assets.
- `cors` accepts exact origins only (no `*`, no patterns) and always sends
  `Vary: Origin`.
- HSTS `preload` is off by default: leaving the preload list takes months.
