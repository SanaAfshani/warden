# @wardenjs/ssr-csrf

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

CSRF protection for cookie-authenticated writes.

```bash
npm i @wardenjs/ssr @wardenjs/ssr-csrf
```

```ts
import { csrf } from '@wardenjs/ssr-csrf';

const guard = csrf({ secret: process.env.CSRF_SECRET!, origin: 'https://app.example.com' });

// At sign-in: set the cookie, give the token to the client.
const { token, cookie } = await guard.issue();

// On writes:
export const POST = chain().use(guard.protect()).use(session.required()).handle(update);
```

Three layers, because each alone has a gap:

1. Your session cookie's SameSite.
2. `Sec-Fetch-Site`, then exact `Origin`, then `Referer`.
3. A signed double-submit token (`x-csrf-token` header must equal the
   `__Host-csrf` cookie, and carry a valid HMAC). The signature defeats cookie
   tossing from a sibling subdomain.

Safe methods pass. Not needed for Bearer-token APIs or webhooks, where the
browser attaches nothing. Use a secret distinct from the session secret.
