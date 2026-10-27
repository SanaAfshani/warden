# @sanaafshani/warden-ssr

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

The contract every SSR plugin builds on: `Handler`, `Decorator`, `chain()`,
`HttpError`, and the few primitives plugins share. No controls, no
configuration, no dependencies.

```bash
npm i @sanaafshani/warden-ssr
```

```ts
import { chain, defineDecorator, HttpError } from '@sanaafshani/warden-ssr';

const requireJson = defineDecorator('requireJson', (request, _context, next) =>
  request.headers.get('accept')?.includes('application/json')
    ? next()
    : Promise.reject(new HttpError(406, 'not_acceptable', 'JSON only.')),
);

export const GET = chain().use(requireJson).handle(async () => Response.json({ ok: true }));
```

## Exports

| | |
| --- | --- |
| `chain()`, `defineDecorator`, `Decorator`, `Handler`, `BaseContext` | Composition; see [docs/ssr.md](../../../docs/ssr.md). |
| `HttpError` | `status`, stable `code`, safe `message`, optional `details` and `headers`. Responses are `no-store`. |
| `readCookie`, `serializeCookie` | Serialisation enforces `__Host-`/`__Secure-` rules and offers no `Domain`. |
| `readBytes(request, max)` | Body with a running cap (Content-Length is only a hint). |
| `clientIp(request, { header?, trustedHops? })` | Trusts only what your proxies add. |
| `withHeaders`, `withCookie` | Safe on immutable `fetch()` responses. |
| `randomToken`, `randomBytes`, `timingSafeEqual`, `assertStrongSecret`, base64url | |
| `emit`, `SecurityEvent` | The event shape plugins report through `onEvent`. |
| `SecurityRegistry`, `Role`, `Permission`, `Principal` | Augment once with your vocabulary. |
