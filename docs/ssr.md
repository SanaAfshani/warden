# SSR track

`@wardenjs/ssr` is the contract; every control is a plugin package
built on it. The core contains no control of its own and needs no
configuration, secret or environment variable.

## The contract

```ts
type Handler<Context> = (request: Request, context: Context) => Promise<Response>;

interface Decorator<Needs, Adds> {
  name: string;
  wrap(inner: Handler<Needs & Adds>): Handler<Needs>;
}
```

A decorator receives the handler it wraps and returns a handler with the same
shape. It may answer without calling inward (a rejection), change what the
inner handler sees (add context), or change what comes back (add headers).
`defineDecorator` covers the common case:

```ts
const tenant = defineDecorator<{ principal: Principal }, { tenantId: string }>(
  'tenant',
  async (request, context, next) => {
    const tenantId = await tenantOf(context.principal.id);
    if (!tenantId) throw new HttpError(403, 'no_tenant', 'No tenant.');
    return next({ tenantId });
  },
);
```

- `next(adds)` merges `adds` into the context for everything inside.
- Throwing `HttpError` rejects. `next()` turns an inner `HttpError` into its
  response, so outer decorators still see it and can add headers to it.
- Any other error propagates. `requestLogger` turns it into an opaque 500.

## Composition

```ts
const handler = chain().use(a).use(b).use(c).handle(fn); // a(b(c(fn)))
```

The first `.use()` is outermost: it sees the request first and the response
last. Chains are immutable, so a shared base is safe:

```ts
const api = chain().use(secureHeaders()).use(requestLogger(logger));
export const GET = api.use(session.required()).handle(listPosts);
```

`.handle()` returns `(request, route?) => Promise<Response>`, which is a
Next.js route handler as is. `route.params` (a promise in Next 15+) arrives
awaited as `context.params`.

**Types.** Each decorator declares what it needs and what it adds.
`chain().use(access.require('x'))` with no authentication before it does not
compile: the error names the missing context key.

## Recommended order

| # | Decorator | Why here |
| --- | --- | --- |
| 1 | `secureHeaders()` | Outermost, so every response, including 401/429/500, carries the headers. |
| 2 | `requestLogger(logger)` | Error boundary: everything inside may throw. |
| 3 | `limiter.limit(...)` | Cheapest rejection, before any crypto or database work. |
| 4 | `csrf.protect()` | Forged writes stop before they touch the session. |
| 5 | `session.required()` / `authenticate(...)` | Adds `principal`. |
| 6 | `access.require(...)` | Needs `principal`. |
| 7 | `body(...)` / `query(...)` / `params(...)` | Unauthorised callers never get their body parsed. |
| 8 | `webhook(...)` / `upload(...)` | Instead of 4 to 7 on routes they apply to. |

`cors()` goes next to `secureHeaders()`, and only when a separate, named
origin calls the API.

## Plugins

| Package | Gives you | Adds to context |
| --- | --- | --- |
| `-headers` | `secureHeaders`, `buildCsp`, `cspNonce`, `cors` | |
| `-ratelimit` | `rateLimiter({ store })`, `memoryStore`, `upstashStore` | |
| `-authn` | `sessions`, `authenticate`, `lockout`, password policy; `/node`: `passwordHasher` | `principal`, `session` |
| `-csrf` | `csrf({ secret, origin })` | |
| `-access` | `accessControl({ roles, grants })` | |
| `-validate` | `body`, `query`, `params`, `readJson`, `readForm` | `body`, `query`, `params` |
| `-logging` | `createLogger`, `requestLogger` | `log`, `requestId` |
| `-crypto` | `cipher`, `signer`, `verifyWebhook`, `webhook` | `rawBody` |
| `-ssrf` (Node only) | `createSafeFetch` | |
| `-upload` | `checkUpload`, `upload` | `upload` |

Plugins never log or call home. Each takes an optional `onEvent`; pass
`logger.event` to audit everything through one place.

## Application vocabulary

Roles, permissions and the principal shape are yours. Declare them once:

```ts
declare module '@wardenjs/ssr' {
  interface SecurityRegistry {
    role: 'user' | 'admin';
    permission: 'post:create' | 'post:delete';
    principal: { id: string; role: 'user' | 'admin'; tenantId: string };
  }
}
```

After that, `access.require('post:craete')` is a compile error.

## Writing a plugin

1. A package under `packages/ssr/<name>` that peer-depends on `@wardenjs/ssr`.
2. Export factories that return `Decorator`s. Take options; read no
   environment variables and keep no module-level state.
3. Validate secrets lazily (`assertStrongSecret` on first use), so a build
   without secrets still works.
4. Throw `HttpError` with a stable `code` and a message that reveals nothing
   about the internals.
5. Report through `emit(options.onEvent, …)`.
6. Use only Fetch-API globals unless the package is Node-only (then say so in
   the README and add `"types": ["node"]`).
