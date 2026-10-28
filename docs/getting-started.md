# Getting started

Two tracks, installed separately. Most applications use both, but neither
needs the other — a backend with no browser code installs only the SSR track.

## Install

Pick the core for your side, then the plugins for the controls you actually
want. Plugins declare their core as a **peer** dependency, so every plugin
shares the one copy of the core your app has; a plugin built for another
version of the core is an install-time error rather than a runtime surprise.

```bash
npm i @wardenjs/ssr \
      @wardenjs/ssr-headers \
      @wardenjs/ssr-authn \
      @wardenjs/ssr-ratelimit
```

Node **≥ 22.12** is required. The packages are ESM; CJS consumers load them
through `require(esm)`, which is why the floor is not lower.

## A first chain

A chain is built once and reused. The first `.use()` is outermost: it sees the
request first and the response last.

```ts
// security.ts — one place that knows your secrets.
import { chain } from '@wardenjs/ssr';
import { secureHeaders } from '@wardenjs/ssr-headers';
import { createLogger, requestLogger } from '@wardenjs/ssr-logging';
import { rateLimiter, memoryStore } from '@wardenjs/ssr-ratelimit';

const logger = createLogger();
const limiter = rateLimiter({ store: memoryStore() });

export const api = chain()
  .use(secureHeaders())            // outermost, so even a 500 carries the headers
  .use(requestLogger(logger))      // the error boundary for everything inside
  .use(limiter.limit({ scope: 'api', limit: 60, windowSeconds: 60 }));
```

```ts
// app/api/posts/route.ts
import { api } from '@/security';

export const GET = api.handle(async () => Response.json(await listPosts()));
```

Chains are immutable, so extending the shared base never mutates it:

```ts
export const POST = api.use(session.required()).handle(createPost);
```

`.handle()` returns `(request, route?) => Promise<Response>` — already the
shape of a Next.js route handler, with no adapter.

## Adding authentication

A decorator that adds context changes the type of everything inside it.

```ts
import { sessions } from '@wardenjs/ssr-authn';

const session = sessions({
  secret: process.env.SESSION_SECRET!,
  issuer: 'https://app.example.com',   // validated on every verify, so a staging token fails here
});

export const GET = api
  .use(session.required())          // adds `principal` and `session`
  .handle(async (_request, { principal }) => Response.json(await me(principal.id)));
```

Drop `session.required()` and `{ principal }` stops compiling. That is the
point: the guard is not a convention you can forget, it is what makes the line
below it type-check.

### Secrets are read lazily

`process.env.SESSION_SECRET!` is read when `sessions()` is called. Keep that
call inside a module your build does not evaluate, or accept that a build
without secrets fails. Plugins validate the secret's strength on **first use**,
not at construction, precisely so a build-time import does not need production
secrets.

## Declare your vocabulary

Roles, permissions and the principal shape are yours, not the library's.
Declare them once and every plugin picks them up:

```ts
declare module '@wardenjs/ssr' {
  interface SecurityRegistry {
    role: 'user' | 'admin';
    permission: 'post:create' | 'post:delete';
    principal: { id: string; role: 'user' | 'admin'; tenantId: string };
  }
}
```

After this, `access.require('post:craete')` is a compile error everywhere at
once. Without the augmentation these widen to `string` and still work — you
lose the typo check, not the control.

It also tightens the plugins. A `principal` with a field beyond `id` and
`role` — `tenantId` above — cannot be reconstructed from the session token
alone, so `sessions()` now **requires** a `load` function and will not compile
without one:

```ts
const session = sessions({
  secret: process.env.SESSION_SECRET!,
  issuer: 'https://app.example.com',
  load: async ({ userId, role }) => ({ id: userId, role, tenantId: await tenantOf(userId) }),
});
```

## A first store

The browser track composes the same way, except a decorator's input and output
types are identical, so order is the only thing you choose.

```ts
import { decorate } from '@wardenjs/csr';
import { webStorage, namespaced, expiring, encrypted, persistentKeyring, jsonStore }
  from '@wardenjs/csr-storage';

const keyring = persistentKeyring({ namespace: 'app' });

const store = decorate(
  webStorage('local'),
  namespaced('app'),
  expiring({ ttlSeconds: 3600 }),
  encrypted({ keyring }),
);

// The schema maps KEY to the type stored under it.
const prefs = jsonStore<{ theme: 'light' | 'dark'; sidebar: boolean }>(store);
await prefs.set('theme', 'dark');
```

Read the nesting as "what is inside `encrypted` is what gets encrypted".
`expiring` sits outside it, so the deadline is part of the ciphertext and a
user cannot edit it in devtools to revive an expired value.

## Turn on the lint rules

The runtime controls are opt-in per route. The lint rules are what stop the
next person from going around them.

```bash
npm i -D @wardenjs/csr-eslint-plugin
```

```js
// eslint.config.mjs
import warden from '@wardenjs/csr-eslint-plugin';

export default warden.enforce(
  { ...warden.configs.recommended, files: ['src/**/*.{ts,tsx}'] },
);
```

On an existing codebase, start with `warden.configs.migrating` — it allows
web-storage **reads** so you can move writes first, which is the order that
matters: an unencrypted read of an encrypted value returns null, while an
unencrypted write leaves plaintext on disk.

If volume is the problem, narrow `files` to the directories you have cleaned
rather than lowering severity. `enforce()` refuses a config that downgrades a
`required` rule, and tells you to use `waive()` with a reason instead.

## Where to go next

- [ssr.md](ssr.md) — the full contract, the recommended decorator order, and
  what each of the ten server plugins adds to the context.
- [csr.md](csr.md) — the browser contract, and what the browser cannot do.
- Each package's README explains why its control exists and where it stops.
