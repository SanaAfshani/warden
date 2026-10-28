# @wardenjs/ssr-access

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Role-based access control and ownership checks.

```bash
npm i @wardenjs/ssr @wardenjs/ssr-access
```

```ts
import { accessControl } from '@wardenjs/ssr-access';

export const access = accessControl({
  roles: ['user', 'moderator', 'admin'], // least to most privileged
  grants: {
    user: ['post:create', 'post:update:own'],
    moderator: ['post:create', 'post:update:own', 'post:update:any'],
    admin: ['post:create', 'post:update:any', 'user:assign-role'],
  },
});

export const POST = chain().use(session.required()).use(access.require('post:create')).handle(create);

// Ownership, inside the handler, with ownerId from the stored record:
access.assertAccess(principal, post.authorId, 'post:update:own', 'post:update:any'); // 404 when denied
```

- Deny by default; anonymous callers get nothing unless `anonymous` names a role.
- The table is validated at construction: a typo in a role name throws.
- `assertAccess` answers 404, not 403, so ids cannot be enumerated.
- `canAssignRole` allows only roles below the actor's, never to themselves.
- `filter` applies the same rules to lists you cannot scope in the query.
