# @sanaafshani/warden-ssr-validate

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Bounded body reading and schema validation. Works with any
[Standard Schema](https://standardschema.dev) library (zod, valibot, arktype)
without depending on one.

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-validate
```

```ts
import { z } from 'zod';
import { body, params, query } from '@sanaafshani/warden-ssr-validate';

export const PATCH = chain()
  .use(params(z.object({ id: z.string().uuid() })))
  .use(body(z.object({ title: z.string().max(200) })))
  .handle(async (_r, { params, body }) => Response.json(await update(params.id, body)));
```

- `body`: `application/json` only (also blocks cross-site form posts), capped
  bytes (100 KB), depth (12) and key count (500), then the schema. Failures
  are 415, 413, 400 or 422 with field-level details; input is never echoed.
- `query`: repeated keys arrive as arrays, so parameter pollution meets the schema.
- `params`: route params are input too.
- `readForm`, `readText`, `readJson` for handlers that read bodies themselves.
