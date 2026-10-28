# @wardenjs/ssr-logging

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Structured logging with redaction, and the request-level error boundary.

```bash
npm i @wardenjs/ssr @wardenjs/ssr-logging
```

```ts
import { createLogger, requestLogger } from '@wardenjs/ssr-logging';

export const logger = createLogger({ fields: { service: 'api' } });

const api = chain().use(secureHeaders()).use(requestLogger(logger));
export const GET = api.handle(async (_r, { log }) => {
  log.info('listing posts');
  return Response.json(await list());
});

// Audit every plugin through one place:
const session = sessions({ secret, issuer, onEvent: logger.event });
```

- Redacts secrets by key at any depth (`password`, `userPassword`,
  `x-api-key`, `refresh_token`, …), bounded in depth, breadth and length,
  cycle-safe.
- Messages are single-line, so input cannot forge a log entry.
- `requestLogger` adds `log` and `requestId`, sets `X-Request-Id`, and turns
  unexpected errors into an opaque 500 that carries only the id.
- `event` logs the client IP truncated to /24 or /48.
- Default sink: one JSON line on stdout/stderr. Pass `sink` for anything else.
