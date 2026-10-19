# @sanaafshani/warden-ssr-logging

Structured logging with redaction, and the request-level error boundary.

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-logging
```

```ts
import { createLogger, requestLogger } from '@sanaafshani/warden-ssr-logging';

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
