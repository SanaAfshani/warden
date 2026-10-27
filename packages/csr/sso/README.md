# @sanaafshani/warden-csr-sso

> Part of [warden](https://github.com/SanaAfshani/warden)'s **browser track**: security controls for code that runs in the
> browser. Here *CSR* means *client side*, not client-side rendering. Nothing here is a trust
> boundary; the server track enforces.

The browser half of a backend-for-frontend (BFF) login: your server runs the
OIDC flow and keeps the tokens; the browser holds only an httpOnly cookie.
XSS can then act while the tab is open, but cannot take a token home.

```bash
npm i @sanaafshani/warden-csr @sanaafshani/warden-csr-sso
```

```ts
import { bffSession, currentReturnTo, idleTimeout } from '@sanaafshani/warden-csr-sso';

export const session = bffSession<User>({
  endpoints: { login: '/auth/login', logout: '/auth/logout', session: '/auth/session', refresh: '/auth/refresh' },
});

await session.load();
if (!session.current()?.authenticated) session.login(currentReturnTo(location));

const orders = await session.fetch('/api/orders'); // CSRF + one refresh-and-retry on 401

idleTimeout({ idleSeconds: 900, onTimeout: () => session.logout() }).start();
```

## Pieces

- `bffSession`: deduplicated session load and refresh, proactive refresh
  before `expiresAt`, logout fanned out to every tab first.
- Fetch decorators (`withCsrf`, `withSessionRefresh`) for your own composition.
  Both act only on your API's origins: third parties never receive the CSRF
  token, and their 401s never trigger a refresh.
- `safeReturnTo`: relative paths only; rejects `//host`, `/\host`, encoded and
  whitespace-smuggled variants.
- `idleTimeout`: idle and absolute clocks. Activity is shared across tabs, so
  a background tab does not sign out a user who is typing elsewhere.
- `sessionChannel`: cross-tab logout (BroadcastChannel, `storage` event fallback).

Idle timeout protects an unattended screen, not against code on the page; the
server's session lifetime is what actually binds.
