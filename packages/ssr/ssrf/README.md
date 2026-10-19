# @sanaafshani/warden-ssr-ssrf

Outbound HTTP to URLs that input can influence, without reaching your
internal network. **Node only** (needs `node:dns` and `node:https`).

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-ssrf
```

```ts
import { createSafeFetch } from '@sanaafshani/warden-ssr-ssrf';

const safeFetch = createSafeFetch({ allowedHosts: ['api.partner.com', '.cdn.partner.com'] });
const { status, body } = await safeFetch(userSuppliedUrl);
```

- https only, no credentials in the URL, ports 443 and 8443 by default.
- Hosts: exact names, or `.example.com` for its subdomains.
- Every resolved address is checked against private, loopback, link-local
  (cloud metadata), CGNAT and IPv4-mapped ranges, and the connection is
  pinned to the checked address, so DNS rebinding cannot redirect it.
- Redirects off by default. When enabled, each hop is re-validated,
  303 becomes GET, and Authorization and Cookie are dropped across hosts.
- Timeout, byte cap, identity encoding (no decompression bombs).
- Throws `SsrfBlockedError` (a 502 `HttpError` with a generic message).

Does not cover fetches made on your behalf by other software: image
optimisers, headless browsers, XML parsers.
