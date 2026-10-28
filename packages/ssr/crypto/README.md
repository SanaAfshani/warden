# @wardenjs/ssr-crypto

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Field encryption, purpose-bound signatures, and webhook verification. Web
Crypto only, so it runs on Edge too.

```bash
npm i @wardenjs/ssr @wardenjs/ssr-crypto
```

```ts
import { cipher, signer, webhook } from '@wardenjs/ssr-crypto';

const fields = cipher({ key: process.env.FIELD_KEY!, version: 'v2', previous: { v1: process.env.FIELD_KEY_V1! } });
const stored = await fields.encrypt(totpSecret, `totp:${userId}`);
const plain = await fields.decrypt(stored, `totp:${userId}`);

const links = signer({ key: process.env.SIGNING_KEY! });
const url = await links.signUrl('/download', { file: id }, 300);

export const POST = chain()
  .use(webhook({ secret: process.env.GITHUB_WEBHOOK_SECRET!, signatureHeader: 'x-hub-signature-256' }))
  .handle(async (_r, { rawBody }) => handle(JSON.parse(rawBody)));
```

- `cipher`: AES-256-GCM, random IV, context bound as AAD (a ciphertext copied
  to another row fails), key rotation with `needsReencryption`.
- `signer`: HMAC per purpose (an unsubscribe signature never verifies as a
  password reset), signed expiring URLs, `blindIndex` for lookups on
  encrypted columns.
- `webhook`: HMAC-SHA256 over the raw bytes with the provider's secret as
  given; hex or base64, `sha256=` prefix, optional timestamp with a replay
  window (`timestampHeader`).
