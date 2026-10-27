# @sanaafshani/warden-ssr-authn

> Part of [warden](https://github.com/SanaAfshani/warden)'s **server track**: security controls as decorators for any
> Fetch-API handler (Next.js route handlers, Hono, Bun, Deno, Workers). Here *SSR* means
> *server side*, not server-side rendering.

Who is calling: signed sessions, a generic authentication decorator,
password policy, lockout, and scrypt hashing.

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-authn jose
```

```ts
import { authenticate, lockout, sessions } from '@sanaafshani/warden-ssr-authn';
import { passwordHasher } from '@sanaafshani/warden-ssr-authn/node';

// Your own sessions (JWT in a __Host- cookie):
const session = sessions({ secret: process.env.SESSION_SECRET!, issuer: 'https://app.example.com' });
export const GET = chain().use(session.required()).handle(async (_r, { principal }) => Response.json(principal));

// Or wrap the provider you already have (Auth.js, Clerk, API keys):
const auth = authenticate(async (request) => toPrincipal(await getProviderSession(request)));
```

## Sessions

- Idle timeout (default 30 min) slides on activity; the absolute deadline
  (default 12 h) never moves. Renewal happens past half the idle window.
- Algorithm pinned, issuer and audience checked, `alg: none` impossible.
- An invalid cookie gets 401 and is cleared. A handler that sets the cookie
  itself (login, logout) has the last word.
- `rotate()` on every privilege change, against session fixation.
- Revocation: put a `version` in the session and compare it in `load`;
  bumping it signs out every device.

## Credentials

- `checkPasswordStrength`: NIST 800-63B: length, common and leet variants,
  sequences, the user's own name and email.
- `checkPasswordAgainstBreaches(password, fetch)`: HIBP k-anonymity (5 hash
  characters leave), fails open.
- `lockout({ store })`: delays after a soft threshold, a bounded lock at a hard
  one. Pair with an IP rate limit; per-account alone misses credential stuffing.
- `/node` `passwordHasher()`: scrypt, versioned format, bounded parameters,
  `needsRehash`, and `verifyOrEqualise` so unknown accounts take as long as
  wrong passwords.
