# CSR track

`@wardenjs/csr` is the contract for browser plugins. Like the server
core it contains no control and needs no configuration.

## The contract

```ts
type Decorator<T> = (inner: T) => T;
function decorate<T>(base: T, ...decorators: Decorator<T>[]): T; // first listed is outermost

interface KeyValueStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  keys(): Promise<string[]>;
}

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
```

Because a decorator's input and output types are the same, decorators can be
stacked in any number and order, and a decorated store or fetch is a drop-in
replacement for the plain one.

## Storage

```ts
const keyring = persistentKeyring({ namespace: 'app' });
const store = decorate(
  webStorage('local'),            // or 'session', or memoryStore()
  namespaced('app'),              // outermost: key prefix
  expiring({ ttlSeconds: 3600 }), // deadline goes inside the ciphertext
  encrypted({ keyring, onEvent }),
);
const prefs = jsonStore<{ theme: 'light' | 'dark' }>(store);
```

What is inside `encrypted` is what gets encrypted. With `expiring` outside it,
the deadline is part of the ciphertext and cannot be edited. With `namespaced`
outside, key names are visible but scoped.

Encryption in the browser does not stop an XSS that runs while the tab is
open: it can call `get` as your code does. It stops scripts that dump storage
from getting plaintext, keeps plaintext off disk, and makes "is our storage
encrypted?" answerable. Session tokens belong in an httpOnly cookie, not here.

## Fetch

```ts
const api = decorate(fetch, withSessionRefresh({ refresh }), withCsrf({ token }));
```

`bffSession()` composes these for a backend-for-frontend login and exposes
the result as `session.fetch`.

## Plugins

| Package | Gives you | React (`/react`) |
| --- | --- | --- |
| `-storage` | base stores, `namespaced`, `expiring`, `encrypted`, keyrings, `jsonStore`, `persistStorage` | `useStoredValue` |
| `-sanitize` | `sanitizeHtml` (DOMPurify), Trusted Types, `escapeHtml`, `safeUrl`, `safeCsvCell` | `<SafeHtml>` |
| `-access` | `permissionSet(granted)` | `<PermissionsProvider>`, `<Can>`, `useCan` |
| `-sso` | `bffSession`, `withCsrf`, `withSessionRefresh`, `safeReturnTo`, `idleTimeout`, `sessionChannel` | |
| `-eslint-plugin` (dev) | five rules that ban the sinks the plugins above replace; `enforce`, `waive` | |

React is an optional peer, used only by the `/react` subpaths: a non-React app
never loads it.

The lint rules are the half a runtime library cannot provide: they stop the
next `innerHTML` or `localStorage.setItem` from going around these plugins.
They are a dev dependency with no runtime dependency on the other packages.
See [its README](../packages/csr/eslint-plugin/README.md) for the rules and tiers.

## What the browser cannot do

Everything in this track runs on a machine the user controls. `access` decides
what the UI shows, never what is allowed; every permission must be checked
again by the server. Sanitising and encryption reduce what an attacker gets;
they do not make the browser a trust boundary.

## Writing a plugin

1. A package under `packages/csr/<name>`. Peer-depend on
   `@wardenjs/csr` only if you use its types.
2. Export `Decorator<KeyValueStore>`, `Decorator<Fetcher>` or plain functions.
   No module-level configuration; take options.
3. Fail closed: a value that cannot be verified is absent, never returned.
4. Report through `emit(options.onEvent, …)`.
5. Framework bindings go in a `/react` subpath with the framework as an
   optional peer.
6. Guard every browser API (`typeof indexedDB === 'undefined'`, try/catch
   around Web Storage), so server rendering and locked-down browsers degrade
   instead of crashing.
