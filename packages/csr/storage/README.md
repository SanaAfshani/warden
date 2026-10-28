# @wardenjs/csr-storage

> Part of [warden](https://github.com/SanaAfshani/warden)'s **browser track**: security controls for code that runs in the
> browser. Here *CSR* means *client side*, not client-side rendering. Nothing here is a trust
> boundary; the server track enforces.

Browser storage built from decorators: namespaced, expiring, encrypted.

```bash
npm i @wardenjs/csr @wardenjs/csr-storage
```

```ts
import { decorate } from '@wardenjs/csr';
import { clearStore, encrypted, expiring, jsonStore, namespaced, persistentKeyring, webStorage } from '@wardenjs/csr-storage';

const keyring = persistentKeyring({ namespace: 'app' });
const store = decorate(
  webStorage('local'),
  namespaced('app'),
  expiring({ ttlSeconds: 7 * 86_400 }),
  encrypted({ keyring, onEvent: report }),
);
const prefs = jsonStore<{ draft: { title: string; body: string } }>(store);
await prefs.set('draft', { title, body });

// Logout:
await clearStore(store);
await keyring.destroy();
```

## Pieces

- **Base stores:** `webStorage('local' | 'session')` (falls back to memory
  where Web Storage is unavailable, reporting `storage.unavailable`) and
  `memoryStore()`.
- **Decorators:** `namespaced(ns)`, `expiring({ ttlSeconds })`, `encrypted({ keyring })`.
  Order matters: `expiring` outside `encrypted` puts the deadline inside the
  ciphertext.
- **Keyrings:** `persistentKeyring()` (non-extractable AES key in IndexedDB,
  rotated every 90 days, previous key kept), `memoryKeyring()` (per tab),
  `passphraseKeyring(pass, { salt })` (PBKDF2), `rawKeyring(bytes)` (tests).
- **Adapters:** `jsonStore<Schema>()` for typed values, `persistStorage()` for
  redux-persist and zustand.
- **React** (`/react`): `useStoredValue(jsonStore, key)`.

`encrypted` fails closed: plaintext or undecryptable values are removed and
read as `null`, reported as `storage.unreadable`.

## What it does not do

An XSS running in the page can call `get` like your code does. Encryption
stops storage-dumping scripts and plaintext at rest, not an attacker in the
tab. Session tokens belong in an httpOnly cookie set by the server.
