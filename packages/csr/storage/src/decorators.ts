import { emit, type Decorator, type KeyValueStore, type SecurityEventHandler } from '@wardenjs/csr';
import { decryptString, encryptString } from './aes.js';
import type { Keyring } from './keyring.js';

/**
 * Prefixes every key, so two features (or two apps on one origin) cannot
 * collide, and `clearStore` on it wipes only its own keys.
 */
export function namespaced(namespace: string): Decorator<KeyValueStore> {
  const prefix = `${namespace}:`;
  return (inner) => ({
    get: (key) => inner.get(prefix + key),
    set: (key, value) => inner.set(prefix + key, value),
    remove: (key) => inner.remove(prefix + key),
    keys: async () => (await inner.keys()).filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length)),
  });
}

/**
 * Expiry enforced on read, not by a timer (timers do not survive a reload).
 * Place it outside `encrypted` so the deadline is inside the ciphertext and
 * cannot be edited.
 */
export function expiring(options: { ttlSeconds: number; onEvent?: SecurityEventHandler }): Decorator<KeyValueStore> {
  return (inner) => ({
    async get(key) {
      const raw = await inner.get(key);
      if (raw === null) return null;
      let envelope: { e?: unknown; d?: unknown };
      try {
        envelope = JSON.parse(raw) as typeof envelope;
      } catch {
        envelope = {};
      }
      const expired = typeof envelope.e === 'number' && Date.now() > envelope.e;
      if (typeof envelope.e !== 'number' || typeof envelope.d !== 'string' || expired) {
        await inner.remove(key);
        emit(options.onEvent, { type: 'storage.unreadable', reason: expired ? 'expired' : 'malformed' });
        return null;
      }
      return envelope.d;
    },
    set: (key, value) => inner.set(key, JSON.stringify({ e: Date.now() + options.ttlSeconds * 1000, d: value })),
    remove: (key) => inner.remove(key),
    keys: () => inner.keys(),
  });
}

/**
 * AES-GCM per value, bound to the key it is stored under. Fails closed: a
 * value that is plaintext (someone wrote around the encryption) or does not
 * decrypt (wrong key, rotated away, moved from another slot) is removed and
 * reported as absent, never returned. Report via `onEvent` so key loss is
 * visible rather than looking like random logouts.
 */
export function encrypted(options: { keyring: Keyring; onEvent?: SecurityEventHandler }): Decorator<KeyValueStore> {
  const context = (key: string) => `storage:${key}`;
  return (inner) => ({
    async get(key) {
      const raw = await inner.get(key);
      if (raw === null) return null;
      try {
        return await decryptString(options.keyring, raw, context(key));
      } catch {
        await inner.remove(key);
        emit(options.onEvent, {
          type: 'storage.unreadable',
          reason: raw.startsWith('enc.') ? 'undecryptable' : 'plaintext',
        });
        return null;
      }
    },
    set: async (key, value) => inner.set(key, await encryptString(options.keyring, value, context(key))),
    remove: (key) => inner.remove(key),
    keys: () => inner.keys(),
  });
}
