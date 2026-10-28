import { afterEach, describe, expect, it, vi } from 'vitest';
import { decorate, type SecurityEvent } from '@wardenjs/csr';
import {
  clearStore,
  encrypted,
  expiring,
  jsonStore,
  KeyringError,
  memoryKeyring,
  memoryStore,
  namespaced,
  passphraseKeyring,
  persistentKeyring,
  rawKeyring,
  webStorage,
} from '../src/index.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('base stores', () => {
  it('webStorage reads and writes the real storage', async () => {
    const store = webStorage('local');
    await store.set('a', '1');
    expect(localStorage.getItem('a')).toBe('1');
    expect(await store.keys()).toEqual(['a']);
  });

  it('falls back to memory, and says so, where Web Storage throws (sandboxed iframes, disabled site data)', async () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    const events: SecurityEvent[] = [];
    const store = webStorage('local', { onEvent: (e) => events.push(e) });
    await store.set('a', '1');
    expect(await store.get('a')).toBe('1');
    expect(events).toEqual([{ type: 'storage.unavailable', reason: 'local' }]);
  });
});

describe('namespaced', () => {
  it('isolates features, and clearStore on a namespace wipes only that namespace', async () => {
    const raw = memoryStore();
    const a = decorate(raw, namespaced('a'));
    const b = decorate(raw, namespaced('b'));
    await a.set('k', '1');
    await b.set('k', '2');
    await clearStore(a);
    expect(await a.get('k')).toBeNull();
    expect(await b.get('k')).toBe('2');
  });
});

describe('encrypted', () => {
  const setup = (keyring = memoryKeyring()) => {
    const raw = memoryStore();
    const events: SecurityEvent[] = [];
    const store = decorate(raw, encrypted({ keyring, onEvent: (e) => events.push(e) }));
    return { raw, store, events };
  };

  it('keeps only ciphertext in the underlying store', async () => {
    const { raw, store } = setup();
    await store.set('token', 'super-secret');
    expect(await raw.get('token')).toMatch(/^enc\./);
    expect(await raw.get('token')).not.toContain('super-secret');
    expect(await store.get('token')).toBe('super-secret');
  });

  it('fails closed on a planted plaintext value: removed, reported, never returned', async () => {
    const { raw, store, events } = setup();
    await raw.set('role', 'admin');
    expect(await store.get('role')).toBeNull();
    expect(await raw.get('role')).toBeNull();
    expect(events).toEqual([{ type: 'storage.unreadable', reason: 'plaintext' }]);
  });

  it('binds each value to its key: ciphertext copied to another key does not decrypt', async () => {
    const { raw, store } = setup();
    await store.set('theme', 'dark');
    await raw.set('role', (await raw.get('theme')) ?? '');
    expect(await store.get('role')).toBeNull();
  });

  it('cannot read values written under a key it does not hold', async () => {
    const first = setup();
    await first.store.set('a', '1');
    const other = decorate(first.raw, encrypted({ keyring: memoryKeyring() }));
    expect(await other.get('a')).toBeNull();
  });

  it('works with a passphrase key and a raw key', async () => {
    for (const keyring of [passphraseKeyring('pass phrase', { salt: 'user-1', iterations: 1000 }), rawKeyring(new Uint8Array(32).fill(7))]) {
      const { store } = setup(keyring);
      await store.set('a', 'value');
      expect(await store.get('a')).toBe('value');
    }
  });

  it('handles values larger than the call-stack argument limit', async () => {
    const { store } = setup();
    const big = 'x'.repeat(300_000);
    await store.set('state', big);
    expect(await store.get('state')).toBe(big);
  });
});

describe('expiring', () => {
  it('drops values past their TTL; outside encrypted(), the deadline cannot be edited', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const raw = memoryStore();
    const store = decorate(raw, expiring({ ttlSeconds: 60 }), encrypted({ keyring: memoryKeyring() }));
    await store.set('otp', '123456');
    expect(await store.get('otp')).toBe('123456');
    expect(await raw.get('otp')).toMatch(/^enc\./);
    vi.advanceTimersByTime(61_000);
    expect(await store.get('otp')).toBeNull();
  });
});

describe('jsonStore', () => {
  it('stores typed values', async () => {
    const store = jsonStore<{ prefs: { theme: string } }>(memoryStore());
    await store.set('prefs', { theme: 'dark' });
    expect(await store.get('prefs')).toEqual({ theme: 'dark' });
  });
});

describe('persistentKeyring', () => {
  it('reports clearly where IndexedDB is unavailable instead of silently storing plaintext', async () => {
    await expect(persistentKeyring().current()).rejects.toBeInstanceOf(KeyringError);
  });
});
