import { describe, expect, it, vi } from 'vitest';
import { chain } from '@sanaafshani/warden-ssr';
import { authenticate, checkPasswordAgainstBreaches, checkPasswordStrength, lockout, type CounterStore } from '../src/index.js';
import { passwordHasher } from '../src/node.js';

function memoryStore(): CounterStore {
  const map = new Map<string, number>();
  return {
    increment: async (key, amount) => {
      map.set(key, (map.get(key) ?? 0) + amount);
      return map.get(key) ?? 0;
    },
    get: async (key) => map.get(key) ?? 0,
    reset: async (key) => void map.delete(key),
  };
}

describe('authenticate', () => {
  it('rejects anonymous callers with 401 before the handler runs', async () => {
    const handler = vi.fn(() => new Response());
    const response = await chain().use(authenticate(() => null).required()).handle(handler)(new Request('https://a.test'));
    expect(response.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('checkPasswordStrength', () => {
  it('rejects common passwords through leetspeak, and passwords built from the user’s own details', () => {
    expect(checkPasswordStrength('P@ssw0rd123456').ok).toBe(false);
    expect(checkPasswordStrength('maryjones-2024!', { userInputs: ['mary.jones@example.com'] }).ok).toBe(false);
    expect(checkPasswordStrength('correct horse battery staple').ok).toBe(true);
  });

  it('caps length, because hashing cost grows with input', () => {
    expect(checkPasswordStrength('x'.repeat(200)).ok).toBe(false);
  });
});

describe('checkPasswordAgainstBreaches', () => {
  it('sends only a 5-character hash prefix (k-anonymity)', async () => {
    const fetchImpl = vi.fn(async (_url: string) => new Response('0000000000000000000000000000000000A:3'));
    const result = await checkPasswordAgainstBreaches('hunter2-but-longer', fetchImpl);
    expect(fetchImpl.mock.calls[0]?.[0]).toMatch(/\/range\/[0-9A-F]{5}$/);
    expect(result).toEqual({ breached: false, count: 0, checked: true });
  });

  it('fails open when the service is down, so an outage does not stop signups', async () => {
    const result = await checkPasswordAgainstBreaches('hunter2-but-longer', async () => new Response(null, { status: 503 }));
    expect(result.checked).toBe(false);
  });
});

describe('lockout', () => {
  it('delays after the soft threshold and locks at the hard one, for a bounded time', async () => {
    const l = lockout({ store: memoryStore(), softThreshold: 2, hardThreshold: 5, lockSeconds: 60 });
    let state = await l.check('a@example.com');
    for (let i = 0; i < 3; i++) state = await l.recordFailure('a@example.com');
    expect(state.delayMs).toBeGreaterThan(0);
    expect(state.locked).toBe(false);
    for (let i = 0; i < 10; i++) state = await l.recordFailure('a@example.com');
    expect(state.locked).toBe(true);
    // Repeated failures during a lock must not stretch it without bound.
    expect(state.lockedForSeconds).toBeLessThanOrEqual(60);
  });

  it('clears the account on success', async () => {
    const l = lockout({ store: memoryStore(), softThreshold: 1 });
    await l.recordFailure('b');
    await l.recordFailure('b');
    await l.recordSuccess('b');
    expect((await l.check('b')).attempts).toBe(0);
  });
});

describe('passwordHasher', () => {
  const hasher = passwordHasher({ N: 16_384 });

  it('verifies, and normalises Unicode so a password typed on another OS still matches', async () => {
    const stored = await hasher.hash('caf\u00e9-long-password');
    expect(await hasher.verify('cafe\u0301-long-password', stored)).toBe(true);
    expect(await hasher.verify('wrong-long-password', stored)).toBe(false);
  });

  it('refuses stored parameters that would make verification free or exhaust memory', async () => {
    const stored = await hasher.hash('a-long-password');
    const weakened = stored.replace(/^scrypt\$16384\$/, 'scrypt$2$');
    expect(await hasher.verify('a-long-password', weakened)).toBe(false);
    expect(await hasher.verify('a-long-password', 'not-a-hash')).toBe(false);
  });

  it('flags hashes made with weaker parameters for upgrade on login', async () => {
    const stronger = passwordHasher({ N: 32_768 });
    expect(stronger.needsRehash(await hasher.hash('a-long-password'))).toBe(true);
  });

  it('spends a hash on unknown accounts, so timing does not reveal which emails exist', async () => {
    expect(await hasher.verifyOrEqualise('anything-long', null)).toBe(false);
  });
});
