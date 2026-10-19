import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/**
 * scrypt, because it ships with Node: no native module, no install script, no
 * platform matrix. argon2id is marginally stronger and costs a postinstall
 * native dependency, the riskiest supply-chain shape there is. The format is
 * versioned, so parameters can be raised (or the algorithm swapped) later and
 * hashes upgraded on login with `needsRehash`.
 *
 * Format: `scrypt$N$r$p$<salt b64>$<hash b64>`.
 */
export interface PasswordHasherOptions {
  /** OWASP: N=2^16, r=8, p=1 (~64 MB per hash). Rate-limit login, or this is the DoS. */
  N?: number;
  r?: number;
  p?: number;
  /** Default 128 characters; hashing cost grows with input. */
  maxLength?: number;
}

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /** False, never a throw, for a malformed stored hash: a different status is an oracle. */
  verify(password: string, encoded: string): Promise<boolean>;
  /** After a successful verify: true when the stored hash uses weaker parameters. */
  needsRehash(encoded: string): boolean;
  /**
   * Use when the account does not exist (`encoded` null): hashes against a
   * dummy so "no such user" costs the same time as "wrong password".
   */
  verifyOrEqualise(password: string, encoded: string | null | undefined): Promise<boolean>;
}

const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

export function passwordHasher(options: PasswordHasherOptions = {}): PasswordHasher {
  const N = options.N ?? 65_536;
  const r = options.r ?? 8;
  const p = options.p ?? 1;
  const maxLength = options.maxLength ?? 128;
  if (!inBounds(N, r, p)) throw new Error('passwordHasher: parameters out of bounds.');

  const derive = (password: string, salt: Buffer, length: number, cost: { N: number; r: number; p: number }) =>
    new Promise<Buffer>((resolve, reject) =>
      // NFC on both sides, or a password set on macOS fails to verify from Windows.
      scrypt(password.normalize('NFC'), salt, length, { ...cost, maxmem: 256 * cost.N * cost.r }, (error, key) =>
        error ? reject(error) : resolve(key),
      ),
    );

  async function hash(password: string): Promise<string> {
    if (password.length > maxLength) throw new RangeError(`Password longer than ${maxLength} characters.`);
    const salt = randomBytes(SALT_LENGTH);
    const key = await derive(password, salt, KEY_LENGTH, { N, r, p });
    return ['scrypt', N, r, p, salt.toString('base64'), key.toString('base64')].join('$');
  }

  async function verify(password: string, encoded: string): Promise<boolean> {
    const parsed = parse(encoded);
    if (!parsed || password.length > maxLength) return false;
    try {
      const key = await derive(password, parsed.salt, parsed.hash.length, parsed);
      return key.length === parsed.hash.length && timingSafeEqual(key, parsed.hash);
    } catch {
      return false;
    }
  }

  let dummy: Promise<string> | undefined;

  return {
    hash,
    verify,
    needsRehash(encoded) {
      const parsed = parse(encoded);
      return !parsed || parsed.N < N || parsed.r < r || parsed.p < p;
    },
    async verifyOrEqualise(password, encoded) {
      if (encoded) return verify(password, encoded);
      dummy ??= hash('timing-equalisation-placeholder');
      await verify(password, await dummy);
      return false;
    },
  };
}

/**
 * Stored parameters are bounded before they reach the KDF: someone who can
 * write the users table could otherwise make verification free (`N=1`) or
 * exhaust memory with one login (`N=2^30`).
 */
const inBounds = (N: number, r: number, p: number) =>
  Number.isInteger(N) && Number.isInteger(r) && Number.isInteger(p) &&
  N >= 16_384 && N <= 1 << 21 && (N & (N - 1)) === 0 && r >= 1 && r <= 32 && p >= 1 && p <= 16;

function parse(encoded: string) {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const [N, r, p] = [Number(parts[1]), Number(parts[2]), Number(parts[3])];
  if (!inBounds(N, r, p)) return null;
  const salt = Buffer.from(parts[4] ?? '', 'base64');
  const hash = Buffer.from(parts[5] ?? '', 'base64');
  if (salt.length < SALT_LENGTH || hash.length < 32) return null;
  return { N, r, p, salt, hash };
}
