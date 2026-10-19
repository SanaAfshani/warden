/** CSPRNG bytes. Backed by a plain ArrayBuffer so they go straight to `crypto.subtle`. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(length) || length <= 0 || length > 65_536) {
    throw new RangeError('randomBytes: length must be an integer in 1..65536');
  }
  return crypto.getRandomValues(new Uint8Array(length));
}

/** URL-, cookie- and header-safe random string. 32 bytes = 256 bits. */
export function randomToken(bytes = 32): string {
  return toBase64Url(randomBytes(bytes));
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Throws on anything that is not base64url. */
export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError('Not base64url.');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Rejects secrets that are short or obviously not random (`changeme…`,
 * `aaaa…`). Generate with `openssl rand -base64 32`.
 */
export function assertStrongSecret(label: string, secret: unknown): asserts secret is string {
  if (typeof secret !== 'string' || new TextEncoder().encode(secret).length < 32) {
    throw new Error(`${label}: secret must be at least 32 bytes (openssl rand -base64 32).`);
  }
  if (new Set(secret).size < 12) {
    throw new Error(`${label}: secret is not random enough (openssl rand -base64 32).`);
  }
}

/**
 * Comparison whose running time does not depend on where the inputs differ.
 * Best effort under a JIT; for attacker-probed secrets compare HMACs instead.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}
