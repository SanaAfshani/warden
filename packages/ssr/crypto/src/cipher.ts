import { assertStrongSecret, fromBase64Url, randomBytes, toBase64Url } from '@sanaafshani/warden-ssr';

export interface CipherOptions {
  /** At least 32 random bytes. */
  key: string;
  /** Written into every envelope. Default `v1`. */
  version?: string;
  /** Retired keys, still accepted for decryption: `{ v1: '…' }`. */
  previous?: Readonly<Record<string, string>>;
}

export interface Cipher {
  /**
   * `context` is authenticated but not encrypted. Bind it to where the value
   * lives (`totp:${userId}`), or a blob copied into another row decrypts there.
   */
  encrypt(plaintext: string, context: string): Promise<string>;
  /** Throws `DecryptionError` for every failure alike; distinguishing them rebuilds an oracle. */
  decrypt(envelope: string, context: string): Promise<string>;
  /** Written under a retired key: re-encrypt in a background job. */
  needsReencryption(envelope: string): boolean;
}

export class DecryptionError extends Error {
  constructor() {
    super('Decryption failed.');
    this.name = 'DecryptionError';
  }
}

/**
 * AES-256-GCM (authenticated: a flipped bit fails instead of returning
 * garbage). The 96-bit IV is random per message and cannot be supplied, since
 * one reused (key, IV) pair breaks the key. Envelope: `enc.<version>.<iv>.<ct>`.
 * For high-value data prefer a KMS data key; the envelope shape allows it.
 */
export function cipher(options: CipherOptions): Cipher {
  const current = options.version ?? 'v1';
  const secrets = new Map<string, string>([...Object.entries(options.previous ?? {}), [current, options.key]]);
  const keys = new Map<string, Promise<CryptoKey>>();

  const keyFor = (version: string) => {
    let key = keys.get(version);
    if (!key) {
      const secret = secrets.get(version);
      if (secret === undefined) throw new DecryptionError();
      assertStrongSecret(`cipher ${version}`, secret);
      key = crypto.subtle
        .digest('SHA-256', new TextEncoder().encode(`${version}:aes-256-gcm:${secret}`))
        .then((digest) => crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']));
      keys.set(version, key);
    }
    return key;
  };

  return {
    async encrypt(plaintext, context) {
      const iv = randomBytes(12);
      const data = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context), tagLength: 128 },
        await keyFor(current),
        new TextEncoder().encode(plaintext),
      );
      return ['enc', current, toBase64Url(iv), toBase64Url(new Uint8Array(data))].join('.');
    },
    async decrypt(envelope, context) {
      const [prefix, version, iv, data, ...rest] = envelope.split('.');
      if (prefix !== 'enc' || !version || !iv || !data || rest.length > 0) throw new DecryptionError();
      try {
        const ivBytes = fromBase64Url(iv);
        if (ivBytes.length !== 12) throw new DecryptionError();
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ivBytes, additionalData: new TextEncoder().encode(context), tagLength: 128 },
          await keyFor(version),
          fromBase64Url(data),
        );
        return new TextDecoder().decode(plain);
      } catch {
        throw new DecryptionError();
      }
    },
    needsReencryption(envelope) {
      const [prefix, version] = envelope.split('.');
      return prefix !== 'enc' || version !== current;
    },
  };
}
