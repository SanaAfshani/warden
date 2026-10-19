import type { Keyring } from './keyring.js';

export class DecryptionError extends Error {
  constructor() {
    super('Decryption failed.');
    this.name = 'DecryptionError';
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new DecryptionError();
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * AES-256-GCM with a random 96-bit IV per value (there is no way to pass one:
 * a reused key+IV pair breaks the key). `context` is authenticated, not
 * encrypted: bind it to where the value lives, so a blob moved to another
 * slot fails instead of decrypting. Envelope: `enc.<keyVersion>.<iv>.<ct>`.
 */
export async function encryptString(keyring: Keyring, plaintext: string, context: string): Promise<string> {
  const { version, key } = await keyring.current();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(context), tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext),
  );
  return ['enc', version, toBase64Url(iv), toBase64Url(new Uint8Array(data))].join('.');
}

/** One error for every failure: telling them apart rebuilds an oracle. */
export async function decryptString(keyring: Keyring, envelope: string, context: string): Promise<string> {
  const [prefix, version, iv, data, ...rest] = envelope.split('.');
  if (prefix !== 'enc' || !version || !iv || !data || rest.length > 0) throw new DecryptionError();
  const handle = await keyring.byVersion(version);
  if (!handle) throw new DecryptionError();
  try {
    const ivBytes = fromBase64Url(iv);
    if (ivBytes.length !== 12) throw new DecryptionError();
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, additionalData: new TextEncoder().encode(context), tagLength: 128 },
      handle.key,
      fromBase64Url(data),
    );
    return new TextDecoder().decode(plain);
  } catch {
    throw new DecryptionError();
  }
}
