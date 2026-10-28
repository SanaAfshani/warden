import { assertStrongSecret, fromBase64Url, toBase64Url } from '@wardenjs/ssr';

export interface Signer {
  /**
   * HMAC-SHA256 under a key derived per `purpose`, so a signature made for
   * one subsystem never verifies in another.
   */
  sign(purpose: string, message: string): Promise<string>;
  /** Constant time (Web Crypto `verify`). */
  verify(purpose: string, message: string, signature: string): Promise<boolean>;
  /** Expiry is inside the signed string, so it cannot be edited. Parameters are sorted (canonical). */
  signUrl(pathname: string, params: Record<string, string>, ttlSeconds: number): Promise<string>;
  verifyUrl(url: URL | string): Promise<boolean>;
  /**
   * Keyed digest for equality lookups on encrypted columns. A bare hash of
   * an email is reversed by hashing a list of emails. Leaks equality by design.
   */
  blindIndex(value: string): Promise<string>;
}

export function signer(options: { key: string }): Signer {
  const keys = new Map<string, Promise<CryptoKey>>();
  const keyFor = (purpose: string) => {
    let key = keys.get(purpose);
    if (!key) {
      assertStrongSecret('signer', options.key);
      key = crypto.subtle
        .digest('SHA-256', new TextEncoder().encode(`hmac-sha256:${purpose}:${options.key}`))
        .then((digest) =>
          crypto.subtle.importKey('raw', digest, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']),
        );
      keys.set(purpose, key);
    }
    return key;
  };

  const sign: Signer['sign'] = async (purpose, message) =>
    toBase64Url(
      new Uint8Array(await crypto.subtle.sign('HMAC', await keyFor(purpose), new TextEncoder().encode(message))),
    );

  const verify: Signer['verify'] = async (purpose, message, signature) => {
    try {
      return await crypto.subtle.verify(
        'HMAC',
        await keyFor(purpose),
        fromBase64Url(signature),
        new TextEncoder().encode(message),
      );
    } catch {
      return false;
    }
  };

  return {
    sign,
    verify,
    async signUrl(pathname, params, ttlSeconds) {
      const search = new URLSearchParams({ ...params, expires: String(Math.floor(Date.now() / 1000) + ttlSeconds) });
      search.delete('sig');
      search.sort();
      search.set('sig', await sign('signed-url', `${pathname}?${search.toString()}`));
      return `${pathname}?${search.toString()}`;
    },
    async verifyUrl(url) {
      const parsed = new URL(url, 'http://placeholder.invalid');
      const search = new URLSearchParams(parsed.searchParams);
      const signature = search.get('sig');
      const expires = Number(search.get('expires'));
      if (!signature || !Number.isFinite(expires) || Math.floor(Date.now() / 1000) > expires) return false;
      search.delete('sig');
      search.sort();
      return verify('signed-url', `${parsed.pathname}?${search.toString()}`, signature);
    },
    blindIndex: (value) => sign('blind-index', value.trim().toLowerCase().normalize('NFC')),
  };
}
