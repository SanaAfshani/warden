import {
  assertStrongSecret,
  defineDecorator,
  emit,
  fromBase64Url,
  HttpError,
  randomToken,
  readCookie,
  serializeCookie,
  timingSafeEqual,
  toBase64Url,
  type Decorator,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

export interface CsrfOptions {
  /** At least 32 random bytes, distinct from the session secret. Checked on first use. */
  secret: string;
  /** Exact origin(s) of the app, e.g. `https://app.example.com`. No patterns. */
  origin: string | readonly string[];
  /**
   * Default `__Host-csrf`, Secure, SameSite=Lax, 12 h. Not HttpOnly by design:
   * the client must read it to echo it in the header. It is not a credential.
   */
  cookie?: { name?: string; secure?: boolean; sameSite?: 'strict' | 'lax' | 'none'; maxAge?: number };
  /** Default `x-csrf-token`. */
  header?: string;
  onEvent?: SecurityEventHandler;
}

export type CsrfVerdict =
  | { ok: true }
  | {
      ok: false;
      reason:
        | 'cross-site'
        | 'origin-mismatch'
        | 'origin-missing'
        | 'token-missing'
        | 'token-mismatch'
        | 'token-invalid';
    };

export interface Csrf {
  /** A fresh token and its `Set-Cookie` value. Issue at sign-in, rotate with the session. */
  issue(): Promise<{ token: string; cookie: string }>;
  verify(request: Request): Promise<CsrfVerdict>;
  /** 403 for unsafe methods that fail `verify`. Not for Bearer-token APIs or webhooks: nothing to forge there. */
  protect(): Decorator;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Three layers, because each alone has a gap:
 *  1. SameSite cookies (set by your session): not enforced by old clients,
 *     and a sibling subdomain is "same-site".
 *  2. `Sec-Fetch-Site` / `Origin` / `Referer`, compared exactly: some
 *     legitimate requests carry none of them.
 *  3. Signed double-submit token: the HMAC defeats cookie tossing, where a
 *     subdomain plants a value it chose in both cookie and header.
 */
export function csrf(options: CsrfOptions): Csrf {
  const origins = new Set(typeof options.origin === 'string' ? [options.origin] : options.origin);
  const cookieName = options.cookie?.name ?? '__Host-csrf';
  const header = options.header ?? 'x-csrf-token';

  let key: Promise<CryptoKey> | undefined;
  const hmacKey = () => {
    if (!key) {
      assertStrongSecret('csrf', options.secret);
      key = crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(options.secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify'],
      );
    }
    return key;
  };
  const message = (raw: string) => new TextEncoder().encode(`csrf:${raw}`);

  function checkOrigin(request: Request): CsrfVerdict {
    // Computed by the browser and unforgeable from a page.
    if (request.headers.get('sec-fetch-site') === 'cross-site') return { ok: false, reason: 'cross-site' };
    const origin = request.headers.get('origin');
    if (origin) return origins.has(origin) ? { ok: true } : { ok: false, reason: 'origin-mismatch' };
    const referer = request.headers.get('referer');
    if (referer) {
      try {
        return origins.has(new URL(referer).origin) ? { ok: true } : { ok: false, reason: 'origin-mismatch' };
      } catch {
        return { ok: false, reason: 'origin-mismatch' };
      }
    }
    return { ok: false, reason: 'origin-missing' };
  }

  async function checkToken(cookie: string | undefined, submitted: string | null): Promise<CsrfVerdict> {
    if (!cookie || !submitted) return { ok: false, reason: 'token-missing' };
    if (!timingSafeEqual(cookie, submitted)) return { ok: false, reason: 'token-mismatch' };
    const dot = cookie.indexOf('.');
    if (dot <= 0) return { ok: false, reason: 'token-invalid' };
    try {
      const signature = fromBase64Url(cookie.slice(dot + 1));
      const valid = await crypto.subtle.verify('HMAC', await hmacKey(), signature, message(cookie.slice(0, dot)));
      return valid ? { ok: true } : { ok: false, reason: 'token-invalid' };
    } catch {
      return { ok: false, reason: 'token-invalid' };
    }
  }

  const verify: Csrf['verify'] = async (request) => {
    if (SAFE_METHODS.has(request.method.toUpperCase())) return { ok: true };
    const origin = checkOrigin(request);
    // A definite cross-origin signal is final; a missing one falls through to the token.
    if (!origin.ok && origin.reason !== 'origin-missing') return origin;
    return checkToken(readCookie(request, cookieName), request.headers.get(header));
  };

  return {
    async issue() {
      const raw = randomToken(32);
      const signature = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(), message(raw)));
      const token = `${raw}.${toBase64Url(signature)}`;
      const cookie = serializeCookie({
        name: cookieName,
        value: token,
        httpOnly: false,
        secure: options.cookie?.secure ?? true,
        sameSite: options.cookie?.sameSite ?? 'lax',
        // As long as a session can live, or late writes in a session 403 for no visible reason.
        maxAge: options.cookie?.maxAge ?? 43_200,
      });
      return { token, cookie };
    },
    verify,
    protect: () =>
      defineDecorator('csrf', async (request, _context, next) => {
        const verdict = await verify(request);
        if (!verdict.ok) {
          emit(options.onEvent, { type: 'csrf.rejected', outcome: 'blocked', reason: verdict.reason, request });
          throw new HttpError(403, 'csrf_failed', 'The request could not be verified.');
        }
        return next();
      }),
  };
}
