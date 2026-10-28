import { SignJWT, errors, jwtVerify } from 'jose';
import {
  assertStrongSecret,
  defineDecorator,
  emit,
  randomToken,
  readCookie,
  serializeCookie,
  withCookie,
  type BasePrincipal,
  type Decorator,
  type Principal,
  type Role,
  type SecurityEventHandler,
} from '@wardenjs/ssr';
import { unauthenticated } from './authenticate.js';

/**
 * What the token proves. A JWT is signed, not encrypted: anyone holding the
 * cookie can read it, so nothing here is personal data.
 */
export interface Session {
  readonly userId: string;
  /** As of signing; may be stale. Use `load` for decisions that need the current role. */
  readonly role: Role;
  /** Per-login random id: correlate audit lines, revoke one device. */
  readonly sessionId: string;
  /** Compare with the user's stored version in `load`; bumping it logs out every device. */
  readonly version: number;
  /** A second factor was completed in this session, not merely enrolled. */
  readonly mfa: boolean;
  /** Idle deadline (unix seconds); slides on renewal. */
  readonly expiresAt: number;
  /** Hard deadline (unix seconds); never moves. */
  readonly absoluteExpiresAt: number;
}

export interface CreateSessionInput {
  userId: string;
  role: Role;
  version: number;
  mfa?: boolean;
}

export type VerifyResult =
  | { valid: true; session: Session }
  | { valid: false; reason: 'missing' | 'malformed' | 'expired' | 'invalid' };

type Loader = (session: Session) => Principal | null | Promise<Principal | null>;

/** `load` is optional only while Principal has no fields beyond id and role. */
type LoadOption = [Exclude<keyof Principal, keyof BasePrincipal>] extends [never]
  ? { load?: Loader }
  : { load: Loader };

export type SessionOptions = LoadOption & {
  /** At least 32 random bytes. Checked on first use, so builds without secrets still work. */
  secret: string;
  /** Usually the app origin. Validated on every verify, so a staging token fails in production. */
  issuer: string;
  /** Default: `issuer`. */
  audience?: string;
  /** Default 1800 (30 min). */
  idleTtlSeconds?: number;
  /** Default 43 200 (12 h). Caps what a stolen cookie is worth. */
  absoluteTtlSeconds?: number;
  algorithm?: 'HS256' | 'HS384' | 'HS512';
  /**
   * Default `__Host-session`, Secure, SameSite=Lax, HttpOnly. `__Host-` binds
   * the cookie to this exact host, so a compromised sibling subdomain cannot
   * plant or overwrite it. Safari refuses Secure cookies on http://localhost;
   * use `{ name: 'session', secure: false }` there, never in production.
   */
  cookie?: { name?: string; secure?: boolean; sameSite?: 'strict' | 'lax' };
  /** Validates the role claim. Default: any non-empty string. */
  isRole?: (value: unknown) => value is Role;
  onEvent?: SecurityEventHandler;
};

export interface Sessions {
  create(input: CreateSessionInput): Promise<string>;
  /**
   * New session id for the same user. Call on every privilege change (login,
   * MFA, role or password change), or a pre-planted id stays valid: fixation.
   */
  rotate(input: CreateSessionInput): Promise<string>;
  verify(token: string | undefined): Promise<VerifyResult>;
  read(request: Request): Promise<VerifyResult>;
  shouldRenew(session: Session): boolean;
  /** `Set-Cookie` value. */
  cookie(token: string): string;
  /** `Set-Cookie` value that deletes the session cookie. */
  clearCookie(): string;
  /** 401 without a valid session. Renews the cookie when it is past half its idle life. */
  required(): Decorator<object, { principal: Principal; session: Session }>;
  optional(): Decorator<object, { principal: Principal | null; session: Session | null }>;
}

/**
 * Stateless signed sessions (JWT via `jose`, so it runs on Edge too). A
 * signed token cannot be deleted, which is why lifetimes are short, the
 * absolute deadline never slides, and `version` gives revocation through `load`.
 * If you need an instant per-session kill switch, use a server-side session
 * table behind `authenticate()` instead.
 */
export function sessions(options: SessionOptions): Sessions {
  const idleTtl = options.idleTtlSeconds ?? 1800;
  const absoluteTtl = options.absoluteTtlSeconds ?? 43_200;
  if (!(idleTtl > 0 && absoluteTtl >= idleTtl && absoluteTtl <= 90 * 86_400)) {
    throw new Error('sessions: need 0 < idleTtlSeconds <= absoluteTtlSeconds <= 90 days.');
  }
  const algorithm = options.algorithm ?? 'HS256';
  const audience = options.audience ?? options.issuer;
  const cookieName = options.cookie?.name ?? '__Host-session';
  const secure = options.cookie?.secure ?? true;
  const sameSite = options.cookie?.sameSite ?? 'lax';
  const isRole =
    options.isRole ?? ((value: unknown): value is Role => typeof value === 'string' && value !== '');
  const load: Loader =
    options.load ?? ((session) => ({ id: session.userId, role: session.role }));
  const clockTolerance = 5;

  let key: Uint8Array | undefined;
  const signingKey = () => {
    if (!key) {
      assertStrongSecret('sessions', options.secret);
      key = new TextEncoder().encode(options.secret);
    }
    return key;
  };

  const now = () => Math.floor(Date.now() / 1000);

  async function sign(input: CreateSessionInput, sessionId: string, absolute: number): Promise<string> {
    const issuedAt = now();
    // `exp` slides but is clamped to the absolute deadline, or one request per
    // idle window keeps a stolen cookie alive forever.
    const claims = { role: input.role, sid: sessionId, sv: input.version, abs: absolute, mfa: input.mfa ?? false };
    return new SignJWT(claims)
      .setProtectedHeader({ alg: algorithm, typ: 'JWT' })
      .setSubject(input.userId)
      .setIssuedAt(issuedAt)
      .setNotBefore(issuedAt)
      .setExpirationTime(Math.min(issuedAt + idleTtl, absolute))
      .setIssuer(options.issuer)
      .setAudience(audience)
      .sign(signingKey());
  }

  const create: Sessions['create'] = (input) => sign(input, randomToken(16), now() + absoluteTtl);

  const verify: Sessions['verify'] = async (token) => {
    if (!token) return { valid: false, reason: 'missing' };
    // Structure first, so junk never reaches signature verification.
    if (token.length > 4096 || token.split('.').length !== 3) return { valid: false, reason: 'malformed' };
    try {
      const { payload } = await jwtVerify(token, signingKey(), {
        // Pinned: trusting the token's own `alg` is how `none` and key-confusion attacks work.
        algorithms: [algorithm],
        issuer: options.issuer,
        audience,
        clockTolerance,
        maxTokenAge: absoluteTtl + clockTolerance,
      });
      const { sub, role, sid, sv, abs, mfa, exp } = payload;
      if (
        typeof sub !== 'string' ||
        sub === '' ||
        !isRole(role) ||
        typeof sid !== 'string' ||
        typeof sv !== 'number' ||
        typeof abs !== 'number' ||
        typeof exp !== 'number'
      ) {
        return { valid: false, reason: 'malformed' };
      }
      if (now() > abs) return { valid: false, reason: 'expired' };
      const session: Session = {
        userId: sub,
        role,
        sessionId: sid,
        version: sv,
        mfa: mfa === true,
        expiresAt: exp,
        absoluteExpiresAt: abs,
      };
      return { valid: true, session };
    } catch (error) {
      if (error instanceof errors.JWTExpired) return { valid: false, reason: 'expired' };
      return { valid: false, reason: 'invalid' };
    }
  };

  const shouldRenew: Sessions['shouldRenew'] = (session) => {
    const t = now();
    // Renew past half the idle window, not on every request: a Set-Cookie on
    // every response breaks caching and races parallel requests.
    return (
      session.expiresAt - t < idleTtl / 2 &&
      session.expiresAt < session.absoluteExpiresAt &&
      t < session.absoluteExpiresAt
    );
  };

  const cookie = (token: string) =>
    serializeCookie({ name: cookieName, value: token, httpOnly: true, secure, sameSite, maxAge: absoluteTtl });
  // Same attributes as the original, or the browser treats it as another cookie and keeps the old one.
  const clearCookie = () =>
    serializeCookie({ name: cookieName, value: '', httpOnly: true, secure, sameSite, maxAge: 0 });

  const read: Sessions['read'] = (request) => verify(readCookie(request, cookieName));

  async function resolve(request: Request) {
    const result = await read(request);
    if (!result.valid) {
      if (result.reason !== 'missing') {
        emit(options.onEvent, { type: 'authn.session_invalid', outcome: 'failure', reason: result.reason, request });
      }
      return { result, principal: null } as const;
    }
    const principal = await load(result.session);
    if (!principal) {
      emit(options.onEvent, {
        type: 'authn.session_revoked',
        outcome: 'blocked',
        actorId: result.session.userId,
        request,
      });
    }
    return { result, principal } as const;
  }

  async function finish(response: Response, result: VerifyResult, principal: Principal | null) {
    // A handler that set the cookie itself (logout, login, rotation) has the last word.
    if (response.headers.getSetCookie().some((value) => value.startsWith(`${cookieName}=`))) {
      return response;
    }
    if (!result.valid) {
      return result.reason === 'missing' ? response : withCookie(response, clearCookie());
    }
    if (!principal) return withCookie(response, clearCookie());
    if (!shouldRenew(result.session)) return response;
    const s = result.session;
    const token = await sign(
      { userId: s.userId, role: s.role, version: s.version, mfa: s.mfa },
      s.sessionId,
      s.absoluteExpiresAt,
    );
    return withCookie(response, cookie(token));
  }

  return {
    create,
    rotate: create,
    verify,
    read,
    shouldRenew,
    cookie,
    clearCookie,
    required: () =>
      defineDecorator<object, { principal: Principal; session: Session }>('session', async (request, _context, next) => {
        const { result, principal } = await resolve(request);
        if (!result.valid || !principal) {
          return finish(unauthenticated().toResponse(), result, principal);
        }
        return finish(await next({ principal, session: result.session }), result, principal);
      }),
    optional: () =>
      defineDecorator<object, { principal: Principal | null; session: Session | null }>(
        'sessionOptional',
        async (request, _context, next) => {
          const { result, principal } = await resolve(request);
          const session = result.valid && principal ? result.session : null;
          return finish(await next({ principal, session }), result, principal);
        },
      ),
  };
}
