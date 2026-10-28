import {
  defineDecorator,
  emit,
  HttpError,
  type Decorator,
  type Principal,
  type SecurityEventHandler,
} from '@wardenjs/ssr';

/** Who is calling, or null. Wrap any provider: Auth.js, Clerk, API keys, mTLS headers. */
export type PrincipalResolver = (request: Request) => Principal | null | Promise<Principal | null>;

export interface Authenticator {
  /** 401 when nobody is signed in; inner decorators get a non-null `principal`. */
  required(): Decorator<object, { principal: Principal }>;
  /** Never rejects; `principal` is null for anonymous callers. */
  optional(): Decorator<object, { principal: Principal | null }>;
}

export const unauthenticated = () =>
  new HttpError(401, 'unauthenticated', 'Authentication required.');

/**
 * The generic authentication decorator. Everything downstream (access
 * control, per-user rate limits, audit) only depends on `principal`, so the
 * identity provider stays swappable.
 */
export function authenticate(
  resolve: PrincipalResolver,
  options: { onEvent?: SecurityEventHandler } = {},
): Authenticator {
  return {
    required: () =>
      defineDecorator<object, { principal: Principal }>('authenticate', async (request, _context, next) => {
        const principal = await resolve(request);
        if (!principal) {
          emit(options.onEvent, { type: 'authn.rejected', outcome: 'blocked', reason: 'anonymous', request });
          throw unauthenticated();
        }
        return next({ principal });
      }),
    optional: () =>
      defineDecorator<object, { principal: Principal | null }>(
        'authenticateOptional',
        async (request, _context, next) => next({ principal: await resolve(request) }),
      ),
  };
}
