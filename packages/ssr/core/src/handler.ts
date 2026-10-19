import { HttpError } from './errors.js';

/**
 * What every route receives before any decorator runs. `params` are the
 * router's path parameters (Next.js passes them as a promise; they are awaited
 * once, here, so nothing downstream has to care).
 */
export interface BaseContext {
  readonly params: Readonly<Record<string, string | string[]>>;
}

/** A Fetch-API handler: the one interface every decorator wraps and returns. */
export type Handler<Context extends object = BaseContext> = (
  request: Request,
  context: Context,
) => Response | Promise<Response>;

/** What `chain().handle()` returns: the shape Next.js, Hono, Bun and Workers call. */
export type RouteHandler = (
  request: Request,
  route?: { params?: unknown },
) => Promise<Response>;

declare const types: unique symbol;

/**
 * A decorator takes a handler and returns a handler with the same interface,
 * adding behaviour before and/or after it without changing it.
 *
 * `Needs` is what it reads from the context (checked at compile time by
 * `chain().use()`); `Adds` is what it passes to everything inside it.
 */
export interface Decorator<Needs extends object = object, Adds extends object = object> {
  readonly name: string;
  wrap(inner: Handler<Needs & Adds>): Handler<Needs>;
  /** Type-level only; never set at runtime. */
  readonly [types]?: { readonly needs: Needs; readonly adds: Adds };
}

/**
 * Calls the decorated handler. Pass what this decorator adds to the context.
 *
 * Always resolves to a Response: an `HttpError` thrown further in is converted
 * here, so a decorator can act on rejections too (headers on a 403, RateLimit
 * headers on a 422). Any other error propagates.
 */
export type Next<Adds extends object> = keyof Adds extends never
  ? (adds?: Adds) => Promise<Response>
  : (adds: Adds) => Promise<Response>;

/**
 * Build a decorator from an `around` function. The context is merged for you
 * (`{ ...context, ...adds }`), so a decorator cannot accidentally drop what an
 * outer one provided.
 */
export function defineDecorator<Needs extends object = object, Adds extends object = object>(
  name: string,
  around: (request: Request, context: Needs, next: Next<Adds>) => Promise<Response>,
): Decorator<Needs, Adds> {
  return {
    name,
    wrap: (inner) => (request, context) => {
      const next = async (adds?: Adds): Promise<Response> => {
        try {
          return await inner(request, { ...context, ...adds } as Needs & Adds);
        } catch (error) {
          if (error instanceof HttpError) return error.toResponse();
          throw error;
        }
      };
      return around(request, context, next);
    },
  };
}

type Flatten<T> = { [K in keyof T]: T[K] } & {};
type Merge<A, B> = Flatten<Omit<A, keyof B> & B>;

/** Resolves to `unknown` when satisfied, otherwise to a type naming the missing keys. */
type Requires<Have, Need> = [Have] extends [Need]
  ? unknown
  : {
      readonly '~missing context': [Exclude<keyof Need, keyof Have>] extends [never]
        ? 'present with an incompatible type'
        : Exclude<keyof Need, keyof Have>;
    };

/**
 * An immutable list of decorators. `.use()` order is nesting order: the first
 * decorator is the outermost, so it sees the request first and the response
 * last. Each `.use()` returns a new chain, so a base chain can be shared.
 */
export interface Chain<Context extends object> {
  use<Needs extends object, Adds extends object>(
    decorator: Decorator<Needs, Adds> & Requires<Context, Needs>,
  ): Chain<Merge<Context, Adds>>;
  handle(handler: Handler<Context>): RouteHandler;
}

export function chain(): Chain<BaseContext> {
  return build([]);
}

function build<Context extends object>(decorators: readonly Decorator[]): Chain<Context> {
  return {
    use: (decorator) => build([...decorators, decorator as Decorator]),
    handle(handler) {
      const composed = decorators.reduceRight<Handler<object>>(
        (inner, decorator) => decorator.wrap(inner),
        handler as Handler<object>,
      );
      return async (request, route) => {
        const raw: unknown = await route?.params;
        const params = typeof raw === 'object' && raw !== null ? raw : {};
        try {
          return await composed(request, { params });
        } catch (error) {
          if (error instanceof HttpError) return error.toResponse();
          throw error;
        }
      };
    },
  };
}
