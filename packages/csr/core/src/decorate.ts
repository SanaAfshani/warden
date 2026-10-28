/**
 * A decorator returns an object with the same interface as the one it wraps,
 * adding behaviour without changing the original. Because input and output
 * types are the same, decorators compose in any order and any number.
 */
export type Decorator<T> = (inner: T) => T;

/**
 * `decorate(base, a, b, c)` is `a(b(c(base)))`: decorators are listed in the
 * order a call passes through them, the first being outermost. The same
 * reading as `.use()` in `@wardenjs/ssr`.
 */
export function decorate<T>(base: T, ...decorators: readonly Decorator<T>[]): T {
  return decorators.reduceRight((inner, decorator) => decorator(inner), base);
}
