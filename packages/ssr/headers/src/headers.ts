import { defineDecorator, withHeaders, type Decorator } from '@wardenjs/ssr';

export interface HeaderSetOptions {
  /**
   * Strict-Transport-Security. Browsers ignore it over plain http, so it is
   * safe to leave on in development. `preload` is a one-way door (removal
   * from the browsers' list takes months), hence off by default.
   */
  hsts?: false | { maxAge?: number; includeSubDomains?: boolean; preload?: boolean };
  /** Default `DENY`. Legacy twin of CSP `frame-ancestors`, still read by old clients. */
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** Default `strict-origin-when-cross-origin`: tokens in URLs never leave in Referer. */
  referrerPolicy?: string;
  /** Default denies camera, microphone, geolocation, payment, usb, serial, bluetooth, display-capture. */
  permissionsPolicy?: readonly string[];
  /** Default `same-origin`: severs `window.opener` (tab-nabbing, XS-Leaks). */
  crossOriginOpenerPolicy?: string;
  /** Default `same-origin`: other sites cannot embed responses as subresources. */
  crossOriginResourcePolicy?: string;
}

const DEFAULT_PERMISSIONS = [
  'camera=()',
  'microphone=()',
  'geolocation=()',
  'payment=()',
  'usb=()',
  'serial=()',
  'bluetooth=()',
  'display-capture=()',
];

/**
 * The headers that are identical for every response, as a plain record, so
 * they can also be set in `next.config` (which covers static assets that a
 * route decorator never sees). `X-XSS-Protection` is deliberately absent: the
 * auditor it controlled was removed from browsers because it was exploitable.
 */
export function securityHeaders(options: HeaderSetOptions = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': options.referrerPolicy ?? 'strict-origin-when-cross-origin',
    'Permissions-Policy': (options.permissionsPolicy ?? DEFAULT_PERMISSIONS).join(', '),
    'Cross-Origin-Opener-Policy': options.crossOriginOpenerPolicy ?? 'same-origin',
    'Cross-Origin-Resource-Policy': options.crossOriginResourcePolicy ?? 'same-origin',
  };
  const frameOptions = options.frameOptions ?? 'DENY';
  if (frameOptions) headers['X-Frame-Options'] = frameOptions;
  if (options.hsts !== false) {
    const { maxAge = 63_072_000, includeSubDomains = true, preload = false } = options.hsts ?? {};
    headers['Strict-Transport-Security'] = [
      `max-age=${maxAge}`,
      includeSubDomains && 'includeSubDomains',
      preload && 'preload',
    ]
      .filter(Boolean)
      .join('; ');
  }
  return headers;
}

/**
 * For any response that contains per-user data: a shared cache that stores
 * `GET /api/me` for one user will serve it to the next.
 */
export function noStoreHeaders(): Record<string, string> {
  return {
    'Cache-Control': 'private, no-store, no-cache, max-age=0, must-revalidate',
    Pragma: 'no-cache',
    Expires: '0',
  };
}

export interface SecureHeadersOptions extends HeaderSetOptions {
  /**
   * Default suits JSON APIs: nothing may load and nothing may frame it.
   * Pass a `buildCsp()` value for HTML, or `false` if a proxy sets CSP.
   */
  csp?: string | false;
  /** Default true. Turn off only for responses that are genuinely public. */
  noStore?: boolean;
}

/**
 * Adds security headers to every response that passes through, including
 * rejections from inner decorators. A header the handler already set wins:
 * the handler is the most specific authority on its own response.
 */
export function secureHeaders(options: SecureHeadersOptions = {}): Decorator {
  const fixed: Record<string, string> = securityHeaders(options);
  const csp = options.csp ?? "default-src 'none'; frame-ancestors 'none'";
  if (csp) fixed['Content-Security-Policy'] = csp;
  if (options.noStore !== false) Object.assign(fixed, noStoreHeaders());

  return defineDecorator('secureHeaders', async (_request, _context, next) => {
    const response = await next();
    const missing: Record<string, string> = {};
    for (const [name, value] of Object.entries(fixed)) {
      if (!response.headers.has(name)) missing[name] = value;
    }
    if (options.noStore !== false) missing.Vary = mergeVary(response.headers.get('vary'), ['Cookie', 'Authorization']);
    return withHeaders(response, missing);
  });
}

export function mergeVary(current: string | null, add: readonly string[]): string {
  const values = (current ?? '').split(',').map((v) => v.trim()).filter(Boolean);
  if (values.includes('*')) return '*';
  const lower = new Set(values.map((v) => v.toLowerCase()));
  for (const value of add) if (!lower.has(value.toLowerCase())) values.push(value);
  return values.join(', ');
}
