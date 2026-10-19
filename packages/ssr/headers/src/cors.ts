import { defineDecorator, withHeaders, type Decorator } from '@sanaafshani/warden-ssr';
import { mergeVary } from './headers.js';

export interface CorsOptions {
  /**
   * Exact origins only. No `*`, no suffix or pattern matching: `endsWith`
   * matches `notexample.com`, and reflecting the Origin header grants every
   * site read access to authenticated responses.
   */
  origins: readonly string[];
  methods?: readonly string[];
  headers?: readonly string[];
  /** Send `Access-Control-Allow-Credentials`. */
  credentials?: boolean;
  /** Preflight cache in seconds. Default 600. */
  maxAge?: number;
}

/** Empty when the origin is absent or not on the list; the browser then blocks by default. */
export function corsHeaders(origin: string | null, options: CorsOptions): Record<string, string> {
  if (!origin || !options.origins.includes(origin)) return {};
  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': (options.methods ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).join(', '),
    'Access-Control-Allow-Headers': (options.headers ?? ['Content-Type', 'Authorization', 'X-CSRF-Token']).join(', '),
    'Access-Control-Max-Age': String(options.maxAge ?? 600),
  };
  if (options.credentials) headers['Access-Control-Allow-Credentials'] = 'true';
  return headers;
}

/**
 * Only needed when a separate, named origin calls this API. A same-origin
 * frontend never triggers CORS, and adding it "just in case" only widens access.
 */
export function cors(options: CorsOptions): Decorator {
  if (options.origins.includes('*')) throw new Error('cors: wildcard origins are not supported.');
  return defineDecorator('cors', async (request, _context, next) => {
    const origin = request.headers.get('origin');
    const allowed = corsHeaders(origin, options);
    if (request.method === 'OPTIONS' && request.headers.has('access-control-request-method')) {
      return new Response(null, { status: 204, headers: { ...allowed, Vary: 'Origin' } });
    }
    const response = await next();
    // Vary: Origin even when denied, or a shared cache can replay an allowed answer to another origin.
    return withHeaders(response, { ...allowed, Vary: mergeVary(response.headers.get('vary'), ['Origin']) });
  });
}
