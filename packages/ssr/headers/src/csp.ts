import { randomToken } from '@sanaafshani/warden-ssr';

/** Fresh per response; a reused nonce is a published password for script injection. */
export function cspNonce(): string {
  return randomToken(16);
}

export interface CspOptions {
  nonce: string;
  connectSrc?: readonly string[];
  imgSrc?: readonly string[];
  frameSrc?: readonly string[];
  /**
   * Default `'self' 'unsafe-inline'`. Inline styles cannot run script, but CSS
   * injection can still exfiltrate attribute values. Pass `["'self'",
   * "'nonce-…'"]` once your styling allows it.
   */
  styleSrc?: readonly string[];
  /** Adds `report-uri` and `report-to csp-endpoint`; pair with `reportingEndpoints()`. */
  reportUri?: string;
  /** Development only: allows `eval` and `ws:` for hot reload. Never in production. */
  development?: boolean;
}

/**
 * A nonce + `strict-dynamic` policy for HTML documents. Host allowlists are
 * not offered: ~94% of real allowlist policies were bypassable (Weichselbaum
 * et al., CCS 2016) through JSONP endpoints and old libraries on allowed hosts.
 * `'unsafe-inline'` and `https:` are ignored by any browser that understands
 * nonces; they only keep CSP2-era browsers from breaking.
 */
export function buildCsp(options: CspOptions): string {
  const dev = options.development === true;
  const directives = [
    "default-src 'none'",
    [
      'script-src',
      `'nonce-${options.nonce}'`,
      "'strict-dynamic'",
      "'unsafe-inline'",
      'https:',
      ...(dev ? ["'unsafe-eval'"] : []),
    ].join(' '),
    ['style-src', ...(options.styleSrc ?? ["'self'", "'unsafe-inline'"])].join(' '),
    "font-src 'self' data:",
    ['img-src', "'self'", 'data:', 'blob:', ...(options.imgSrc ?? [])].join(' '),
    ['connect-src', "'self'", ...(dev ? ['ws:', 'wss:'] : []), ...(options.connectSrc ?? [])].join(' '),
    options.frameSrc?.length ? ['frame-src', ...options.frameSrc].join(' ') : "frame-src 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "worker-src 'self' blob:",
    "media-src 'self'",
    "manifest-src 'self'",
  ];
  if (!dev) directives.push('upgrade-insecure-requests');
  if (options.reportUri) directives.push(`report-uri ${options.reportUri}`, 'report-to csp-endpoint');
  return directives.join('; ');
}

/** Value for the `Reporting-Endpoints` header that `report-to csp-endpoint` points at. */
export function reportingEndpoints(reportUrl: string): string {
  return `csp-endpoint="${reportUrl}"`;
}
