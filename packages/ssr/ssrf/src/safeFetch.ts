import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { emit, HttpError, type SecurityEventHandler } from '@wardenjs/ssr';
import { blockedRange } from './address.js';

export type SsrfReason =
  | 'invalid_url'
  | 'scheme'
  | 'credentials'
  | 'port'
  | 'host'
  | 'dns'
  | 'private_address'
  | 'redirects'
  | 'too_large'
  | 'timeout';

/** A 502 with a generic message: "blocked 10.0.4.7" would confirm the address exists. */
export class SsrfBlockedError extends HttpError {
  readonly reason: SsrfReason;
  constructor(reason: SsrfReason) {
    super(502, 'outbound_blocked', 'The outbound request was not allowed.');
    this.name = 'SsrfBlockedError';
    this.reason = reason;
  }
}

export interface SafeFetchOptions {
  /** Exact hostnames, or `.example.com` for that domain's subdomains. Empty denies everything. */
  allowedHosts: readonly string[];
  /** Default [443, 8443]: no Redis, memcached or SMTP that happens to speak enough HTTP. */
  ports?: readonly number[];
  /** Default 5000 ms. */
  timeoutMs?: number;
  /** Default 2 MB, counted on the wire with identity encoding (no gzip bombs). */
  maxBytes?: number;
  /** Default 0. Each hop is validated, resolved and pinned again. */
  maxRedirects?: number;
  userAgent?: string;
  onEvent?: SecurityEventHandler;
}

export interface SafeRequest {
  method?: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Never forward the inbound request's Cookie or Authorization. */
  headers?: Record<string, string>;
  body?: string;
}

export interface SafeResponse {
  status: number;
  headers: Headers;
  body: string;
  url: string;
}

/**
 * Node only. The one chokepoint for outbound HTTP to URLs that input can
 * influence. https only, allowlisted host, allowed port, every resolved
 * address checked, and the connection pinned to the checked address so a
 * second DNS answer (rebinding) cannot redirect it. Redirects are followed
 * manually or not at all. Does not cover fetches made on your behalf:
 * image optimisers, headless browsers, XML external entities.
 */
export function createSafeFetch(options: SafeFetchOptions) {
  const hosts = options.allowedHosts.map((host) => host.trim().toLowerCase());
  const ports = new Set(options.ports ?? [443, 8443]);
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
  const maxRedirects = options.maxRedirects ?? 0;

  const block = (reason: SsrfReason, target: string): never => {
    emit(options.onEvent, { type: 'ssrf.blocked', outcome: 'blocked', reason, target });
    throw new SsrfBlockedError(reason);
  };

  function validate(raw: string): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return block('invalid_url', '');
    }
    if (url.protocol !== 'https:') block('scheme', url.protocol);
    // `https://allowed.com@evil.example/` reads as allowed to a naive prefix check.
    if (url.username || url.password) block('credentials', url.hostname);
    if (!ports.has(url.port ? Number(url.port) : 443)) block('port', url.host);
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    const allowed = hosts.some((entry) =>
      entry.startsWith('.') ? host.endsWith(entry) : host === entry,
    );
    if (!allowed) block('host', host);
    return url;
  }

  async function resolve(hostname: string): Promise<string> {
    const literal = hostname.replace(/^\[|\]$/g, '');
    // All addresses: a name can resolve to [public, 169.254.169.254] and let the client pick.
    const records = isIP(literal)
      ? [{ address: literal }]
      : await lookup(hostname, { all: true }).catch(() => block('dns', hostname));
    if (records.length === 0) block('dns', hostname);
    for (const record of records) if (blockedRange(record.address)) block('private_address', hostname);
    return records[0]?.address ?? block('dns', hostname);
  }

  return async function safeFetch(raw: string, init: SafeRequest = {}): Promise<SafeResponse> {
    let current = raw;
    let method = init.method ?? 'GET';
    let body = init.body;
    let headers = { ...init.headers };
    let originalHost: string | undefined;

    for (let hop = 0; ; hop++) {
      const url = validate(current);
      originalHost ??= url.host;
      const address = await resolve(url.hostname);
      const response = await send(url, address, method, headers, body);
      const location = response.headers.get('location');
      if (response.status < 300 || response.status >= 400 || !location) return { ...response, url: url.toString() };
      if (hop >= maxRedirects) block('redirects', url.host);
      current = new URL(location, url).toString();
      // Browser semantics: 303 (and 301/302 after POST) become GET without a body.
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
      }
      // Credentials meant for one host must not follow a redirect to another.
      if (new URL(current).host !== originalHost) {
        headers = Object.fromEntries(
          Object.entries(headers).filter(([name]) => !/^(authorization|cookie|proxy-authorization)$/i.test(name)),
        );
      }
    }
  };

  function send(
    url: URL,
    address: string,
    method: string,
    headers: Record<string, string>,
    body: string | undefined,
  ): Promise<Omit<SafeResponse, 'url'>> {
    return new Promise((resolvePromise, reject) => {
      const request = httpsRequest(
        {
          hostname: url.hostname,
          port: url.port ? Number(url.port) : 443,
          path: `${url.pathname}${url.search}`,
          method,
          headers: {
            'user-agent': options.userAgent ?? 'warden-ssrf',
            ...headers,
            // Forced after the caller's headers.
            host: url.host,
            'accept-encoding': 'identity',
            ...(body === undefined ? {} : { 'content-length': String(Buffer.byteLength(body)) }),
          },
          lookup: pinned(address),
          servername: isIP(url.hostname) ? undefined : url.hostname,
          timeout: timeoutMs,
        },
        (res) => {
          const out = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (Array.isArray(value)) for (const v of value) out.append(name, v);
            else if (typeof value === 'string') out.set(name, value);
          }
          const chunks: Buffer[] = [];
          let received = 0;
          res.on('data', (chunk: Buffer) => {
            received += chunk.byteLength;
            if (received > maxBytes) {
              res.destroy();
              reject(new SsrfBlockedError('too_large'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () =>
            resolvePromise({ status: res.statusCode ?? 0, headers: out, body: Buffer.concat(chunks).toString('utf8') }),
          );
          res.on('error', reject);
        },
      );
      request.on('timeout', () => {
        request.destroy();
        reject(new SsrfBlockedError('timeout'));
      });
      request.on('error', reject);
      if (body !== undefined) request.write(body);
      request.end();
    });
  }
}

/** Answers the client's DNS query with the address already checked: no second lookup to poison. */
function pinned(address: string): LookupFunction {
  const family = isIP(address) === 6 ? 6 : 4;
  return ((_hostname: string, options: { all?: boolean } | undefined, callback: (...args: unknown[]) => void) => {
    if (options?.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  }) as unknown as LookupFunction;
}
