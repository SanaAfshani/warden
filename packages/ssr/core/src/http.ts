import { HttpError } from './errors.js';

export function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0 || part.slice(0, index).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      // Malformed percent-encoding: treat as absent so junk cannot 500 a route.
      return undefined;
    }
  }
  return undefined;
}

export interface Cookie {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path?: string;
  /** Seconds. Omit for a browser-session cookie; 0 deletes. */
  maxAge?: number;
}

/**
 * There is deliberately no `domain` attribute: a cookie scoped to a parent
 * domain is readable and overwritable by every sibling subdomain.
 */
export function serializeCookie(cookie: Cookie): string {
  const path = cookie.path ?? '/';
  if (cookie.name.startsWith('__Host-') && (!cookie.secure || path !== '/')) {
    throw new Error('__Host- cookies require Secure and Path=/.');
  }
  if (cookie.name.startsWith('__Secure-') && !cookie.secure) {
    throw new Error('__Secure- cookies require Secure.');
  }
  if (cookie.sameSite === 'none' && !cookie.secure) {
    throw new Error('SameSite=None requires Secure.');
  }
  // Encoded so a `;` in the value cannot inject attributes.
  const parts = [`${cookie.name}=${encodeURIComponent(cookie.value)}`, `Path=${path}`];
  if (cookie.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(cookie.maxAge))}`);
  parts.push(`SameSite=${cookie.sameSite[0]?.toUpperCase()}${cookie.sameSite.slice(1)}`);
  if (cookie.httpOnly) parts.push('HttpOnly');
  if (cookie.secure) parts.push('Secure');
  return parts.join('; ');
}

/**
 * The body with a running byte cap: 413 at the limit, not after buffering.
 * `request.json()`, `.text()` and `.formData()` have no limit at all, and
 * `Content-Length` is only a hint (absent on chunked bodies, and clients lie).
 */
export async function readBytes(request: Request, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  const tooLarge = () => new HttpError(413, 'payload_too_large', `Request body exceeds ${maxBytes} bytes.`);
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) throw tooLarge();
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export interface ClientIpOptions {
  /**
   * A header your edge overwrites on every request (`cf-connecting-ip`,
   * `x-real-ip`, `fly-client-ip`). Only set this if the app is unreachable
   * except through that edge, or anyone can choose their own IP.
   */
  header?: string;
  /** Proxies that append to `X-Forwarded-For`. 0 ignores the header. Default 1. */
  trustedHops?: number;
}

/**
 * The client IP as reported by your own infrastructure. The left-most
 * `X-Forwarded-For` entry is whatever the client sent; the entry added by
 * your last trusted proxy is `trustedHops` from the right.
 */
export function clientIp(request: Request, options: ClientIpOptions = {}): string {
  if (options.header) return request.headers.get(options.header)?.trim() || 'unknown';
  const hops = options.trustedHops ?? 1;
  if (hops <= 0) return 'unknown';
  const chain = (request.headers.get('x-forwarded-for') ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return chain[chain.length - hops] ?? 'unknown';
}

/**
 * Set headers on a response. Responses from `fetch()` and `Response.redirect()`
 * have immutable headers; those are copied instead of throwing.
 */
export function withHeaders(response: Response, headers: Record<string, string>): Response {
  return mutate(response, (target) => {
    for (const [name, value] of Object.entries(headers)) target.set(name, value);
  });
}

/** Appends, so cookies set by the handler or other decorators survive. */
export function withCookie(response: Response, setCookie: string): Response {
  return mutate(response, (target) => target.append('Set-Cookie', setCookie));
}

function mutate(response: Response, apply: (headers: Headers) => void): Response {
  try {
    apply(response.headers);
    return response;
  } catch {
    const copy = new Response(response.body, response);
    apply(copy.headers);
    return copy;
  }
}
