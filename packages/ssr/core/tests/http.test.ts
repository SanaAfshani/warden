import { describe, expect, it } from 'vitest';
import { assertStrongSecret, clientIp, HttpError, readBytes, readCookie, serializeCookie } from '../src/index.js';

const streamOf = (chunks: number, size: number) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < chunks; i++) controller.enqueue(new Uint8Array(size));
      controller.close();
    },
  });

describe('readBytes', () => {
  it('caps chunked bodies that carry no Content-Length', async () => {
    const request = new Request('https://app.test', {
      method: 'POST',
      body: streamOf(10, 1024),
      duplex: 'half',
    } as RequestInit);
    await expect(readBytes(request, 4096)).rejects.toMatchObject({ status: 413 });
  });

  it('rejects early on a declared Content-Length over the cap', async () => {
    const request = new Request('https://app.test', { method: 'POST', body: 'x', headers: { 'content-length': '999999' } });
    await expect(readBytes(request, 10)).rejects.toBeInstanceOf(HttpError);
  });
});

describe('clientIp', () => {
  const request = (headers: Record<string, string>) => new Request('https://app.test', { headers });

  it('ignores the client-controlled left side of X-Forwarded-For', () => {
    expect(clientIp(request({ 'x-forwarded-for': '1.1.1.1, 203.0.113.9' }))).toBe('203.0.113.9');
  });

  it('does not trust platform headers unless configured: anyone can send them', () => {
    expect(clientIp(request({ 'cf-connecting-ip': '1.1.1.1' }))).toBe('unknown');
    expect(clientIp(request({ 'cf-connecting-ip': '198.51.100.4' }), { header: 'cf-connecting-ip' })).toBe('198.51.100.4');
  });
});

describe('cookies', () => {
  it('encodes values so a `;` cannot inject attributes', () => {
    const header = serializeCookie({ name: 'a', value: 'x; Domain=evil.example', httpOnly: true, secure: true, sameSite: 'lax' });
    expect(header).not.toContain('Domain=');
    expect(readCookie(new Request('https://app.test', { headers: { cookie: header.split(';')[0] ?? '' } }), 'a')).toBe(
      'x; Domain=evil.example',
    );
  });

  it('refuses __Host- cookies without Secure, and SameSite=None without Secure', () => {
    expect(() => serializeCookie({ name: '__Host-s', value: '', httpOnly: true, secure: false, sameSite: 'lax' })).toThrow();
    expect(() => serializeCookie({ name: 's', value: '', httpOnly: true, secure: false, sameSite: 'none' })).toThrow();
  });

  it('treats malformed percent-encoding as absent instead of throwing', () => {
    expect(readCookie(new Request('https://app.test', { headers: { cookie: 'a=%E0%A4%A' } }), 'a')).toBeUndefined();
  });
});

describe('assertStrongSecret', () => {
  it('rejects short and low-variety secrets', () => {
    expect(() => assertStrongSecret('test', 'short')).toThrow();
    expect(() => assertStrongSecret('test', 'a'.repeat(64))).toThrow();
    expect(() => assertStrongSecret('test', 'k9$Lm2#Qp7@Zx4!Rt8&Wv1^Ny6*Bc3%Hd5')).not.toThrow();
  });
});
