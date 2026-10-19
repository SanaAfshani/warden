import { describe, expect, it } from 'vitest';
import { chain } from '@sanaafshani/warden-ssr';
import { csrf } from '../src/index.js';

const secret = 'k9$Lm2#Qp7@Zx4!Rt8&Wv1^Ny6*Bc3%Hd5';
const origin = 'https://app.test';

const post = (headers: Record<string, string>) => new Request(`${origin}/api/transfer`, { method: 'POST', headers });

async function setup() {
  const c = csrf({ secret, origin });
  const handler = chain().use(c.protect()).handle(() => new Response('done'));
  const { token } = await c.issue();
  return { c, handler, token };
}

describe('csrf', () => {
  it('accepts a same-origin write with the matching signed token', async () => {
    const { handler, token } = await setup();
    const response = await handler(post({ origin, cookie: `__Host-csrf=${token}`, 'x-csrf-token': token }));
    expect(response.status).toBe(200);
  });

  it('rejects a cross-site request even when the browser attached the cookie', async () => {
    const { handler, token } = await setup();
    const response = await handler(
      post({ 'sec-fetch-site': 'cross-site', origin: 'https://evil.example', cookie: `__Host-csrf=${token}`, 'x-csrf-token': token }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: 'csrf_failed' } });
  });

  it('compares Origin exactly: a lookalike suffix is a different site', async () => {
    const { c, token } = await setup();
    const verdict = await c.verify(post({ origin: 'https://app.test.evil.example', cookie: `__Host-csrf=${token}`, 'x-csrf-token': token }));
    expect(verdict).toEqual({ ok: false, reason: 'origin-mismatch' });
  });

  it('defeats cookie tossing: a value planted in both cookie and header is not signed', async () => {
    const { c } = await setup();
    const planted = 'attacker-chosen.c2lnbmF0dXJl';
    const verdict = await c.verify(post({ origin, cookie: `__Host-csrf=${planted}`, 'x-csrf-token': planted }));
    expect(verdict).toEqual({ ok: false, reason: 'token-invalid' });
  });

  it('requires the header to echo the cookie', async () => {
    const { c, token } = await setup();
    expect(await c.verify(post({ origin, cookie: `__Host-csrf=${token}` }))).toEqual({ ok: false, reason: 'token-missing' });
  });

  it('leaves safe methods alone', async () => {
    const { c } = await setup();
    expect(await c.verify(new Request(`${origin}/x`, { headers: { 'sec-fetch-site': 'cross-site' } }))).toEqual({ ok: true });
  });
});
