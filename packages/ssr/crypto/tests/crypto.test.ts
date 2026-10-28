import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { chain } from '@wardenjs/ssr';
import { cipher, DecryptionError, signer, verifyWebhook, webhook } from '../src/index.js';

const key = 'k9$Lm2#Qp7@Zx4!Rt8&Wv1^Ny6*Bc3%Hd5';
const nextKey = 'Z1#qW2$eR3%tY4^uI5&oP6*aS7(dF8)gH9';

describe('cipher', () => {
  it('round-trips, with a fresh IV per message', async () => {
    const c = cipher({ key });
    const a = await c.encrypt('secret', 'totp:u1');
    expect(a).not.toBe(await c.encrypt('secret', 'totp:u1'));
    expect(await c.decrypt(a, 'totp:u1')).toBe('secret');
  });

  it('fails when a ciphertext is moved to another row (context is authenticated)', async () => {
    const c = cipher({ key });
    await expect(c.decrypt(await c.encrypt('secret', 'totp:u1'), 'totp:u2')).rejects.toBeInstanceOf(DecryptionError);
  });

  it('fails on a single flipped character', async () => {
    const c = cipher({ key });
    const envelope = await c.encrypt('secret', 'ctx');
    const tampered = envelope.slice(0, -2) + (envelope.endsWith('A') ? 'B' : 'A') + envelope.slice(-1);
    await expect(c.decrypt(tampered, 'ctx')).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rotates keys: old envelopes still decrypt and are flagged for re-encryption', async () => {
    const old = await cipher({ key, version: 'v1' }).encrypt('secret', 'ctx');
    const rotated = cipher({ key: nextKey, version: 'v2', previous: { v1: key } });
    expect(await rotated.decrypt(old, 'ctx')).toBe('secret');
    expect(rotated.needsReencryption(old)).toBe(true);
  });
});

describe('signer', () => {
  it('separates purposes: a signature for one subsystem never verifies in another', async () => {
    const s = signer({ key });
    const signature = await s.sign('unsubscribe', 'u1');
    expect(await s.verify('unsubscribe', 'u1', signature)).toBe(true);
    expect(await s.verify('password-reset', 'u1', signature)).toBe(false);
  });

  it('signed URLs reject edited parameters', async () => {
    const s = signer({ key });
    const url = new URL(await s.signUrl('/download', { file: 'a.pdf' }, 60), 'https://a.test');
    expect(await s.verifyUrl(url)).toBe(true);
    url.searchParams.set('file', 'b.pdf');
    expect(await s.verifyUrl(url)).toBe(false);
  });
});

describe('webhooks', () => {
  const secret = 'whsec_provider_given_secret';
  const body = '{"event":"paid","amount":100}';
  const github = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;

  it('verifies a real provider signature made with the raw secret', async () => {
    expect(await verifyWebhook({ secret, rawBody: body, signature: github })).toEqual({ valid: true });
  });

  it('rejects a body changed after signing, and replays outside the tolerance', async () => {
    expect(await verifyWebhook({ secret, rawBody: body.replace('100', '1'), signature: github })).toMatchObject({ valid: false });
    const t = Math.floor(Date.now() / 1000) - 3600;
    const stripe = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
    expect(await verifyWebhook({ secret, rawBody: body, signature: stripe, timestamp: t })).toEqual({ valid: false, reason: 'stale' });
  });

  it('the decorator answers 401 and never runs the handler on a bad signature', async () => {
    const handler = chain()
      .use(webhook({ secret, signatureHeader: 'x-hub-signature-256' }))
      .handle((_r, c) => new Response(c.rawBody));
    const send = (signature: string) =>
      handler(new Request('https://a.test/hook', { method: 'POST', body, headers: { 'x-hub-signature-256': signature } }));
    expect(await (await send(github)).text()).toBe(body);
    expect((await send('sha256=00')).status).toBe(401);
  });
});
