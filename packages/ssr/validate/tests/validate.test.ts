import { describe, expect, expectTypeOf, it } from 'vitest';
import { z } from 'zod';
import { chain } from '@sanaafshani/warden-ssr';
import { body, params, query, readForm } from '../src/index.js';

const json = (value: string, headers: Record<string, string> = {}) =>
  new Request('https://a.test/x', { method: 'POST', body: value, headers: { 'content-type': 'application/json', ...headers } });

const create = chain()
  .use(body(z.object({ title: z.string().min(1).max(100) })))
  .handle((_r, c) => {
    expectTypeOf(c.body).toEqualTypeOf<{ title: string }>();
    return Response.json(c.body);
  });

describe('body', () => {
  it('hands the handler a typed, validated body (any Standard Schema library)', async () => {
    expect(await (await create(json('{"title":"hi"}'))).json()).toEqual({ title: 'hi' });
  });

  it('rejects with 422 and field-level details, never echoing the input', async () => {
    const response = await create(json('{"title":""}'));
    expect(response.status).toBe(422);
    const payload = (await response.json()) as { error: { details: Record<string, string[]> } };
    expect(Object.keys(payload.error.details)).toEqual(['title']);
  });

  it('rejects non-JSON content types, which also blocks cross-site form posts', async () => {
    const response = await create(new Request('https://a.test/x', { method: 'POST', body: 'title=x', headers: { 'content-type': 'text/plain' } }));
    expect(response.status).toBe(415);
  });

  it('rejects deeply nested JSON before anything walks it', async () => {
    const response = await create(json(`${'['.repeat(50)}${']'.repeat(50)}`));
    expect(response.status).toBe(400);
  });

  it('rejects oversized bodies with 413', async () => {
    const big = chain().use(body(z.unknown(), { maxBytes: 10 })).handle(() => new Response());
    expect((await big(json('{"title":"far too long"}'))).status).toBe(413);
  });
});

describe('query and params', () => {
  it('exposes parameter pollution as an array, so the schema decides', async () => {
    const handler = chain()
      .use(query(z.object({ limit: z.string() })))
      .handle(() => new Response());
    expect((await handler(new Request('https://a.test/x?limit=10&limit=999999'))).status).toBe(422);
  });

  it('validates route params, which are input too', async () => {
    const handler = chain()
      .use(params(z.object({ id: z.string().regex(/^\d+$/) })))
      .handle((_r, c) => Response.json(c.params));
    const route = (id: string) => ({ params: Promise.resolve({ id }) });
    expect((await handler(new Request('https://a.test/orders/1'), route('../../admin'))).status).toBe(422);
    expect(await (await handler(new Request('https://a.test/orders/1'), route('42'))).json()).toEqual({ id: '42' });
  });
});

describe('readForm', () => {
  it('enforces the byte cap on the real body, not on the Content-Length hint', async () => {
    const form = new FormData();
    form.set('a', 'x'.repeat(5000));
    const request = new Request('https://a.test/x', { method: 'POST', body: form });
    request.headers.delete('content-length');
    await expect(readForm(request, { maxBytes: 1000 })).rejects.toMatchObject({ status: 413 });
  });

  it('caps the number of fields', async () => {
    const form = new FormData();
    for (let i = 0; i < 60; i++) form.set(`f${i}`, '1');
    await expect(readForm(new Request('https://a.test/x', { method: 'POST', body: form }))).rejects.toMatchObject({ status: 400 });
  });
});
