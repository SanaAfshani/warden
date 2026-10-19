import { describe, expect, expectTypeOf, it } from 'vitest';
import { chain, defineDecorator, HttpError, type BaseContext } from '../src/index.js';

const user = defineDecorator<object, { user: { id: string } }>('user', (_request, _context, next) =>
  next({ user: { id: 'u1' } }),
);

const needsUser = defineDecorator<{ user: { id: string } }>('needs-user', (_request, context, next) =>
  context.user.id ? next() : Promise.reject(new HttpError(403, 'forbidden', 'Forbidden.')),
);

const trace = (log: string[], name: string) =>
  defineDecorator(name, async (_request, _context, next) => {
    log.push(`${name}:in`);
    const response = await next();
    log.push(`${name}:out`);
    return response;
  });

const request = () => new Request('https://app.test/x');

describe('chain', () => {
  it('runs decorators in .use() order, first is outermost', async () => {
    const log: string[] = [];
    const handler = chain()
      .use(trace(log, 'a'))
      .use(trace(log, 'b'))
      .handle(() => {
        log.push('handler');
        return new Response('ok');
      });
    await handler(request());
    expect(log).toEqual(['a:in', 'b:in', 'handler', 'b:out', 'a:out']);
  });

  it('accumulates context and keeps what outer decorators added', async () => {
    const handler = chain()
      .use(user)
      .use(needsUser)
      .handle((_request, context) => {
        expectTypeOf(context).toEqualTypeOf<{
          readonly params: BaseContext['params'];
          user: { id: string };
        }>();
        return Response.json({ id: context.user.id, params: context.params });
      });
    const response = await handler(request(), { params: Promise.resolve({ slug: 'x' }) });
    expect(await response.json()).toEqual({ id: 'u1', params: { slug: 'x' } });
  });

  it('rejects at compile time when a decorator needs context nobody added', () => {
    // @ts-expect-error `needs-user` requires `user`, which no outer decorator provides.
    chain().use(needsUser);
  });

  it('turns an HttpError into a response that outer decorators still see', async () => {
    const seen: number[] = [];
    const observe = defineDecorator('observe', async (_request, _context, next) => {
      const response = await next();
      seen.push(response.status);
      return response;
    });
    const handler = chain()
      .use(observe)
      .handle(() => {
        throw new HttpError(409, 'conflict', 'Already exists.');
      });
    const response = await handler(request());
    expect(response.status).toBe(409);
    expect(seen).toEqual([409]);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({ error: { code: 'conflict', message: 'Already exists.' } });
  });

  it('lets non-HttpError failures propagate instead of guessing a response', async () => {
    const handler = chain().handle(() => {
      throw new Error('bug');
    });
    await expect(handler(request())).rejects.toThrow('bug');
  });

  it('is immutable, so a base chain can be shared', async () => {
    const log: string[] = [];
    const base = chain().use(trace(log, 'base'));
    base.use(trace(log, 'extra'));
    await base.handle(() => new Response(null))(request());
    expect(log).toEqual(['base:in', 'base:out']);
  });
});
