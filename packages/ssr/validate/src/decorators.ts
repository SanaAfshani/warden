import { defineDecorator, type BaseContext, type Decorator } from '@wardenjs/ssr';
import { readJson, searchParamsRecord, type JsonLimits } from './read.js';
import { parse, type Infer, type StandardSchema } from './schema.js';

/** Capped JSON body, validated; the handler gets `body` typed from the schema. */
export function body<S extends StandardSchema>(
  schema: S,
  limits?: JsonLimits,
): Decorator<object, { body: Infer<S> }> {
  return defineDecorator<object, { body: Infer<S> }>('body', async (request, _context, next) =>
    next({ body: await parse(schema, await readJson(request, limits)) }),
  );
}

export function query<S extends StandardSchema>(schema: S): Decorator<object, { query: Infer<S> }> {
  return defineDecorator<object, { query: Infer<S> }>('query', async (request, _context, next) =>
    next({ query: await parse(schema, searchParamsRecord(request.url)) }),
  );
}

/** Route params are input too: `/orders/[id]` matches `/orders/..%2f..%2fadmin`. Replaces `params`. */
export function params<S extends StandardSchema>(
  schema: S,
): Decorator<BaseContext, { params: Infer<S> }> {
  return defineDecorator<BaseContext, { params: Infer<S> }>('params', async (_request, context, next) =>
    next({ params: await parse(schema, context.params) }),
  );
}
