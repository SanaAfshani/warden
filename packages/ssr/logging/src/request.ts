import { defineDecorator, randomBytes, withHeaders, type Decorator } from '@wardenjs/ssr';
import type { Logger } from './logger.js';

export interface RequestLoggerOptions {
  /** Default 'request'. Set to false to log only failures. */
  message?: string | false;
}

/**
 * One line per request, a request id on every response, and the error
 * boundary: an unexpected error is logged with its stack and answered with an
 * opaque 500 carrying only the id, so support can find the line and the client
 * learns nothing about the internals. Place it outside everything that can throw.
 */
export function requestLogger(
  logger: Logger,
  options: RequestLoggerOptions = {},
): Decorator<object, { log: Logger; requestId: string }> {
  return defineDecorator<object, { log: Logger; requestId: string }>(
    'requestLogger',
    async (request, _context, next) => {
      const requestId = Array.from(randomBytes(8), (b) => b.toString(16).padStart(2, '0')).join('');
      const log = logger.child({ requestId });
      const started = Date.now();
      const fields = { method: request.method, path: new URL(request.url).pathname };
      let response: Response;
      try {
        response = await next({ log, requestId });
      } catch (error) {
        log.error('request.failed', { ...fields, error, durationMs: Date.now() - started });
        response = Response.json(
          { error: { code: 'internal_error', message: 'The request could not be completed.', requestId } },
          { status: 500, headers: { 'cache-control': 'no-store' } },
        );
      }
      if (options.message !== false) {
        log.info(options.message ?? 'request', { ...fields, status: response.status, durationMs: Date.now() - started });
      }
      return withHeaders(response, { 'X-Request-Id': requestId });
    },
  );
}
