/**
 * A rejection with a status the client is meant to see.
 *
 * `message` and `details` are sent to the client, so they must be written by
 * the server, never copied from input or from another error. Anything that is
 * not an `HttpError` is a bug and is not turned into a response here; that is
 * left to an error boundary (see `@sanaafshani/warden-ssr-logging`) or the
 * framework, both of which answer with an opaque 500.
 */
export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly headers: Readonly<Record<string, string>>;

  constructor(
    status: number,
    code: string,
    message: string,
    options: { details?: unknown; headers?: Record<string, string>; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.details = options.details;
    this.headers = options.headers ?? {};
  }

  toResponse(): Response {
    const body: { code: string; message: string; details?: unknown } = {
      code: this.code,
      message: this.message,
    };
    if (this.details !== undefined) body.details = this.details;
    return Response.json(
      { error: body },
      { status: this.status, headers: { 'cache-control': 'no-store', ...this.headers } },
    );
  }
}
