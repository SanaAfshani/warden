import { HttpError, readBytes } from '@sanaafshani/warden-ssr';

export interface JsonLimits {
  /** Default 100 KB. */
  maxBytes?: number;
  /** Default 12. 40 KB of `[[[[…]]]]` parses fine and then blows the stack of whatever walks it. */
  maxDepth?: number;
  /** Total keys and array elements. Default 500. */
  maxKeys?: number;
}

const badRequest = (message: string) => new HttpError(400, 'bad_request', message);

function requireContentType(request: Request, expected: string): void {
  const actual = (request.headers.get('content-type') ?? '').toLowerCase();
  if (!actual.startsWith(expected)) {
    throw new HttpError(415, 'unsupported_media_type', `Content-Type must be ${expected}.`);
  }
}

/**
 * Requiring `application/json` also blocks plain cross-site `<form>` posts:
 * forms can only send simple content types, so anything else must pass a
 * CORS preflight.
 */
export async function readJson(request: Request, limits: JsonLimits = {}): Promise<unknown> {
  requireContentType(request, 'application/json');
  const text = decode(await readBytes(request, limits.maxBytes ?? 100 * 1024));
  if (text.trim() === '') return {};
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    // Never echo the parser message: it quotes the input.
    throw badRequest('Request body must be valid JSON.');
  }
  checkStructure(value, limits.maxDepth ?? 12, limits.maxKeys ?? 500);
  return value;
}

/** For bodies that must stay raw: webhook signatures, CSP reports. */
export async function readText(
  request: Request,
  options: { maxBytes: number; contentType?: string },
): Promise<string> {
  if (options.contentType) requireContentType(request, options.contentType.toLowerCase());
  return decode(await readBytes(request, options.maxBytes));
}

/** `request.formData()` with a real byte cap and a field cap (multipart allocates per part). */
export async function readForm(
  request: Request,
  options: { maxBytes?: number; maxFields?: number } = {},
): Promise<FormData> {
  const contentType = request.headers.get('content-type') ?? '';
  const bytes = await readBytes(request, options.maxBytes ?? 5 * 1024 * 1024);
  let form: FormData;
  try {
    form = await new Response(bytes, { headers: { 'content-type': contentType } }).formData();
  } catch {
    throw new HttpError(415, 'unsupported_media_type', 'Expected form data.');
  }
  let fields = 0;
  for (const _ of form.keys()) {
    if (++fields > (options.maxFields ?? 50)) throw badRequest('Too many form fields.');
  }
  return form;
}

/**
 * Repeated keys become arrays, so the schema decides. `?limit=10&limit=999999`
 * is parameter pollution: layers disagree on which value wins.
 */
export function searchParamsRecord(url: URL | string): Record<string, string | string[]> {
  const params = new URL(url).searchParams;
  const record: Record<string, string | string[]> = {};
  for (const key of new Set(params.keys())) {
    const values = params.getAll(key);
    record[key] = values.length === 1 ? (values[0] ?? '') : values;
  }
  return record;
}

function decode(bytes: Uint8Array): string {
  try {
    // `fatal`: invalid UTF-8 is rejected rather than silently altered.
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw badRequest('Request body is not valid UTF-8.');
  }
}

function checkStructure(value: unknown, maxDepth: number, maxKeys: number): void {
  let used = 0;
  const walk = (node: unknown, depth: number): void => {
    if (depth > maxDepth) throw badRequest('Request body is nested too deeply.');
    if (node === null || typeof node !== 'object') return;
    const children = Array.isArray(node) ? (node as unknown[]) : Object.values(node);
    used += children.length;
    if (used > maxKeys) throw badRequest('Request body has too many fields.');
    for (const child of children) walk(child, depth + 1);
  };
  walk(value, 0);
}
