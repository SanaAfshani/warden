import {
  defineDecorator,
  emit,
  fromBase64Url,
  HttpError,
  readBytes,
  type Decorator,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

export interface VerifyWebhookInput {
  /** The secret the provider gave you, used as-is (no derivation). */
  secret: string;
  /** The exact bytes received. Parse-then-stringify changes them and the HMAC never matches. */
  rawBody: string | Uint8Array;
  /** Hex or base64, optionally prefixed `sha256=`. */
  signature: string | null;
  /** Unix seconds. When given it is part of the signed message (`<t>.<body>`), as Stripe does. */
  timestamp?: number;
  /** Default 300 s, in both directions. */
  toleranceSeconds?: number;
}

export type WebhookVerdict =
  | { valid: true }
  | { valid: false; reason: 'missing_signature' | 'bad_signature' | 'stale' };

/**
 * HMAC-SHA256 over the raw body with the raw shared secret: the scheme
 * GitHub, Stripe, Shopify and most others use. Without a timestamp a captured
 * webhook can be replayed forever; check one whenever the provider sends it.
 */
export async function verifyWebhook(input: VerifyWebhookInput): Promise<WebhookVerdict> {
  if (!input.signature) return { valid: false, reason: 'missing_signature' };
  if (input.timestamp !== undefined) {
    const skew = Math.abs(Math.floor(Date.now() / 1000) - input.timestamp);
    if (!Number.isFinite(skew) || skew > (input.toleranceSeconds ?? 300)) return { valid: false, reason: 'stale' };
  }
  const provided = decodeSignature(input.signature.replace(/^sha256=/i, '').trim());
  if (!provided || !input.secret) return { valid: false, reason: 'bad_signature' };
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(input.secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const body = typeof input.rawBody === 'string' ? new TextEncoder().encode(input.rawBody) : input.rawBody;
  const prefix = new TextEncoder().encode(input.timestamp === undefined ? '' : `${input.timestamp}.`);
  const message = new Uint8Array(prefix.length + body.length);
  message.set(prefix);
  message.set(body, prefix.length);
  const ok = await crypto.subtle.verify('HMAC', key, provided, message);
  return ok ? { valid: true } : { valid: false, reason: 'bad_signature' };
}

function decodeSignature(value: string): Uint8Array<ArrayBuffer> | null {
  if (/^[0-9a-f]{64}$/i.test(value)) {
    return Uint8Array.from({ length: 32 }, (_, i) => parseInt(value.slice(i * 2, i * 2 + 2), 16));
  }
  try {
    return fromBase64Url(value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  } catch {
    return null;
  }
}

export interface WebhookOptions {
  secret: string;
  /** e.g. `x-hub-signature-256`. */
  signatureHeader: string;
  /** Header with unix seconds, when the provider sends one. */
  timestampHeader?: string;
  /** Default 1 MB. */
  maxBytes?: number;
  toleranceSeconds?: number;
  onEvent?: SecurityEventHandler;
}

/** Reads the capped raw body, verifies it, and hands the verified text inward. Parse only after this. */
export function webhook(options: WebhookOptions): Decorator<object, { rawBody: string }> {
  return defineDecorator<object, { rawBody: string }>('webhook', async (request, _context, next) => {
    const bytes = await readBytes(request, options.maxBytes ?? 1024 * 1024);
    const timestamp = options.timestampHeader ? Number(request.headers.get(options.timestampHeader)) : undefined;
    const verdict = await verifyWebhook({
      secret: options.secret,
      rawBody: bytes,
      signature: request.headers.get(options.signatureHeader),
      ...(timestamp === undefined ? {} : { timestamp }),
      ...(options.toleranceSeconds === undefined ? {} : { toleranceSeconds: options.toleranceSeconds }),
    });
    if (!verdict.valid) {
      emit(options.onEvent, { type: 'webhook.rejected', outcome: 'blocked', reason: verdict.reason, request });
      throw new HttpError(401, 'invalid_signature', 'Signature verification failed.');
    }
    return next({ rawBody: new TextDecoder().decode(bytes) });
  });
}
