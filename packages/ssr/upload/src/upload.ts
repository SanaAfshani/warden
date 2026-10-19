import {
  defineDecorator,
  emit,
  HttpError,
  randomToken,
  readBytes,
  type Decorator,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

interface Signature {
  mime: string;
  extensions: readonly string[];
  bytes: readonly number[];
  offset?: number;
  /** Container formats carry a second marker. */
  then?: { bytes: readonly number[]; offset: number };
}

const SIGNATURES: readonly Signature[] = [
  { mime: 'image/png', extensions: ['png'], bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { mime: 'image/jpeg', extensions: ['jpg', 'jpeg'], bytes: [0xff, 0xd8, 0xff] },
  { mime: 'image/webp', extensions: ['webp'], bytes: [0x52, 0x49, 0x46, 0x46], then: { bytes: [0x57, 0x45, 0x42, 0x50], offset: 8 } },
  { mime: 'image/gif', extensions: ['gif'], bytes: [0x47, 0x49, 0x46, 0x38] },
  { mime: 'application/pdf', extensions: ['pdf'], bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
];

/**
 * Types the bytes can prove. SVG is deliberately absent: it is an XML
 * document that can carry script, i.e. stored XSS that looks like an image.
 */
export type UploadType = 'image/png' | 'image/jpeg' | 'image/webp' | 'image/gif' | 'application/pdf';

export function detectFileType(bytes: Uint8Array): { mime: UploadType; extensions: readonly string[] } | null {
  const at = (expected: readonly number[], offset: number) =>
    bytes.length >= offset + expected.length && expected.every((b, i) => bytes[offset + i] === b);
  const match = SIGNATURES.find((s) => at(s.bytes, s.offset ?? 0) && (!s.then || at(s.then.bytes, s.then.offset)));
  return match ? { mime: match.mime as UploadType, extensions: match.extensions } : null;
}

// Only the first 8 KB: a full scan of every upload is CPU an attacker can spend cheaply.
const SCRIPT_MARKERS = ['<script', '<?php', '<%', 'javascript:', 'onerror=', 'onload=', '<svg', '<iframe', '#!/'];

export function containsScriptMarkers(bytes: Uint8Array): boolean {
  const text = new TextDecoder('latin1').decode(bytes.subarray(0, 8192)).toLowerCase();
  return SCRIPT_MARKERS.some((marker) => text.includes(marker));
}

export interface UploadRules {
  /** Default PNG, JPEG, WebP, PDF. */
  allowedTypes?: readonly UploadType[];
  /** Default 5 MB. */
  maxBytes?: number;
}

export type UploadRejection = 'empty' | 'too_large' | 'type_not_allowed' | 'content_mismatch' | 'embedded_script';

export interface VerifiedUpload {
  bytes: Uint8Array;
  mime: UploadType;
  extension: string;
  /** Random; the only name that may reach a storage key or path. */
  storageName: string;
  /** The client's name made safe to display. Never a path. */
  displayName: string;
}

/**
 * Client claims (name, MIME) must agree with what the bytes prove; a
 * mismatch is someone trying something, so it is rejected even when the real
 * type is allowed. This is the weaker half of upload security; the stronger
 * half is architectural: store outside the web root, serve from a separate
 * cookieless origin with `Content-Disposition: attachment`, re-encode images.
 */
export function checkUpload(
  input: { bytes: Uint8Array; filename: string; mime: string },
  rules: UploadRules = {},
): { ok: true; upload: VerifiedUpload } | { ok: false; reason: UploadRejection } {
  const allowed: readonly string[] = rules.allowedTypes ?? ['image/png', 'image/jpeg', 'image/webp', 'application/pdf'];
  if (input.bytes.length === 0) return { ok: false, reason: 'empty' };
  if (input.bytes.length > (rules.maxBytes ?? 5 * 1024 * 1024)) return { ok: false, reason: 'too_large' };

  const detected = detectFileType(input.bytes);
  if (!detected || !allowed.includes(detected.mime)) return { ok: false, reason: 'type_not_allowed' };
  const claimed = input.mime.toLowerCase() === 'image/jpg' ? 'image/jpeg' : input.mime.toLowerCase();
  const extension = /\.([a-z0-9]{1,8})$/i.exec(input.filename)?.[1]?.toLowerCase();
  if (claimed !== detected.mime || !extension || !detected.extensions.includes(extension)) {
    return { ok: false, reason: 'content_mismatch' };
  }
  if (containsScriptMarkers(input.bytes)) return { ok: false, reason: 'embedded_script' };

  return {
    ok: true,
    upload: {
      bytes: input.bytes,
      mime: detected.mime,
      extension,
      storageName: `${randomToken(16)}.${extension}`,
      displayName: displayName(input.filename),
    },
  };
}

/** Drops paths, control and bidi characters (`exe\u202Egnp.` renders as `.png`). */
export function displayName(filename: string): string {
  const base = filename.normalize('NFC').split(/[/\\]/).pop() ?? '';
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  const clean = base.replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/gu, '').trim();
  return (clean.replace(/^\.+/, '') || 'file').slice(0, 255);
}

export interface UploadOptions extends UploadRules {
  /** Form field holding the file. Default `file`. */
  field?: string;
  onEvent?: SecurityEventHandler;
}

/** Reads a capped multipart body, verifies one file, and hands `upload` inward. */
export function upload(options: UploadOptions = {}): Decorator<object, { upload: VerifiedUpload }> {
  const maxBytes = options.maxBytes ?? 5 * 1024 * 1024;
  return defineDecorator<object, { upload: VerifiedUpload }>('upload', async (request, _context, next) => {
    // Multipart framing adds a little; the file itself is checked against maxBytes below.
    const body = await readBytes(request, maxBytes + 64 * 1024);
    let file: FormDataEntryValue | null;
    try {
      const form = await new Response(body, {
        headers: { 'content-type': request.headers.get('content-type') ?? '' },
      }).formData();
      file = form.get(options.field ?? 'file');
    } catch {
      throw new HttpError(415, 'unsupported_media_type', 'Expected multipart form data.');
    }
    if (!(file instanceof File)) throw new HttpError(400, 'bad_request', 'No file was uploaded.');
    const result = checkUpload(
      { bytes: new Uint8Array(await file.arrayBuffer()), filename: file.name, mime: file.type },
      options,
    );
    if (!result.ok) {
      emit(options.onEvent, { type: 'upload.rejected', outcome: 'blocked', reason: result.reason, request });
      throw new HttpError(result.reason === 'too_large' ? 413 : 422, 'upload_rejected', 'The file was not accepted.', {
        details: { reason: result.reason },
      });
    }
    return next({ upload: result.upload });
  });
}
