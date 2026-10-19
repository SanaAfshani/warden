import { describe, expect, it } from 'vitest';
import { chain } from '@sanaafshani/warden-ssr';
import { checkUpload, displayName, upload } from '../src/index.js';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
const GIF = new TextEncoder().encode('GIF89a......');
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

describe('checkUpload', () => {
  it('accepts a file whose bytes, MIME and extension agree, and renames it', () => {
    const result = checkUpload({ bytes: PNG, filename: 'cat.png', mime: 'image/png' });
    expect(result.ok && result.upload.storageName).toMatch(/^[\w-]+\.png$/);
  });

  it('rejects SVG: it is a document that runs script, not an image', () => {
    expect(checkUpload({ bytes: SVG, filename: 'a.svg', mime: 'image/svg+xml' })).toEqual({ ok: false, reason: 'type_not_allowed' });
  });

  it('rejects a mismatch between what the client claims and what the bytes prove', () => {
    expect(checkUpload({ bytes: PNG, filename: 'cat.html', mime: 'image/png' })).toEqual({ ok: false, reason: 'content_mismatch' });
    expect(checkUpload({ bytes: PNG, filename: 'cat.png', mime: 'text/html' })).toEqual({ ok: false, reason: 'content_mismatch' });
  });

  it('rejects polyglots: a valid PNG header followed by markup', () => {
    const polyglot = concat(PNG, new TextEncoder().encode('<script>alert(1)</script>'));
    expect(checkUpload({ bytes: polyglot, filename: 'a.png', mime: 'image/png' })).toEqual({ ok: false, reason: 'embedded_script' });
  });

  it('allows GIF only when configured', () => {
    expect(checkUpload({ bytes: GIF, filename: 'a.gif', mime: 'image/gif' }).ok).toBe(false);
    expect(checkUpload({ bytes: GIF, filename: 'a.gif', mime: 'image/gif' }, { allowedTypes: ['image/gif'] }).ok).toBe(true);
  });
});

describe('displayName', () => {
  it('drops paths and bidi overrides that disguise the extension', () => {
    expect(displayName('../../etc/passwd')).toBe('passwd');
    expect(displayName('invoice\u202Efdp.exe')).toBe('invoicefdp.exe');
  });
});

describe('upload decorator', () => {
  it('hands the verified file inward and rejects the rest with 422', async () => {
    const handler = chain()
      .use(upload())
      .handle((_r, c) => new Response(c.upload.mime));
    const send = (file: File) => {
      const form = new FormData();
      form.set('file', file);
      return handler(new Request('https://a.test/upload', { method: 'POST', body: form }));
    };
    expect(await (await send(new File([PNG], 'a.png', { type: 'image/png' }))).text()).toBe('image/png');
    expect((await send(new File([SVG], 'a.svg', { type: 'image/svg+xml' }))).status).toBe(422);
  });
});
