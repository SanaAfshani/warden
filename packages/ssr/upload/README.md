# @sanaafshani/warden-ssr-upload

File upload checks by content, not by what the client claims.

```bash
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-upload
```

```ts
import { upload } from '@sanaafshani/warden-ssr-upload';

export const POST = chain()
  .use(session.required())
  .use(upload({ allowedTypes: ['image/png', 'image/jpeg'], maxBytes: 2 * 1024 * 1024 }))
  .handle(async (_r, { upload }) => {
    await storage.put(upload.storageName, upload.bytes, { contentType: upload.mime });
    return Response.json({ name: upload.displayName });
  });
```

- Type from magic bytes (PNG, JPEG, WebP, GIF, PDF). Claimed MIME and
  extension must agree with it.
- No SVG: it is a document that runs script.
- Polyglots with script markers are rejected.
- `storageName` is random; `displayName` has paths, control and bidi
  characters removed.
- Capped multipart read; 413 or 422 `upload_rejected`.
- `checkUpload` for files that arrive some other way.

The stronger half is architectural: store outside the web root, serve from a
separate cookieless origin with `Content-Disposition: attachment`, re-encode
images.
