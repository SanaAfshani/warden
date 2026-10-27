# @sanaafshani/warden-csr-sanitize

> Part of [warden](https://github.com/SanaAfshani/warden)'s **browser track**: security controls for code that runs in the
> browser. Here *CSR* means *client side*, not client-side rendering. Nothing here is a trust
> boundary; the server track enforces.

Rendering untrusted content: HTML sanitising, Trusted Types, and escaping
for each sink.

```bash
npm i @sanaafshani/warden-csr-sanitize dompurify   # dompurify only if you sanitise HTML
```

```tsx
import { installTrustedTypes, preloadSanitizer, safeUrl } from '@sanaafshani/warden-csr-sanitize';
import { SafeHtml } from '@sanaafshani/warden-csr-sanitize/react';

await preloadSanitizer();   // at startup: sync rendering, no flash
installTrustedTypes();      // with CSP require-trusted-types-for 'script'

<SafeHtml html={comment.body} allowLinks />
<a href={safeUrl(user.website) ?? '#'}>site</a>
```

| Sink | Use |
| --- | --- |
| Markup | `sanitizeHtml` / `<SafeHtml>`: DOMPurify in a private instance, strict allowlist, no `data-*`, links get `rel="noopener noreferrer nofollow"` |
| Text node, quoted attribute | `escapeHtml` |
| `href`, `src` | `safeUrl`: http, https, mailto, tel, relative; rejects `javascript:`, `//host`, `/\host`, credentials |
| JSON inside `<script>` | `escapeJsonForHtml` |
| CSV export | `safeCsvCell` (no spreadsheet formulas) |
| Logs, subjects, headers | `singleLineText` |
| Comparisons | `normaliseText` (NFC, invisible and bidi characters removed) |

Without DOMPurify installed, `sanitizeHtml` throws and `<SafeHtml>` renders
nothing: a sanitiser that fails open is worse than none.
