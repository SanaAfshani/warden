import { createElement, useEffect, useMemo, useState, type ReactNode } from 'react';
import { sanitizeHtml, sanitizeHtmlSync, sanitizerReady, type SanitizeOptions } from './html.js';

export interface SafeHtmlProps extends SanitizeOptions {
  html: string;
  as?: 'div' | 'span' | 'section' | 'article' | 'p';
  className?: string;
  /** Shown while the sanitiser loads, only if `preloadSanitizer()` was not awaited. */
  fallback?: ReactNode;
}

/**
 * The one sanctioned replacement for `dangerouslySetInnerHTML`. Synchronous
 * once the sanitiser is preloaded (no flash). If DOMPurify is missing it
 * renders nothing: a sanitiser that fails open is worse than none.
 */
export function SafeHtml({ html, as = 'div', className, fallback = null, ...options }: SafeHtmlProps): ReactNode {
  const optionsKey = JSON.stringify(options);
  // Keyed on the serialised options: callers pass inline object literals.
  const immediate = useMemo(() => (sanitizerReady() ? sanitizeHtmlSync(html, options) : null), [html, optionsKey]);
  const [late, setLate] = useState<string | null>(null);

  useEffect(() => {
    if (immediate !== null) return;
    let cancelled = false;
    void sanitizeHtml(html, options)
      .catch(() => '')
      .then((clean) => {
        if (!cancelled) setLate(clean);
      });
    return () => {
      cancelled = true;
    };
  }, [html, optionsKey, immediate]);

  const clean = immediate ?? late;
  if (clean === null) return fallback;
  return createElement(as, { ...(className === undefined ? {} : { className }), dangerouslySetInnerHTML: { __html: clean } });
}
