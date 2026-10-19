export interface SanitizeOptions {
  /** Allow `<a href>`; every link gets `target=_blank rel="noopener noreferrer nofollow"`. */
  allowLinks?: boolean;
  /** Allow `<img>`. Off by default: an image in user content is also a tracking pixel. */
  allowImages?: boolean;
  extraTags?: readonly string[];
  extraAttributes?: readonly string[];
}

interface Purifier {
  sanitize(dirty: string, config: Record<string, unknown>): string;
  addHook(name: 'afterSanitizeAttributes', hook: (node: Element) => void): void;
}
type PurifierFactory = Purifier & ((root: Window) => Purifier);

const BASE_TAGS = [
  'p', 'br', 'hr', 'strong', 'b', 'em', 'i', 'u', 's', 'sub', 'sup', 'ul', 'ol', 'li', 'blockquote',
  'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span', 'div', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
];

let purifier: Purifier | null = null;

/**
 * Loads DOMPurify (optional peer: one package, no dependencies in a browser)
 * into a private instance, so the link hook below does not change behaviour
 * for other libraries on the page. Call at startup to make the sync path and
 * Trusted Types usable.
 */
export async function preloadSanitizer(): Promise<void> {
  if (purifier) return;
  let factory: PurifierFactory;
  try {
    factory = ((await import('dompurify')) as unknown as { default: PurifierFactory }).default;
  } catch {
    throw new Error('sanitizeHtml needs the `dompurify` package: npm i dompurify. For plain text use escapeHtml().');
  }
  const instance = factory(globalThis as unknown as Window);
  // Tab-nabbing: an opened page can rewrite `window.opener.location`.
  instance.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A' && node.hasAttribute('href')) {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer nofollow');
    }
  });
  purifier = instance;
}

export const sanitizerReady = (): boolean => purifier !== null;

function config(options: SanitizeOptions): Record<string, unknown> {
  const tags = [...BASE_TAGS, ...(options.extraTags ?? [])];
  const attrs = ['class', 'title', ...(options.extraAttributes ?? [])];
  if (options.allowLinks) {
    tags.push('a');
    attrs.push('href', 'target', 'rel');
  }
  if (options.allowImages) {
    tags.push('img');
    attrs.push('src', 'alt', 'width', 'height', 'loading');
  }
  return {
    ALLOWED_TAGS: tags,
    ALLOWED_ATTR: attrs,
    // The tag being allowed says nothing about `href="javascript:…"`.
    ALLOWED_URI_REGEXP: /^(?:https?:|mailto:|tel:|#|\/(?![/\\])|\.\.?\/)/i,
    // Never, even if the allowlist is widened later.
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'template', 'svg', 'math'],
    FORBID_ATTR: ['style', 'srcset', 'formaction', 'form', 'ping'],
    // Angular, Alpine and htmx read data-* as instructions.
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    KEEP_CONTENT: true,
  };
}

/**
 * Untrusted markup that must render as markup. Hand-written cleaners lose to
 * mutation XSS (the parser rewrites "clean" strings); DOMPurify tracks those
 * quirks. For text, escaping is correct and free: see `escapeHtml`.
 */
export async function sanitizeHtml(dirty: string, options: SanitizeOptions = {}): Promise<string> {
  await preloadSanitizer();
  return sanitizeHtmlSync(dirty, options);
}

/** Requires `preloadSanitizer()` first. Exists because Trusted Types policies cannot await. */
export function sanitizeHtmlSync(dirty: string, options: SanitizeOptions = {}): string {
  if (!purifier) throw new Error('sanitizeHtmlSync() before preloadSanitizer() resolved.');
  return purifier.sanitize(dirty, config(options));
}

export interface TrustedTypesPolicy {
  readonly supported: boolean;
  createHTML(input: string): string;
}

interface TrustedTypesGlobal {
  trustedTypes?: {
    createPolicy(name: string, rules: { createHTML: (s: string) => string }): { createHTML(s: string): unknown };
    defaultPolicy?: unknown;
  };
}

let policy: TrustedTypesPolicy | null = null;

/**
 * With CSP `require-trusted-types-for 'script'`, every HTML sink throws on a
 * plain string, so this policy becomes the only path from string to DOM, and
 * it sanitises. Roll out report-only first: each break is a sink you did not
 * know about. Chromium only; elsewhere the returned shim still sanitises.
 * `installDefault` also covers third-party code that knows nothing of policies.
 */
export function installTrustedTypes(
  options: { policyName?: string; installDefault?: boolean; sanitizer?: (input: string) => string } = {},
): TrustedTypesPolicy {
  if (policy) return policy;
  const clean = options.sanitizer ?? ((input: string) => sanitizeHtmlSync(input));
  const tt = (globalThis as TrustedTypesGlobal).trustedTypes;
  if (!tt) return (policy = { supported: false, createHTML: clean });
  const named = tt.createPolicy(options.policyName ?? 'warden-security', { createHTML: clean });
  if (options.installDefault && !tt.defaultPolicy) tt.createPolicy('default', { createHTML: clean });
  return (policy = { supported: true, createHTML: (input) => named.createHTML(input) as string });
}
