/**
 * ============================================================================
 * no-unsafe-target-blank
 * ============================================================================
 *
 * `target="_blank"` requires `rel="noopener"`.
 *
 * ---------------------------------------------------------------------------
 * Tab-nabbing, in one paragraph
 * ---------------------------------------------------------------------------
 * A link opened with `target="_blank"` hands the opened page a live
 * `window.opener` reference back to YOUR tab. That page can then set
 * `opener.location` to a pixel-perfect copy of your login screen. The user
 * finishes reading the new tab, switches back, finds a session-expired prompt
 * that looks exactly right, and types their password into someone else's site.
 *
 * `rel="noopener"` severs the reference. `noreferrer` additionally stops your
 * current URL — which may carry a token or an id — leaking in the `Referer`
 * header of the outbound request.
 *
 * ---------------------------------------------------------------------------
 * "Modern browsers do this by default"
 * ---------------------------------------------------------------------------
 * True, and not sufficient. The implicit `noopener` applies to `target="_blank"`
 * on anchors in current browsers; it does not apply to `window.open()`, and it
 * does not apply in older or embedded webviews — which is where a lot of real
 * traffic lives. It also does nothing about `Referer` leakage, which is the
 * half of this that browsers did not change.
 *
 * The fix is free. Relying on a default you cannot verify per-visitor is not.
 */

import type { Rule } from 'eslint';
import type { Node } from 'estree';
import { createRule, docs, isStaticString, type WardenRule } from '../shared.js';

interface JsxAttributeLike {
  type: string;
  name?: { type?: string; name?: string };
  value?: { type?: string; value?: unknown; expression?: Node };
}

/** The string value of a JSX attribute, or null when it is not statically a string. */
function readStaticString(value: JsxAttributeLike['value']): string | null {
  if (value?.type === 'Literal') {
    return typeof value.value === 'string' ? value.value : null;
  }
  if (value?.type === 'JSXExpressionContainer' && isStaticString(value.expression)) {
    const inner = value.expression as { value?: unknown };
    return typeof inner.value === 'string' ? inner.value : null;
  }
  return null;
}

export const noUnsafeTargetBlank: WardenRule = createRule(
  {
    type: 'problem',
    docs: {
      description: 'Require rel="noopener noreferrer" on links with target="_blank".',
      url: docs('no-unsafe-target-blank'),
      /**
       * Tab-nabbing needs the user to return to a tab they left, and every
       * current browser already implies `noopener` for `target="_blank"` — so
       * this hardens old browsers and in-app webviews rather than closing a
       * live hole on its own.
       *
       * `recommended` is therefore the honest tier, even though the autofix
       * makes it free to keep on. Tempting to call it `required` for that
       * reason, but cheapness is not severity, and that is the same conflation
       * the tiers exist to prevent.
       */
      tier: 'recommended',
    },
    schema: [],
    fixable: 'code',
    messages: {
      missing:
        'target="_blank" gives the opened page a live `window.opener` handle to THIS tab, which it can use to replace your page with a phishing copy while the user is looking away (tab-nabbing). Add rel="noopener noreferrer".',
    },
  },
  (context) => ({
    JSXOpeningElement(node: Rule.Node) {
      const element = node as unknown as { attributes?: JsxAttributeLike[] };
      const attributes = element.attributes ?? [];

      const find = (name: string): JsxAttributeLike | undefined =>
        attributes.find((a) => a.type === 'JSXAttribute' && a.name?.name === name);

      const target = find('target');
      if (!target) return;

      // Only a literal `_blank` is decidable here. A dynamic target is rare and
      // reporting it would be a guess.
      const targetValue = target.value;
      const isBlank =
        targetValue?.type === 'Literal'
          ? targetValue.value === '_blank'
          : targetValue?.type === 'JSXExpressionContainer' &&
            isStaticString(targetValue.expression) &&
            (targetValue.expression as { value?: unknown }).value === '_blank';
      if (!isBlank) return;

      const rel = find('rel');
      if (rel) {
        const relValue = rel.value;
        // Only a genuine string is readable here. `rel={true}` or a JSX node
        // is not something to coerce — `String(...)` on an object yields
        // "[object Object]", which would then silently fail the noopener test
        // for a reason nobody could work out from the message.
        const text = readStaticString(relValue);
        // A dynamic rel cannot be read statically. Treated as satisfied: the
        // author clearly thought about rel, and a false positive here trains
        // people to disable the rule.
        if (text === null) return;
        if (/\bnoopener\b/.test(text)) return;
      }

      context.report({
        node,
        messageId: 'missing',
        fix(fixer) {
          if (rel) return null;   // amending an existing rel is the author's call
          return fixer.insertTextAfter(target, ' rel="noopener noreferrer"');
        },
      });
    },
  }),
);
