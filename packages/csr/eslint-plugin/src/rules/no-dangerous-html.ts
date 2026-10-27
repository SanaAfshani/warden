/**
 * ============================================================================
 * no-dangerous-html
 * ============================================================================
 *
 * Ban `dangerouslySetInnerHTML` in JSX.
 *
 * ---------------------------------------------------------------------------
 * Why a lint rule and not a code review
 * ---------------------------------------------------------------------------
 * React escapes `{value}`, so a React app usually has no XSS at all — right up
 * until one component needs to render rich text from a CMS or a comment box.
 * That component gets reviewed once, carefully, and then never again. The
 * second use is copy-pasted from the first, and the third is written at 6pm.
 *
 * The prop is well named. Naming is not a control: `dangerouslySetInnerHTML`
 * has been in React for a decade and is still the most common source of XSS in
 * React codebases, precisely because a scary name is something you read once
 * and stop seeing.
 *
 * This makes every new use a build failure with a named alternative.
 *
 * ---------------------------------------------------------------------------
 * The escape hatch, and why it is a file and not an option
 * ---------------------------------------------------------------------------
 * Somewhere, exactly one component has to use it — ours is `<SafeHtml>`, which
 * runs DOMPurify on the line above. That file exempts itself with a disable
 * comment carrying a reason, so the exemption is visible in the file that needs
 * it rather than hidden in a config a reviewer never opens.
 */

import type { Rule } from 'eslint';
import { createRule, docs, type WardenRule } from '../shared.js';

export const noDangerousHtml: WardenRule = createRule(
  {
    type: 'problem',
    docs: {
      description:
        'Disallow dangerouslySetInnerHTML; render untrusted markup through a sanitising component instead.',
      url: docs('no-dangerous-html'),
      /**
       * Stored XSS, and the one rule here with no false-positive mode at all:
       * it matches a literal JSX attribute name, so it never fires on anything
       * but the real thing. A rule that costs nothing to keep on and guards an
       * injection class has no honest argument for being downgradeable.
       */
      tier: 'required',
    },
    schema: [
      {
        type: 'object',
        properties: {
          /** The component to recommend in the message. Yours may differ. */
          component: { type: 'string' },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      dangerous:
        'dangerouslySetInnerHTML assigns an unsanitised string to innerHTML — this is the most common XSS in React. Use <{{component}} html={...} />, which runs the sanitiser for you. If this markup is genuinely trusted and static, disable this rule on the line WITH A REASON.',
    },
  },
  (context) => {
    const options = (context.options[0] ?? {}) as { component?: string };
    const component = options.component ?? 'SafeHtml';

    return {
      JSXAttribute(node: Rule.Node) {
        const attribute = node as unknown as { name?: { type?: string; name?: string } };
        if (attribute.name?.type !== 'JSXIdentifier') return;
        if (attribute.name.name !== 'dangerouslySetInnerHTML') return;
        context.report({ node, messageId: 'dangerous', data: { component } });
      },
    };
  },
);
