/**
 * ============================================================================
 * no-dom-html-sink
 * ============================================================================
 *
 * Ban the DOM sinks that turn a string into executable markup:
 * `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`.
 *
 * ---------------------------------------------------------------------------
 * Why these four, and why an allowlist of "safe" strings is not enough
 * ---------------------------------------------------------------------------
 * The usual defence is "we only assign strings we built ourselves". That fails
 * because of MUTATION XSS: the browser's HTML parser REWRITES markup during the
 * assignment, so a string that is provably clean before it is assigned can be
 * executable after. Payloads in the `<svg><style>` and `<math><mtext>` families
 * defeat every regex-based cleaner ever written.
 *
 * So the rule does not try to judge the string. It bans the sink.
 *
 * ---------------------------------------------------------------------------
 * What to use instead, in order of preference
 * ---------------------------------------------------------------------------
 *  1. `textContent` — if the value is TEXT, this is correct, free, and immune.
 *     Most uses of innerHTML are actually this one, written in a hurry.
 *  2. `element.append(node)` — building DOM nodes cannot inject markup at all.
 *  3. `sanitizeHtml(dirty)` — when it genuinely has to be markup.
 *
 * ---------------------------------------------------------------------------
 * And the deeper point
 * ---------------------------------------------------------------------------
 * This rule covers code you wrote. Trusted Types covers the code you did not —
 * every dependency, every future teammate — by making the browser itself throw
 * on these same sinks. The two are complementary, and neither replaces the
 * other: a lint rule cannot see into `node_modules`, and Trusted Types is not
 * supported in every browser yet.
 */

import type { Node } from 'estree';
import { createRule, docs, memberPath, lastSegment, type WardenRule } from '../shared.js';

const ASSIGNMENT_SINKS = new Set(['innerHTML', 'outerHTML']);
const CALL_SINKS = new Set(['insertAdjacentHTML', 'write', 'writeln']);

export const noDomHtmlSink: WardenRule = createRule(
  {
    type: 'problem',
    docs: {
      description:
        'Disallow assigning strings to innerHTML/outerHTML and calling insertAdjacentHTML or document.write.',
      url: docs('no-dom-html-sink'),
      /**
       * Mutation XSS: the parser rewrites markup as it assigns, so sanitising
       * beforehand is not sufficient and no runtime wrapper of ours can make
       * the sink safe. The known false positive — `obj.innerHTML` on a plain
       * object — costs one disable line; the false negative is an XSS.
       */
      tier: 'required',
    },
    schema: [],
    messages: {
      assignment:
        'Assigning to `{{sink}}` parses the string as markup, and the browser REWRITES it while parsing — so a string that looks clean can still execute (mutation XSS). Use `textContent` for text, `append()` for nodes, or `sanitizeHtml()` when it must be markup.',
      call:
        '`{{sink}}` parses its argument as markup, with the same mutation-XSS problem as innerHTML. Build nodes and `append()` them, or sanitise first.',
    },
  },
  (context) => ({
    AssignmentExpression(node) {
      const left = node.left as Node;
      if (left.type !== 'MemberExpression') return;
      const member = left;
      if (member.computed) return;
      if (member.property.type !== 'Identifier') return;
      const sink = member.property.name;
      if (!ASSIGNMENT_SINKS.has(sink)) return;
      context.report({ node, messageId: 'assignment', data: { sink } });
    },

    CallExpression(node) {
      const path = memberPath(node.callee);
      if (path === null) return;
      const name = lastSegment(path);
      if (!CALL_SINKS.has(name)) return;

      // `write`/`writeln` are common method names. Only report them on
      // something that reads as a document, otherwise every logger in the
      // codebase lights up and the rule gets turned off.
      if ((name === 'write' || name === 'writeln') && !/(^|\.)document\.(write|writeln)$/.test(path)) {
        return;
      }
      context.report({ node, messageId: 'call', data: { sink: path } });
    },
  }),
);
