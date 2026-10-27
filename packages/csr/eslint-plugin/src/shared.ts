/**
 * ============================================================================
 * Shared helpers
 * ============================================================================
 *
 * ---------------------------------------------------------------------------
 * Why these rules do NOT use type information
 * ---------------------------------------------------------------------------
 * typescript-eslint's type-aware rules are more precise and several times
 * slower, and they only run where a tsconfig covers the file. These rules are
 * deliberately syntax-only so they work in a plain JavaScript project, in a
 * `.mjs` build script, and in a file nobody remembered to add to `include` —
 * which is exactly the file where the mistake will be.
 *
 * The cost is that a rule cannot tell `el.innerHTML` on a DOM element from
 * `obj.innerHTML` on a plain object. That trade is accepted on purpose: the
 * false positive is one line of `eslint-disable` with a reason next to it, and
 * the false NEGATIVE is a cross-site scripting vulnerability.
 */

import type { Rule } from 'eslint';
import type { Node } from 'estree';
import type { Tier } from './severity.js';

export const REPO = 'https://github.com/SanaAfshani/warden';

export function docs(name: string): string {
  return `${REPO}/blob/main/packages/csr/eslint-plugin/README.md#${name}`;
}

/**
 * The dotted source text of a member expression, e.g. `window.localStorage`.
 *
 * Returns null for anything computed (`a[b]`), because a computed access is not
 * something a syntax-only rule can resolve, and guessing would produce exactly
 * the confident-but-wrong report that makes teams disable a rule.
 */
export function memberPath(node: Node): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    if (node.computed) return null;
    const object = memberPath(node.object);
    if (object === null) return null;
    const property = node.property.type === 'Identifier' ? node.property.name : null;
    if (property === null) return null;
    return `${object}.${property}`;
  }
  return null;
}

/** The last segment of a member path: `window.localStorage` -> `localStorage`. */
export function lastSegment(path: string): string {
  const parts = path.split('.');
  return parts[parts.length - 1] ?? path;
}

/**
 * Is this expression a value we can see is constant?
 *
 * A string literal, or a template literal with no interpolation. Anything else
 * — a variable, a call, a conditional — is treated as untrusted, because a
 * syntax-only rule cannot follow it and the safe assumption is the pessimistic
 * one.
 */
export function isStaticString(node: Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'Literal') return typeof node.value === 'string';
  if (node.type === 'TemplateLiteral') return node.expressions.length === 0;
  return false;
}

/** Name of the function being called, dotted. `safeUrl`, `utils.safeUrl`. */
export function calleeName(node: Node): string | null {
  if (node.type !== 'CallExpression') return null;
  return memberPath(node.callee);
}

type EslintRuleMeta = NonNullable<Rule.RuleModule['meta']>;

/**
 * Our `meta`, with `docs` mandatory and carrying a {@link Tier}.
 *
 * ESLint 10 types `meta.docs` as `RulesMetaDocs & ExtRuleDocs` precisely so a
 * plugin can add its own fields, but `Rule.RuleModule` pins `ExtRuleDocs` to
 * `{}`. Widening it here is what lets `tier` be a compile error when missing
 * rather than a convention someone forgets on the sixth rule.
 */
export type WardenRuleMeta = Omit<EslintRuleMeta, 'docs'> & {
  docs: NonNullable<EslintRuleMeta['docs']> & { description: string; url: string; tier: Tier };
};

/** A rule module whose tier is readable without casting. */
export type WardenRule = Rule.RuleModule & { meta: WardenRuleMeta };

/**
 * `meta` is required here, not optional as in ESLint's own type: a rule without
 * a description and a docs URL is a rule people disable instead of reading —
 * and, since the tier was added, a rule nobody can tell is load-bearing.
 */
export function createRule(meta: WardenRuleMeta, create: Rule.RuleModule['create']): WardenRule {
  return { meta, create };
}
