/**
 * The library can make the safe thing easy; it cannot make the unsafe thing
 * impossible. `localStorage.setItem` and `dangerouslySetInnerHTML` are one line
 * away, and a control the build does not enforce survives only as long as the
 * person who introduced it. These rules are that enforcement.
 *
 * No roles, permissions or endpoints: every name a rule needs (the sanitising
 * component, the URL validator, the storage replacement) is an option, with
 * the CSR track's names only as defaults.
 */

import type { ESLint, Linter } from 'eslint';
import { noDangerousHtml } from './rules/no-dangerous-html.js';
import { noDomHtmlSink } from './rules/no-dom-html-sink.js';
import { noRawWebStorage } from './rules/no-raw-web-storage.js';
import { requireSafeUrl } from './rules/require-safe-url.js';
import { noUnsafeTargetBlank } from './rules/no-unsafe-target-blank.js';
import type { Tier } from './severity.js';

const rules = {
  'no-dangerous-html': noDangerousHtml,
  'no-dom-html-sink': noDomHtmlSink,
  'no-raw-web-storage': noRawWebStorage,
  'require-safe-url': requireSafeUrl,
  'no-unsafe-target-blank': noUnsafeTargetBlank,
};

/** The namespace a consumer's config must use to address these rules. */
export const NAMESPACE = '@sanaafshani/warden-csr';

const id = (name: string) => `${NAMESPACE}/${name}`;

/** Rule ids, by tier. `required` is the list {@link enforce} refuses to see lowered. */
export const tiers: Record<Tier, readonly string[]> = {
  required: Object.entries(rules)
    .filter(([, rule]) => rule.meta.docs.tier === 'required')
    .map(([name]) => id(name)),
  recommended: Object.entries(rules)
    .filter(([, rule]) => rule.meta.docs.tier === 'recommended')
    .map(([name]) => id(name)),
};

/**
 * Build a config from the tiers rather than by hand, so a severity is chosen
 * where the reasoning lives and hand-written configs cannot drift from it.
 * `required` rules are not a parameter. That is the whole point of the tier.
 */
function configure(
  recommendedTier: Linter.RuleSeverity,
  options: Partial<Record<keyof typeof rules, unknown>> = {},
): Linter.Config {
  const configured: Linter.RulesRecord = {};
  for (const [name, rule] of Object.entries(rules)) {
    const severity = rule.meta.docs.tier === 'required' ? 'error' : recommendedTier;
    const option = options[name as keyof typeof rules];
    configured[id(name)] = option === undefined ? severity : [severity, option];
  }
  return { plugins: { [NAMESPACE]: plugin }, rules: configured };
}

const plugin = {
  meta: { name: '@sanaafshani/warden-csr-eslint-plugin', version: '0.1.1' },
  rules,
} satisfies ESLint.Plugin;

/**
 * `recommended` — every rule as an ERROR.
 *
 * Not "warnings so we can adopt gradually". A warning in a CI log is a warning
 * nobody reads, and these five rules each stand for a real vulnerability class.
 * Adopt gradually by SCOPING the config to new directories, which is visible in
 * the config file, rather than by lowering severity, which is visible nowhere.
 */
const recommended: Linter.Config = configure('error');

/**
 * `migrating` — for an existing codebase.
 *
 * It differs from `recommended` by OPTION, not by severity: reads are allowed
 * on web storage so a team can move writes first, which is the order that
 * actually matters, since an unencrypted READ of a value that was written
 * encrypted simply returns null while an unencrypted WRITE leaves plaintext on
 * disk.
 *
 * `required` rules are still errors here. A config named "migrating" is the
 * most tempting place to park a `warn` forever, which is exactly why the tier
 * does not let it.
 */
const migrating: Linter.Config = configure('error', { 'no-raw-web-storage': { allowReads: true } });

/** A `required` rule that a config switched off or lowered to a warning. */
export interface Downgrade {
  rule: string;
  /** What the offending config asked for, normalised. */
  found: 'off' | 'warn';
}

export interface Waiver {
  /** Rule name, with or without the `@sanaafshani/warden-csr/` prefix. */
  rule: string;
  /** The files this covers. A waiver with no scope is not a waiver. */
  files: readonly string[];
  /** Why this code is allowed to do the dangerous thing. */
  reason: string;
}

/**
 * Configs produced by {@link waive}, and the single rule each one excuses.
 *
 * A `WeakMap` rather than a marker property because ESLint rejects unknown keys
 * on a flat config object outright — `Unexpected key "reason" found` — so the
 * provenance has to live beside the config instead of on it.
 */
const waived = new WeakMap<Linter.Config, string>();

/**
 * Switch a rule off for named files, on the record.
 *
 * ---------------------------------------------------------------------------
 * Why an escape hatch exists at all
 * ---------------------------------------------------------------------------
 * Somewhere, exactly one component has to call the dangerous thing — ours is
 * `<SafeHtml>`, which runs DOMPurify on the line above — and a test suite has
 * to build hostile input on purpose. A control with no hatch gets removed
 * wholesale the first time it blocks legitimate work, which is strictly worse
 * than a hatch that leaves a record.
 *
 * So this is not a loophole in the tier, it is the tier's price list: a
 * required rule costs a scope and a sentence to switch off, both greppable and
 * both in the diff. `enforce` accepts a downgrade from here and from nowhere
 * else.
 */
export function waive({ rule, files, reason }: Waiver): Linter.Config {
  if (files.length === 0) {
    throw new Error(`${NAMESPACE}: waive() needs a 'files' scope — an unscoped waiver is just 'off'.`);
  }
  if (reason.trim() === '') {
    throw new Error(`${NAMESPACE}: waive() needs a reason — it is the only thing a reviewer reads.`);
  }
  const target = rule.startsWith(`${NAMESPACE}/`) ? rule : id(rule);
  // The reason also goes in `name`, so ESLint's own output carries it.
  const config: Linter.Config = {
    name: `${NAMESPACE} waiver: ${target} — ${reason}`,
    files: [...files],
    rules: { [target]: 'off' },
  };
  waived.set(config, target);
  return config;
}

/** `Array.isArray` narrows `unknown` to `any[]`; this keeps the element `unknown`. */
const isTuple = (value: unknown): value is readonly unknown[] => Array.isArray(value);

/** ESLint accepts `0 | 1 | 2` and `'off' | 'warn' | 'error'`, bare or in a tuple. */
function severityOf(entry: unknown): 'off' | 'warn' | 'error' | null {
  const value = isTuple(entry) ? entry[0] : entry;
  if (value === 0 || value === 'off') return 'off';
  if (value === 1 || value === 'warn') return 'warn';
  if (value === 2 || value === 'error') return 'error';
  return null;
}

/**
 * Every `required` rule that `configs` disables or lowers, in config order.
 * A rule excused by {@link waive} is not a downgrade — that is what waiving is.
 */
export function findDowngrades(configs: readonly Linter.Config[]): Downgrade[] {
  const found: Downgrade[] = [];
  for (const config of configs) {
    for (const rule of tiers.required) {
      if (waived.get(config) === rule) continue;
      const severity = severityOf(config.rules?.[rule]);
      if (severity === 'off' || severity === 'warn') found.push({ rule, found: severity });
    }
  }
  return found;
}

/**
 * Wrap a flat config array so that disabling a `required` rule fails loudly.
 *
 * ```js
 * export default warden.enforce(...tseslint.config(/* everything *\/));
 * ```
 *
 * ---------------------------------------------------------------------------
 * Pass it the WHOLE array, not a fragment
 * ---------------------------------------------------------------------------
 * This sees exactly the configs it is given. Handing it a slice — the waivers
 * alone, say — checks that slice and silently ignores a downgrade sitting
 * anywhere else in the file, which is the one case the tier exists to catch.
 * Since a config that enforces our tiers must also enable our rules, receiving
 * no plugin registration means it was handed a fragment, and it says so rather
 * than reporting a clean bill of health it cannot vouch for.
 *
 * ---------------------------------------------------------------------------
 * Why this is a thrown error and not a silent re-enable
 * ---------------------------------------------------------------------------
 * ESLint gives a plugin no way to forbid an override: a flat config is just an
 * array and the last entry wins. The options are to re-assert our severity
 * after the consumer's — which makes their `'off'` do nothing, with no
 * explanation, and sends them hunting — or to refuse the config and say why.
 *
 * A security control that fails silently in the safe direction still teaches
 * the team that the config file lies to them, so this one fails loudly instead.
 * Scoped adoption is unaffected: narrow the `files` of the config that ENABLES
 * these rules. Downgrading remains a mistake whether or not it is scoped.
 */
export function enforce(...configs: Linter.Config[]): Linter.Config[] {
  if (!configs.some((config) => config.plugins?.[NAMESPACE])) {
    throw new Error(
      `${NAMESPACE}: enforce() was given no config that registers the plugin, so it was handed a ` +
        `fragment rather than the whole flat config — and a downgrade elsewhere in the array would ` +
        `pass unnoticed. Wrap everything:\n` +
        `  export default warden.enforce(...tseslint.config(/* everything */));`,
    );
  }
  const downgrades = findDowngrades(configs);
  if (downgrades.length > 0) {
    const lines = downgrades.map(({ rule, found }) => `  ${rule} is set to '${found}'`);
    throw new Error(
      `${NAMESPACE}: these rules are tier 'required' and must stay at 'error':\n${lines.join('\n')}\n` +
        `A required rule guards a vulnerability class nothing else here mitigates at runtime.\n` +
        `If some file genuinely has to do the dangerous thing, say so on the record:\n` +
        `  waive({ rule: 'no-dom-html-sink', files: ['src/legacy/**'], reason: '...' })\n` +
        `To adopt gradually, narrow the 'files' of the config that ENABLES these rules instead of lowering them.`,
    );
  }
  return configs;
}

export default { ...plugin, configs: { recommended, migrating }, enforce, waive };
export { rules, recommended, migrating };
