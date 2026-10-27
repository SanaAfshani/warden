/**
 * These tests exist to BREAK the guard, not to watch it pass.
 *
 * A tier that is only ever asserted on a good config proves nothing: the same
 * test passes against a function that returns `[]` unconditionally. So every
 * case below either downgrades a required rule and demands a throw, or does
 * something that looks like a downgrade and demands silence.
 */
import { describe, expect, it } from 'vitest';
import type { Linter } from 'eslint';
import plugin, { enforce, findDowngrades, migrating, recommended, rules, tiers, waive, NAMESPACE } from '../src/index.js';

const ruleId = (name: string) => `${NAMESPACE}/${name}`;
const severityOf = (config: Linter.Config, name: string) => {
  const entry = config.rules?.[ruleId(name)];
  return Array.isArray(entry) ? entry[0] : entry;
};

describe('tiers', () => {
  it('gives every rule a tier', () => {
    for (const [name, rule] of Object.entries(rules)) {
      expect(rule.meta.docs.tier, name).toMatch(/^(required|recommended)$/);
    }
  });

  it('sorts the rules into the two tiers with nothing left over', () => {
    expect([...tiers.required].sort()).toEqual([
      ruleId('no-dangerous-html'),
      ruleId('no-dom-html-sink'),
      ruleId('require-safe-url'),
    ]);
    expect([...tiers.recommended].sort()).toEqual([
      ruleId('no-raw-web-storage'),
      ruleId('no-unsafe-target-blank'),
    ]);
    expect(tiers.required.length + tiers.recommended.length).toBe(Object.keys(rules).length);
  });
});

describe('shipped configs', () => {
  it('keeps every required rule at error in BOTH configs', () => {
    for (const config of [recommended, migrating]) {
      for (const rule of tiers.required) {
        expect(config.rules?.[rule], rule).toBe('error');
      }
    }
  });

  it('lets migrating differ by option but never by severity', () => {
    // The one intended difference: writes still fail, reads are allowed.
    expect(migrating.rules?.[ruleId('no-raw-web-storage')]).toEqual([
      'error',
      { allowReads: true },
    ]);
    for (const name of Object.keys(rules)) {
      expect(severityOf(migrating, name), name).toBe(severityOf(recommended, name));
    }
  });

  it('passes its own enforcement', () => {
    expect(() => enforce(recommended, migrating)).not.toThrow();
  });
});

describe('enforce', () => {
  it('throws when a required rule is switched off', () => {
    expect(() => enforce(recommended, { rules: { [ruleId('no-dom-html-sink')]: 'off' } })).toThrow(
      /no-dom-html-sink/,
    );
  });

  it('throws when a required rule is merely downgraded to a warning', () => {
    expect(() =>
      enforce(recommended, { rules: { [ruleId('require-safe-url')]: 'warn' } }),
    ).toThrow(/require-safe-url/);
  });

  it('throws on the numeric spellings of off and warn', () => {
    expect(() => enforce(recommended, { rules: { [ruleId('no-dangerous-html')]: 0 } })).toThrow(/no-dangerous-html/);
    expect(() => enforce(recommended, { rules: { [ruleId('no-dangerous-html')]: 1 } })).toThrow(/no-dangerous-html/);
  });

  it('throws when the downgrade hides in a tuple with options', () => {
    expect(() =>
      enforce(recommended, { rules: { [ruleId('require-safe-url')]: ['warn', { validators: ['ok'] }] } }),
    ).toThrow(/require-safe-url/);
  });

  it('throws even when the downgrade is scoped to some files', () => {
    // Scoping is the blessed way to ADOPT, by narrowing the config that enables
    // these rules. It is not a licence to lower one for a subdirectory.
    expect(() =>
      enforce(recommended, {
        files: ['legacy/**'],
        rules: { [ruleId('no-dangerous-html')]: 'off' },
      }),
    ).toThrow(/no-dangerous-html/);
  });

  it('names every offender, not just the first', () => {
    try {
      enforce(recommended, {
        rules: {
          [ruleId('no-dangerous-html')]: 'off',
          [ruleId('require-safe-url')]: 'warn',
        },
      });
      expect.unreachable('enforce should have thrown');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('no-dangerous-html');
      expect(message).toContain('require-safe-url');
    }
  });

  it('refuses a fragment that does not register the plugin', () => {
    // The trap this catches is real: wiring this repo's own config, the first
    // attempt passed enforce() only the waivers. It reported a clean bill of
    // health while an unwaived `'off'` sat elsewhere in the array, unseen.
    expect(() => enforce({ rules: { 'no-console': 'off' } })).toThrow(/fragment/);
    expect(() => enforce()).toThrow(/fragment/);
  });

  it('allows a recommended rule to be switched off', () => {
    // The tier is the whole point: these are a team's call to make.
    expect(() =>
      enforce(recommended, { rules: { [ruleId('no-raw-web-storage')]: 'off' } }),
    ).not.toThrow();
    expect(() =>
      enforce(recommended, { rules: { [ruleId('no-unsafe-target-blank')]: 'warn' } }),
    ).not.toThrow();
  });

  it('ignores configs that do not mention our rules', () => {
    expect(() => enforce(recommended, { rules: { 'no-console': 'off' } }, { files: ['**/*.ts'] })).not.toThrow();
  });

  it('returns the configs unchanged so it can wrap an array in place', () => {
    const own: Linter.Config = { files: ['src/**'] };
    expect(enforce(recommended, own)).toEqual([recommended, own]);
  });

  it('is reachable from the default export, which is how a config file uses it', () => {
    expect(plugin.enforce).toBe(enforce);
  });
});

describe('waive', () => {
  const hatch = () =>
    waive({
      rule: 'no-dangerous-html',
      files: ['packages/csr/sanitize/src/react.ts'],
      reason: 'the one sanitising component; DOMPurify runs on the line above',
    });

  it('lets enforce accept the downgrade it excuses', () => {
    expect(() => enforce(recommended, hatch())).not.toThrow();
  });

  it('excuses only the rule it names', () => {
    const config = hatch();
    // Same object, a second required rule smuggled in afterwards.
    config.rules![ruleId('no-dom-html-sink')] = 'off';
    expect(() => enforce(recommended, config)).toThrow(/no-dom-html-sink/);
  });

  it('does not excuse the same rule in a different config', () => {
    expect(() =>
      enforce(recommended, hatch(), { rules: { [ruleId('no-dangerous-html')]: 'off' } }),
    ).toThrow(/no-dangerous-html/);
  });

  it('accepts a rule name with or without the namespace', () => {
    const prefixed = waive({ rule: ruleId('no-dom-html-sink'), files: ['t/**'], reason: 'hostile input by design' });
    expect(prefixed.rules).toEqual({ [ruleId('no-dom-html-sink')]: 'off' });
    expect(() => enforce(recommended, prefixed)).not.toThrow();
  });

  it('refuses a waiver with no scope', () => {
    expect(() => waive({ rule: 'no-dangerous-html', files: [], reason: 'because' })).toThrow(/scope/);
  });

  it('refuses a waiver with no reason', () => {
    expect(() => waive({ rule: 'no-dangerous-html', files: ['a/**'], reason: '   ' })).toThrow(/reason/);
  });

  it('carries the reason into the config name, where ESLint will print it', () => {
    expect(hatch().name).toContain('DOMPurify runs on the line above');
  });

  it('is reachable from the default export', () => {
    expect(plugin.waive).toBe(waive);
  });
});

describe('findDowngrades', () => {
  it('reports what was found, not merely that something was', () => {
    expect(
      findDowngrades([
        { rules: { [ruleId('no-dangerous-html')]: 'off' } },
        { rules: { [ruleId('require-safe-url')]: 'warn' } },
      ]),
    ).toEqual([
      { rule: ruleId('no-dangerous-html'), found: 'off' },
      { rule: ruleId('require-safe-url'), found: 'warn' },
    ]);
  });

  it('is silent on a config that raises nothing', () => {
    expect(findDowngrades([recommended, migrating])).toEqual([]);
  });
});
