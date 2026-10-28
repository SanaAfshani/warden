// The plugin is imported from its build output, so `npm run build` runs before `npm run lint`.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import warden from '@wardenjs/csr-eslint-plugin';

// `enforce` is the OUTERMOST call on purpose: it only inspects what it is
// handed, so wrapping a fragment would miss a downgrade elsewhere in the array.
export default warden.enforce(...tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**'] },

  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { project: './tsconfig.json', tsconfigRootDir: import.meta.dirname },
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      // A forgotten `await` on a check means the request proceeds before it finished.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      eqeqeq: ['error', 'always'],
      'no-eval': 'error',
      'no-new-func': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // Contract methods return promises whether or not this implementation awaits.
      '@typescript-eslint/require-await': 'off',
    },
  },
  // Outside tsconfig.json, so no type information.
  { ...tseslint.configs.disableTypeChecked, files: ['**/*.mjs'] },

  // The tracks share no code; universal code stays framework-free.
  {
    files: ['packages/ssr/*/src/**/*.ts'],
    rules: {
      'no-restricted-imports': ['error', {
        patterns: [
          { group: ['@wardenjs/csr', '@wardenjs/csr-*'], message: 'The SSR track must not depend on the CSR track.' },
          { group: ['react', 'react-dom', 'next', 'next/*'], message: 'SSR plugins are framework-agnostic.' },
        ],
      }],
    },
  },
  {
    files: ['packages/csr/*/src/**/*.ts'],
    ignores: ['packages/csr/*/src/react.ts'],
    rules: {
      'no-restricted-imports': ['error', {
        patterns: [
          { group: ['@wardenjs/ssr', '@wardenjs/ssr-*'], message: 'The CSR track must not depend on the SSR track.' },
          { group: ['react', 'react-dom'], message: 'React belongs in the `/react` subpath, so non-React apps never load it.' },
        ],
      }],
    },
  },

  // Dogfooding. Each exemption is a file whose job is the dangerous thing.
  { ...warden.configs.recommended, files: ['**/*.ts'] },
  {
    // The Web Storage base store, and the cross-tab logout fallback (a timestamp, no data).
    files: ['packages/csr/storage/src/stores.ts', 'packages/csr/sso/src/channel.ts'],
    rules: { '@wardenjs/csr/no-raw-web-storage': 'off' },
  },
  {
    // Reads the double-submit CSRF cookie, which is meant to be readable and is not a secret.
    files: ['packages/csr/sso/src/bff.ts'],
    rules: { '@wardenjs/csr/no-raw-web-storage': 'off' },
  },
  // A required rule costs a scope and a reason to switch off. These are ours.
  warden.waive({
    rule: 'no-dangerous-html',
    files: ['packages/csr/sanitize/src/react.ts'],
    reason: '<SafeHtml> is the one sink, and DOMPurify runs on the line above it.',
  }),
  warden.waive({
    rule: 'no-dom-html-sink',
    files: ['packages/**/tests/**/*.ts'],
    reason: 'Tests assign hostile markup on purpose, to prove the rules and the sanitiser catch it.',
  }),
  warden.waive({
    rule: 'no-dangerous-html',
    files: ['packages/**/tests/**/*.ts'],
    reason: 'Tests render the banned prop on purpose, to prove the rule reports it.',
  }),
  {
    files: ['packages/**/tests/**/*.ts'],
    rules: {
      // Tier `recommended`: a team's call, and ours is that tests may use raw storage.
      '@wardenjs/csr/no-raw-web-storage': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
));
