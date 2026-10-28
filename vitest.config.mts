import { defineConfig } from 'vitest/config';

// Workspace imports resolve to source, so tests need no build. Listing
// conditions replaces Vite's defaults, hence the defaults are repeated.
const conditions = (platform: 'browser' | 'node') => ['@wardenjs/source', 'module', platform, 'development|production'];

export default defineConfig({
  resolve: { conditions: conditions('browser') },
  ssr: { resolve: { conditions: conditions('node'), externalConditions: ['@wardenjs/source'] } },
  test: {
    projects: [
      // Server code is tested without a DOM: a server module that reaches for
      // `window` should fail here, not in production.
      { extends: true, test: { name: 'ssr', environment: 'node', include: ['packages/ssr/*/tests/**/*.test.ts'] } },
      {
        extends: true,
        test: {
          name: 'csr',
          environment: 'jsdom',
          include: ['packages/csr/*/tests/**/*.test.ts'],
          exclude: ['packages/csr/eslint-plugin/**'],
        },
      },
      // RuleTester registers its cases through global describe/it.
      {
        extends: true,
        test: { name: 'eslint-plugin', environment: 'node', globals: true, include: ['packages/csr/eslint-plugin/tests/**/*.test.ts'] },
      },
      { extends: true, test: { name: 'release', environment: 'node', include: ['tests/**/*.test.ts'] } },
    ],
  },
});
