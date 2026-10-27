/**
 * What `npm publish --workspaces` ships, checked before it ships. Each case is
 * a mistake that tests of the code cannot see and that cannot be undone once
 * a version is on the registry.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import plugin from '@sanaafshani/warden-csr-eslint-plugin';

const root = join(import.meta.dirname, '..');
const dirs = ['ssr', 'csr'].flatMap((track) =>
  readdirSync(join(root, 'packages', track)).map((name) => join(root, 'packages', track, name)),
);
const manifests = dirs.map((dir) => ({
  dir,
  pkg: JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
    name: string;
    version: string;
    peerDependencies?: Record<string, string>;
  },
}));
const version = manifests[0]?.pkg.version;

describe('release', () => {
  it('names every package after its track', () => {
    for (const { dir, pkg } of manifests) {
      const track = dir.includes('/packages/ssr/') ? 'ssr' : 'csr';
      expect(pkg.name, dir).toMatch(new RegExp(`^@sanaafshani/warden-${track}(-|$)`));
    }
  });

  // One version for all, so an advisory names one version to move to.
  it('gives every package the same version', () => {
    for (const { pkg } of manifests) expect(pkg.version, pkg.name).toBe(version);
  });

  // A stale range makes npm refuse to install a plugin next to its own core.
  it('peers every plugin on the current version of its core', () => {
    for (const { pkg } of manifests) {
      for (const [name, range] of Object.entries(pkg.peerDependencies ?? {})) {
        if (name.startsWith('@sanaafshani/')) expect(range, `${pkg.name} → ${name}`).toBe(`^${version}`);
      }
    }
  });

  // ESLint keys its cache on this; a stale value keeps old rule results.
  it('reports the eslint plugin version from package.json', () => {
    expect(plugin.meta.version).toBe(version);
  });

  // npm packs the LICENSE from the package folder only, and MIT requires the text in every copy.
  it('ships the license and a README in every package', () => {
    const license = readFileSync(join(root, 'LICENSE'), 'utf8');
    for (const { dir } of manifests) {
      expect(readFileSync(join(dir, 'LICENSE'), 'utf8'), dir).toBe(license);
      expect(readdirSync(dir), dir).toContain('README.md');
    }
  });
});
