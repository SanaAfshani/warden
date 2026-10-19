import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { permissionSet } from '../src/index.js';
import { Can, PermissionsProvider } from '../src/react.js';

describe('permissionSet', () => {
  it('denies everything while signed out or loading', () => {
    expect(permissionSet(null).can('post:read')).toBe(false);
    expect(permissionSet(undefined).canAny(['post:read'])).toBe(false);
  });

  it('does not treat an empty requirement list as permission', () => {
    expect(permissionSet(['post:read']).canAll([])).toBe(false);
  });
});

describe('<Can>', () => {
  const render = (granted: string[] | null, props: Record<string, unknown>) =>
    renderToString(
      createElement(PermissionsProvider, { granted, children: createElement(Can, { otherwise: 'no', children: 'yes', ...props }) }),
    );

  it('renders children only when the check passes', () => {
    expect(render(['post:delete'], { permission: 'post:delete' })).toBe('yes');
    expect(render(['post:read'], { permission: 'post:delete' })).toBe('no');
    expect(render(['a', 'b'], { all: ['a', 'b'] })).toBe('yes');
  });

  it('denies when given no condition, instead of rendering for everyone', () => {
    expect(render(['post:delete'], {})).toBe('no');
  });

  it('denies outside a provider', () => {
    expect(renderToString(createElement(Can, { permission: 'x', children: 'yes' }))).toBe('');
  });
});
