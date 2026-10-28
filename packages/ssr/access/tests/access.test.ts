import { describe, expect, it } from 'vitest';
import { chain, defineDecorator, HttpError, type Principal } from '@wardenjs/ssr';
import { accessControl } from '../src/index.js';

const ac = accessControl({
  roles: ['user', 'moderator', 'admin'],
  grants: {
    user: ['post:read:own', 'post:update:own'],
    moderator: ['post:read:own', 'post:update:own', 'post:read:any', 'user:assign-role'],
    admin: ['post:read:any', 'post:update:any', 'user:assign-role'],
  },
});

const alice: Principal = { id: 'alice', role: 'user' };
const mod: Principal = { id: 'mod', role: 'moderator' };

describe('accessControl', () => {
  it('denies by default, including anonymous callers', () => {
    expect(ac.can(alice, 'post:update:any')).toBe(false);
    expect(ac.can(null, 'post:read:own')).toBe(false);
  });

  it('prevents IDOR: own-permission covers only records you own', () => {
    expect(ac.canAccess(alice, 'alice', 'post:update:own', 'post:update:any')).toBe(true);
    expect(ac.canAccess(alice, 'bob', 'post:update:own', 'post:update:any')).toBe(false);
  });

  it('answers someone else’s record with 404, not 403, so ids cannot be enumerated', () => {
    try {
      ac.assertAccess(alice, 'bob', 'post:read:own', 'post:read:any');
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(HttpError);
      expect((error as HttpError).status).toBe(404);
    }
  });

  it('blocks self-promotion and granting a rank equal to your own', () => {
    expect(ac.canAssignRole(mod, 'mod', 'user', 'user:assign-role')).toBe(false);
    expect(ac.canAssignRole(mod, 'alice', 'moderator', 'user:assign-role')).toBe(false);
    expect(ac.canAssignRole(mod, 'alice', 'user', 'user:assign-role')).toBe(true);
  });

  it('filters lists the same way it guards detail routes', () => {
    const posts = [{ owner: 'alice' }, { owner: 'bob' }];
    expect(ac.filter(alice, posts, (p) => p.owner, 'post:read:own', 'post:read:any')).toEqual([{ owner: 'alice' }]);
  });

  it('throws on a grant table with a typo instead of silently granting nothing', () => {
    expect(() => accessControl({ roles: ['user'], grants: { user: [], admn: [] } })).toThrow(/admn/);
    expect(() => accessControl({ roles: ['user', 'admin'], grants: { user: [] } })).toThrow(/admin/);
  });

  it('require() rejects with 403 inside a chain', async () => {
    const as = (principal: Principal) =>
      defineDecorator<object, { principal: Principal }>('as', (_r, _c, next) => next({ principal }));
    const handler = (p: Principal) =>
      chain().use(as(p)).use(ac.require('post:read:any')).handle(() => new Response('ok'));
    expect((await handler(alice)(new Request('https://a.test/posts'))).status).toBe(403);
    expect((await handler(mod)(new Request('https://a.test/posts'))).status).toBe(200);
  });
});
