import {
  defineDecorator,
  emit,
  HttpError,
  type Decorator,
  type Permission,
  type Principal,
  type Role,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

export interface AccessControlOptions {
  /** Least to most privileged; the order is what `canAssignRole` ranks by. */
  roles: readonly Role[];
  /** An entry for every role, even an empty one, so a forgotten role is visible. */
  grants: Readonly<Record<Role, readonly Permission[]>>;
  /** Role used for `principal === null`. Default: none, so anonymous callers can do nothing. */
  anonymous?: Role;
  onEvent?: SecurityEventHandler;
}

export interface AccessControl {
  can(principal: Principal | null, permission: Permission): boolean;
  canAll(principal: Principal | null, permissions: readonly Permission[]): boolean;
  canAny(principal: Principal | null, permissions: readonly Permission[]): boolean;
  /**
   * Ownership, the check that prevents IDOR. `ownerId` must come from the
   * stored record, never from the request. `any` is checked first.
   */
  canAccess(principal: Principal | null, ownerId: string, own: Permission, any: Permission): boolean;
  /** Only below your own rank, never yourself: one request must not self-promote. */
  canAssignRole(actor: Principal, targetUserId: string, role: Role, assignPermission: Permission): boolean;
  /** Runtime check for roles from a database row or a token. */
  isRole(value: unknown): value is Role;
  /** For lists you cannot scope in the query; a guarded detail route and an unguarded list route leak the same rows. */
  filter<T>(principal: Principal | null, items: readonly T[], ownerOf: (item: T) => string, own: Permission, any: Permission): T[];
  /** Throws 403. */
  assert(principal: Principal, permission: Permission, target?: string): void;
  /**
   * Throws 404 by default: a 403 confirms the record exists, and walking an id
   * range then enumerates the table. Use `{ notFound: false }` for resources
   * that are publicly known to exist.
   */
  assertAccess(
    principal: Principal,
    ownerId: string,
    own: Permission,
    any: Permission,
    options?: { notFound?: boolean; target?: string },
  ): void;
  /** Requires every listed permission; runs after an authn decorator. */
  require(...permissions: Permission[]): Decorator<{ principal: Principal }>;
}

/** Deny by default; a malformed table throws at construction instead of silently granting nothing. */
export function accessControl(options: AccessControlOptions): AccessControl {
  const problems = validate(options);
  if (problems.length > 0) throw new Error(`accessControl:\n- ${problems.join('\n- ')}`);

  const grants = new Map<string, ReadonlySet<string>>(
    Object.entries(options.grants as Record<string, readonly string[]>).map(([role, list]) => [role, new Set(list)]),
  );
  const ranks = options.roles;

  const can = (principal: Principal | null, permission: Permission) => {
    const role = principal ? principal.role : options.anonymous;
    return role !== undefined && (grants.get(role)?.has(permission) ?? false);
  };
  // Strict equality: `0 == '0'` is the type confusion that lets a JSON number match a string id.
  const canAccess: AccessControl['canAccess'] = (principal, ownerId, own, any) =>
    can(principal, any) || (principal !== null && principal.id === ownerId && can(principal, own));

  const deny = (principal: Principal, permission: string, target?: string) =>
    emit(options.onEvent, {
      type: 'access.denied',
      outcome: 'blocked',
      actorId: principal.id,
      reason: permission,
      ...(target === undefined ? {} : { target }),
    });

  const forbidden = () => new HttpError(403, 'forbidden', 'You do not have permission to do this.');

  return {
    can,
    canAll: (principal, list) => list.every((p) => can(principal, p)),
    canAny: (principal, list) => list.some((p) => can(principal, p)),
    canAccess,
    canAssignRole(actor, targetUserId, role, assignPermission) {
      if (!can(actor, assignPermission) || actor.id === targetUserId) return false;
      const actorRank = ranks.indexOf(actor.role);
      const newRank = ranks.indexOf(role);
      return actorRank >= 0 && newRank >= 0 && newRank < actorRank;
    },
    isRole: (value): value is Role => typeof value === 'string' && ranks.includes(value),
    filter(principal, items, ownerOf, own, any) {
      if (can(principal, any)) return [...items];
      return items.filter((item) => canAccess(principal, ownerOf(item), own, any));
    },
    assert(principal, permission, target) {
      if (can(principal, permission)) return;
      deny(principal, permission, target);
      throw forbidden();
    },
    assertAccess(principal, ownerId, own, any, { notFound = true, target } = {}) {
      if (canAccess(principal, ownerId, own, any)) return;
      deny(principal, own, target);
      throw notFound ? new HttpError(404, 'not_found', 'Not found.') : forbidden();
    },
    require: (...permissions) =>
      defineDecorator<{ principal: Principal }>('access', async (request, context, next) => {
        const missing = permissions.find((p) => !can(context.principal, p));
        if (missing !== undefined) {
          deny(context.principal, missing, new URL(request.url).pathname);
          throw forbidden();
        }
        return next();
      }),
  };
}

function validate(options: AccessControlOptions): string[] {
  const problems: string[] = [];
  const roles = options.roles;
  const declared = new Set(roles);
  if (roles.length === 0) problems.push('roles is empty.');
  if (declared.size !== roles.length) problems.push('roles contains duplicates.');
  for (const role of Object.keys(options.grants)) {
    if (!declared.has(role)) problems.push(`grants has '${role}', which is not in roles (typo?).`);
  }
  for (const role of roles) {
    if (!Object.hasOwn(options.grants, role)) problems.push(`role '${role}' has no grants entry; use [] for none.`);
  }
  if (options.anonymous !== undefined && !declared.has(options.anonymous)) {
    problems.push(`anonymous role '${options.anonymous}' is not in roles.`);
  }
  return problems;
}
