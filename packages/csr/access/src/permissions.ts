import type { Permission } from '@wardenjs/csr';

/**
 * What the UI shows, never what is allowed: the user owns the browser and
 * can call your API directly. Every check here must be repeated on the server.
 */
export interface Permissions {
  can(permission: Permission): boolean;
  canAll(permissions: readonly Permission[]): boolean;
  canAny(permissions: readonly Permission[]): boolean;
}

/**
 * Built from the CURRENT user's permissions, typically returned by your
 * session endpoint. Shipping the full role → permission table instead
 * publishes your whole admin surface to anyone who opens the bundle.
 * Null or undefined (signed out, still loading) denies everything.
 */
export function permissionSet(granted: Iterable<Permission> | null | undefined): Permissions {
  const set = new Set<Permission>(granted ?? []);
  const can = (permission: Permission) => set.has(permission);
  return {
    can,
    // `every` on an empty list is true, and "requires nothing" is not a reason to show an admin control.
    canAll: (permissions) => permissions.length > 0 && permissions.every(can),
    canAny: (permissions) => permissions.some(can),
  };
}
