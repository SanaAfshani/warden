import { createContext, createElement, useContext, useMemo, type ReactNode } from 'react';
import type { Permission } from '@wardenjs/csr';
import { permissionSet, type Permissions } from './permissions.js';

const Context = createContext<Permissions>(permissionSet(null));

/** Outside a provider every check denies. */
export function PermissionsProvider(props: { granted: readonly Permission[] | null | undefined; children: ReactNode }): ReactNode {
  const key = props.granted?.join('\u0000') ?? '';
  // Keyed on content: a fresh array from every session fetch must not re-render the tree.
  const value = useMemo(() => permissionSet(props.granted), [key]);
  return createElement(Context.Provider, { value }, props.children);
}

export const usePermissions = (): Permissions => useContext(Context);
export const useCan = (permission: Permission): boolean => useContext(Context).can(permission);

export interface CanProps {
  children: ReactNode;
  permission?: Permission;
  all?: readonly Permission[];
  any?: readonly Permission[];
  /** Default nothing: a "no access" message confirms the feature exists. */
  otherwise?: ReactNode;
}

/** `<Can permission="post:delete"><DeleteButton /></Can>`. With no condition it denies. */
export function Can({ children, permission, all, any, otherwise = null }: CanProps): ReactNode {
  const permissions = useContext(Context);
  if (permission === undefined && all === undefined && any === undefined) return otherwise;
  const ok =
    (permission === undefined || permissions.can(permission)) &&
    (all === undefined || permissions.canAll(all)) &&
    (any === undefined || permissions.canAny(any));
  return ok ? children : otherwise;
}
