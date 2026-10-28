/**
 * The application's vocabulary, declared once by module augmentation:
 *
 *   declare module '@wardenjs/ssr' {
 *     interface SecurityRegistry {
 *       role: 'user' | 'admin';
 *       permission: 'order:read:own' | 'order:read:any';
 *       principal: { id: string; role: 'user' | 'admin'; tenantId: string };
 *     }
 *   }
 *
 * Every SSR plugin reads these types from here, so a typo in a permission is a
 * compile error everywhere at once. Without augmentation they widen to string.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmented by applications
export interface SecurityRegistry {}

export type Role = SecurityRegistry extends { role: infer R extends string } ? R : string;

export type Permission = SecurityRegistry extends { permission: infer P extends string }
  ? P
  : string;

export interface BasePrincipal {
  readonly id: string;
  readonly role: Role;
}

export type Principal = SecurityRegistry extends { principal: infer P extends BasePrincipal }
  ? P
  : BasePrincipal;
