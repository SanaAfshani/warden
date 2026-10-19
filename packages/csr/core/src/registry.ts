/**
 * The application's vocabulary for the browser track, declared once:
 *
 *   declare module '@sanaafshani/warden-csr' {
 *     interface SecurityRegistry {
 *       role: 'user' | 'admin';
 *       permission: 'post:create' | 'post:delete';
 *     }
 *   }
 *
 * Separate from the server track's registry on purpose (the tracks share no
 * code). To keep both in step, declare the unions once in your app and
 * reference them from both augmentations.
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
