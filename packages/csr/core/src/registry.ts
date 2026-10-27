/**
 * The application's vocabulary for the browser track, declared once:
 *
 *   declare module '@sanaafshani/warden-csr' {
 *     interface SecurityRegistry {
 *       permission: 'post:create' | 'post:delete';
 *     }
 *   }
 *
 * Separate from the server track's registry on purpose (the tracks share no
 * code). To keep both in step, declare the union once in your app and
 * reference it from both augmentations.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmented by applications
export interface SecurityRegistry {}

export type Permission = SecurityRegistry extends { permission: infer P extends string }
  ? P
  : string;
