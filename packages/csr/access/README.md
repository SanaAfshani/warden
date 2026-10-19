# @sanaafshani/warden-csr-access

Permission-gated UI. **Display only:** the user controls the browser, so
every permission shown here must be enforced again by the server
(`@sanaafshani/warden-ssr-access`).

```bash
npm i @sanaafshani/warden-csr @sanaafshani/warden-csr-access
```

```tsx
import { Can, PermissionsProvider, useCan } from '@sanaafshani/warden-csr-access/react';

<PermissionsProvider granted={session.user?.permissions}>
  <Can permission="post:delete"><DeleteButton /></Can>
</PermissionsProvider>

const canExport = useCan('report:export');
```

- Built from the **current user's** permissions, typically returned by your
  session endpoint. Shipping the whole role table to the browser publishes
  your admin surface.
- Signed out, loading, or outside a provider: everything is denied.
- `<Can>` with no condition denies, and renders nothing by default rather
  than a message that confirms the feature exists.
- Without React: `permissionSet(granted).can('x')`.
