# @sanaafshani/warden-csr

The contract browser plugins build on. No controls, no configuration, no
dependencies.

```bash
npm i @sanaafshani/warden-csr
```

```ts
import { decorate, type Decorator, type KeyValueStore } from '@sanaafshani/warden-csr';

const logged: Decorator<KeyValueStore> = (inner) => ({
  ...inner,
  set: async (key, value) => {
    console.debug('write', key);
    return inner.set(key, value);
  },
});

const store = decorate(base, logged, otherDecorator); // logged(otherDecorator(base))
```

| | |
| --- | --- |
| `Decorator<T>`, `decorate(base, ...decorators)` | First listed is outermost. See [docs/csr.md](../../../docs/csr.md). |
| `KeyValueStore` | Async string store; what storage decorators wrap. |
| `Fetcher` | The `fetch` signature; what fetch decorators wrap. |
| `emit`, `SecurityEvent` | The event shape plugins report through `onEvent`. |
| `SecurityRegistry`, `Permission` | Augment once with your permission names; `-access` reads them. |
