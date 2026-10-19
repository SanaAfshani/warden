import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { describe, expect, it } from 'vitest';
import { jsonStore, memoryStore } from '../src/index.js';
import { useStoredValue, type StoredValue } from '../src/react.js';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe('useStoredValue', () => {
  it('loads, writes and removes through the store', async () => {
    const store = jsonStore<{ count: number }>(memoryStore());
    await store.set('count', 1);
    let latest: StoredValue<number> | undefined;
    const Probe = () => {
      latest = useStoredValue(store, 'count');
      return null;
    };
    const root = createRoot(document.createElement('div'));
    await act(async () => root.render(createElement(Probe)));
    expect(latest?.loading).toBe(false);
    expect(latest?.value).toBe(1);

    await act(async () => latest?.set(2));
    expect(latest?.value).toBe(2);
    expect(await store.get('count')).toBe(2);

    await act(async () => latest?.remove());
    expect(latest?.value).toBeNull();
    root.unmount();
  });
});
