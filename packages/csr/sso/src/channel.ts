export interface SessionChannel {
  onLogout(handler: () => void): () => void;
  broadcastLogout(): void;
  close(): void;
}

/**
 * Logout in one tab clears every tab now, not on their next request: on a
 * shared machine the point of signing out is that the data leaves the screen.
 * BroadcastChannel where available, otherwise the `storage` event (fires in
 * other tabs only). Carries no data, only the fact.
 */
export function sessionChannel(namespace = 'app'): SessionChannel {
  const name = `cs:session:${namespace}`;
  const handlers = new Set<() => void>();
  const fire = () => {
    for (const handler of handlers) {
      try {
        handler();
      } catch {
        // One failing subscriber must not keep the others signed in.
      }
    }
  };

  let channel: BroadcastChannel | null = null;
  let onStorage: ((event: StorageEvent) => void) | null = null;
  if (typeof BroadcastChannel !== 'undefined') {
    channel = new BroadcastChannel(name);
    channel.onmessage = (event: MessageEvent<unknown>) => {
      if ((event.data as { type?: unknown } | null)?.type === 'logout') fire();
    };
  } else if (typeof addEventListener === 'function') {
    onStorage = (event) => {
      if (event.key === name && event.newValue !== null) fire();
    };
    addEventListener('storage', onStorage);
  }

  return {
    onLogout(handler) {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    broadcastLogout() {
      if (channel) return channel.postMessage({ type: 'logout' });
      try {
        // Set then remove: the event fires on the set, and nothing is left behind.
        localStorage.setItem(name, String(Date.now()));
        localStorage.removeItem(name);
      } catch {
        // No storage: other tabs find out on their next 401.
      }
    },
    close() {
      handlers.clear();
      channel?.close();
      if (onStorage) removeEventListener('storage', onStorage);
    },
  };
}
