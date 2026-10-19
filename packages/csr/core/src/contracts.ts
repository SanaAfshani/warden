/**
 * Where strings are kept. Async because the most useful decorator,
 * encryption, is async: Web Crypto has no synchronous API.
 */
export interface KeyValueStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  /** Every key visible through this store, as this store names them. */
  keys(): Promise<string[]>;
}

/** The `fetch` signature, so a decorated fetch is a drop-in replacement. */
export type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Something security-relevant happened in the browser (an unreadable stored
 * value, an expired session). Plugins report through an `onEvent` option and
 * never log or phone home on their own.
 */
export interface SecurityEvent {
  /** `<plugin>.<what>`, e.g. `storage.unreadable`, `sso.session_expired`. */
  readonly type: string;
  readonly reason?: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

export type SecurityEventHandler = (event: SecurityEvent) => void;

/** A throwing handler must not break the control that reported. */
export function emit(handler: SecurityEventHandler | undefined, event: SecurityEvent): void {
  if (!handler) return;
  try {
    handler(event);
  } catch {
    // Deliberately swallowed; see above.
  }
}
