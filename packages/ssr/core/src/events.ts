/**
 * A security-relevant decision, reported by a plugin through its `onEvent`
 * option. Plugins never log on their own: where events go (a logger, a SIEM,
 * an audit table, nowhere) is the application's choice.
 */
export interface SecurityEvent {
  /** `<plugin>.<what>`, e.g. `csrf.rejected`, `ratelimit.exceeded`, `access.denied`. */
  readonly type: string;
  readonly outcome: 'success' | 'failure' | 'blocked';
  /** Machine-readable cause, e.g. `origin_mismatch`. Never contains input values. */
  readonly reason?: string;
  readonly actorId?: string;
  readonly target?: string;
  readonly request?: Request;
  readonly data?: Readonly<Record<string, unknown>>;
}

export type SecurityEventHandler = (event: SecurityEvent) => void;

/** A failing event handler must never turn a security decision into a 500. */
export function emit(handler: SecurityEventHandler | undefined, event: SecurityEvent): void {
  if (!handler) return;
  try {
    handler(event);
  } catch {
    // Deliberately swallowed; see above.
  }
}
