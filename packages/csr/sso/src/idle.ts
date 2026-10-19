export interface IdleTimeoutOptions {
  /** Sign out after this long without activity. */
  idleSeconds: number;
  /** Sign out this long after `start()` regardless of activity. */
  absoluteSeconds?: number;
  /** Warn this long before the idle deadline. Default 60. */
  warnSeconds?: number;
  /** Check interval. Default 5. */
  tickSeconds?: number;
  onWarn?: (secondsLeft: number) => void;
  onTimeout: (reason: 'idle' | 'absolute') => void;
  events?: readonly string[];
  /**
   * Activity in one tab counts in all tabs of `namespace`. Without this, a
   * background tab times out and its logout broadcast signs out the user
   * typing in another tab. Default true where BroadcastChannel exists.
   */
  crossTab?: boolean;
  namespace?: string;
  target?: EventTarget;
}

export interface IdleTimeout {
  start(): void;
  stop(): void;
  /** The user chose to stay. */
  extend(): void;
  idleFor(): number;
}

const DEFAULT_EVENTS = ['pointerdown', 'keydown', 'touchstart', 'scroll', 'wheel'];

/**
 * Defends against the unattended screen (shared workstation, open laptop),
 * not against code on the page, which can stop the timer. It is the UI half:
 * the server's session lifetime is what binds.
 */
export function idleTimeout(options: IdleTimeoutOptions): IdleTimeout {
  const { idleSeconds, absoluteSeconds, warnSeconds = 60, tickSeconds = 5, onWarn, onTimeout } = options;
  const events = options.events ?? DEFAULT_EVENTS;
  const target = options.target ?? globalThis;
  // `capture` so a component calling stopPropagation cannot make the session immortal.
  // Removal must pass the same `capture` value, or the listener stays attached.
  const listenerOptions = { passive: true, capture: true } as const;

  let lastActivity = Date.now();
  let startedAt = Date.now();
  let lastShared = 0;
  let warned = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  let channel: BroadcastChannel | null = null;

  const touch = (at = Date.now()) => {
    lastActivity = Math.max(lastActivity, at);
    warned = false;
  };
  const onActivity = () => {
    touch();
    if (channel && lastActivity - lastShared >= tickSeconds * 1000) {
      lastShared = lastActivity;
      channel.postMessage(lastActivity);
    }
  };
  // Background tabs throttle timers; check the moment the tab is visible again.
  const onVisible = () => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') check();
  };

  function check(): void {
    if (timer === null) return;
    const now = Date.now();
    if (absoluteSeconds !== undefined && now - startedAt >= absoluteSeconds * 1000) {
      stop();
      return onTimeout('absolute');
    }
    const idleMs = now - lastActivity;
    if (idleMs >= idleSeconds * 1000) {
      stop();
      return onTimeout('idle');
    }
    const secondsLeft = Math.ceil((idleSeconds * 1000 - idleMs) / 1000);
    if (!warned && onWarn && secondsLeft <= warnSeconds) {
      warned = true;
      onWarn(secondsLeft);
    }
  }

  function stop(): void {
    if (timer === null) return;
    clearInterval(timer);
    timer = null;
    for (const event of events) target.removeEventListener(event, onActivity, listenerOptions);
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisible);
    channel?.close();
    channel = null;
  }

  return {
    start() {
      if (timer !== null) return;
      startedAt = lastActivity = Date.now();
      warned = false;
      for (const event of events) target.addEventListener(event, onActivity, listenerOptions);
      if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisible);
      if ((options.crossTab ?? true) && typeof BroadcastChannel !== 'undefined') {
        channel = new BroadcastChannel(`cs:idle:${options.namespace ?? 'app'}`);
        channel.onmessage = (event: MessageEvent<unknown>) => {
          if (typeof event.data === 'number' && event.data <= Date.now()) touch(event.data);
        };
      }
      timer = setInterval(check, tickSeconds * 1000);
    },
    stop,
    extend: () => onActivity(),
    idleFor: () => Math.floor((Date.now() - lastActivity) / 1000),
  };
}
