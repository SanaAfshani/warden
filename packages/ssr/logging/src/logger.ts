import {
  clientIp,
  type ClientIpOptions,
  type SecurityEvent,
  type SecurityEventHandler,
} from '@sanaafshani/warden-ssr';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Record<string, unknown>;
export interface LogRecord extends LogFields {
  time: string;
  level: LogLevel;
  msg: string;
}

export interface LoggerOptions {
  /** Default `info`. */
  level?: LogLevel;
  /** Default: one JSON line on stdout/stderr, which every serious platform collects. */
  sink?: (record: LogRecord) => void;
  /** Keys whose values never leave the process, at any depth. Replaces the default list. */
  redactKeys?: readonly string[];
  /** Default 2048. */
  maxFieldLength?: number;
  /** Fields on every line. */
  fields?: LogFields;
  /** Used by `event` to report the client IP (truncated). */
  ip?: ClientIpOptions;
}

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(fields: LogFields): Logger;
  /** Pass as `onEvent` to any plugin; also the audit call for your own events. */
  event: SecurityEventHandler;
}

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const DEFAULT_REDACT = [
  'password', 'newPassword', 'currentPassword', 'passwordConfirm', 'token', 'accessToken',
  'refreshToken', 'idToken', 'secret', 'apiKey', 'authorization', 'cookie', 'setCookie',
  'sessionId', 'csrf', 'creditCard', 'cardNumber', 'cvv', 'ssn', 'privateKey',
];

/** `refresh_token` → [refresh, token]; `x-api-key` → [x, api, key]. */
const tokenise = (key: string) =>
  key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .flatMap((part) => part.split(' '))
    .map((part) => part.toLowerCase())
    .filter(Boolean);

/**
 * Redacts when any contiguous run of key tokens spells a needle: catches
 * `userPassword` and `x-api-key`, but not `sessionIdleTtlSeconds` (a plain
 * substring match over-redacted it). Over-redaction is the right failure.
 */
function sensitiveMatcher(keys: readonly string[]) {
  const needles = new Set(keys.map((key) => key.toLowerCase().replace(/[^a-z0-9]/g, '')));
  return (key: string) => {
    const tokens = tokenise(key);
    for (let start = 0; start < tokens.length; start++) {
      let joined = '';
      for (let end = start; end < tokens.length; end++) {
        joined += tokens[end];
        if (needles.has(joined)) return true;
      }
    }
    return false;
  };
}

/** Control characters and line breaks out, so input cannot forge a second log line. */
const singleLine = (value: string) =>
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  value.replace(/[\u0000-\u001F\u007F-\u009F\u2028\u2029]+/gu, ' ');

export function createLogger(options: LoggerOptions = {}): Logger {
  const threshold = ORDER[options.level ?? 'info'];
  const isSensitive = sensitiveMatcher(options.redactKeys ?? DEFAULT_REDACT);
  const maxLength = options.maxFieldLength ?? 2048;
  const sink = options.sink ?? console_;

  // Bounded in depth, breadth and cycles: a logger must never take the process down.
  const redact = (value: unknown, depth: number, seen: WeakSet<object>): unknown => {
    if (depth > 8) return '[max-depth]';
    if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'string') {
      return value.length > maxLength ? `${value.slice(0, maxLength)}…[truncated]` : value;
    }
    if (typeof value === 'bigint') return value.toString();
    if (value instanceof Date) return value.toISOString();
    if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
    if (typeof value !== 'object') return '[unloggable]';
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    if (Array.isArray(value)) return value.slice(0, 100).map((item) => redact(item, depth + 1, seen));
    const out: Record<string, unknown> = {};
    let count = 0;
    for (const [key, nested] of Object.entries(value)) {
      if (count++ >= 200) {
        out['…'] = '[truncated]';
        break;
      }
      out[key] = isSensitive(key) ? '[redacted]' : redact(nested, depth + 1, seen);
    }
    return out;
  };

  const write = (level: LogLevel, message: string, fields: LogFields) => {
    if (ORDER[level] < threshold) return;
    const record: LogRecord = {
      ...(redact(fields, 0, new WeakSet()) as LogFields),
      time: new Date().toISOString(),
      level,
      msg: singleLine(message).slice(0, 512),
    };
    try {
      sink(record);
    } catch {
      // A failing sink must not fail the request, nor lose the line silently.
      console_({ ...record, sinkFailed: true });
    }
  };

  const make = (bound: LogFields): Logger => {
    const logger: Logger = {
      debug: (m, f) => write('debug', m, { ...bound, ...f }),
      info: (m, f) => write('info', m, { ...bound, ...f }),
      warn: (m, f) => write('warn', m, { ...bound, ...f }),
      error: (m, f) => write('error', m, { ...bound, ...f }),
      child: (extra) => make({ ...bound, ...extra }),
      event: (event: SecurityEvent) => {
        const { request, ...rest } = event;
        const where = request
          ? {
              method: request.method,
              path: new URL(request.url).pathname,
              ip: clientIpForLog(clientIp(request, options.ip)),
            }
          : {};
        logger[event.outcome === 'success' ? 'info' : 'warn'](event.type, { ...rest, ...where });
      },
    };
    return logger;
  };
  return make(options.fields ?? {});
}

function console_(record: LogRecord): void {
  const line = JSON.stringify(record);
  if (record.level === 'error') console.error(line);
  else if (record.level === 'warn') console.warn(line);
  else console.log(line);
}

/**
 * IP addresses are personal data. Keep the /24 (IPv4) or /48 (IPv6): enough
 * to see "many attempts from one subnet", not enough to identify a person.
 */
export function clientIpForLog(ip: string): string {
  if (ip === 'unknown' || ip === '::1' || ip === '::') return ip;
  if (ip.includes(':')) {
    const groups = ip.split(':').filter(Boolean);
    return groups.length <= 3 ? ip : `${groups.slice(0, 3).join(':')}::/48`;
  }
  const parts = ip.split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'invalid';
}
