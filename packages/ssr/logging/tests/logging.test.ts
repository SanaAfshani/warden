import { describe, expect, it } from 'vitest';
import { chain, HttpError } from '@sanaafshani/warden-ssr';
import { clientIpForLog, createLogger, requestLogger, type LogRecord } from '../src/index.js';

const capture = () => {
  const lines: LogRecord[] = [];
  return { lines, logger: createLogger({ sink: (record) => lines.push(record) }) };
};

describe('createLogger', () => {
  it('redacts secrets at any depth and under any casing of the key', () => {
    const { lines, logger } = capture();
    logger.info('login', {
      userPassword: 'hunter2',
      headers: { Authorization: 'Bearer abc', 'x-api-key': 'k' },
      nested: [{ refresh_token: 'r' }],
      sessionIdleTtlSeconds: 1800,
    });
    const text = JSON.stringify(lines[0]);
    for (const secret of ['hunter2', 'Bearer abc', '"k"', '"r"']) expect(text).not.toContain(secret);
    expect(lines[0]?.sessionIdleTtlSeconds).toBe(1800);
  });

  it('keeps input on one line, so a newline cannot forge a second log entry', () => {
    const { lines, logger } = capture();
    logger.warn('user said\n{"level":"info","msg":"admin login ok"}');
    expect(lines[0]?.msg).not.toContain('\n');
  });

  it('survives cyclic objects', () => {
    const { lines, logger } = capture();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    logger.info('x', { cyclic });
    expect(lines).toHaveLength(1);
  });

  it('truncates IPs to the network, for data minimisation', () => {
    expect(clientIpForLog('203.0.113.77')).toBe('203.0.113.0/24');
  });
});

describe('requestLogger', () => {
  it('turns an unexpected error into an opaque 500 that carries only the request id', async () => {
    const { lines, logger } = capture();
    const handler = chain()
      .use(requestLogger(logger))
      .handle(() => {
        throw new Error('db password is hunter2 at 10.0.0.5');
      });
    const response = await handler(new Request('https://a.test/x'));
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).not.toContain('hunter2');
    expect(text).toContain(response.headers.get('x-request-id'));
    expect(lines.some((line) => line.level === 'error')).toBe(true);
  });

  it('passes HttpErrors through as their own status', async () => {
    const { logger } = capture();
    const handler = chain()
      .use(requestLogger(logger))
      .handle(() => {
        throw new HttpError(404, 'not_found', 'Not found.');
      });
    expect((await handler(new Request('https://a.test/x'))).status).toBe(404);
  });
});
