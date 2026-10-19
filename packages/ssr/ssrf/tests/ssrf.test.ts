import { describe, expect, it } from 'vitest';
import { blockedRange, createSafeFetch, SsrfBlockedError } from '../src/index.js';

describe('blockedRange', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '::1',
    'fc00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
    '::ffff:a9fe:a9fe',
  ])('blocks %s', (ip) => {
    expect(blockedRange(ip)).not.toBeNull();
  });

  it('allows public addresses', () => {
    expect(blockedRange('93.184.216.34')).toBeNull();
    expect(blockedRange('2606:4700::1111')).toBeNull();
  });
});

describe('createSafeFetch', () => {
  const safeFetch = createSafeFetch({ allowedHosts: ['api.partner.test', '.cdn.test', '127.0.0.1', '2130706433'] });
  const reason = async (url: string) => {
    try {
      await safeFetch(url);
      return 'allowed';
    } catch (error) {
      expect(error).toBeInstanceOf(SsrfBlockedError);
      return (error as SsrfBlockedError).reason;
    }
  };

  it('requires https', async () => {
    expect(await reason('http://api.partner.test/x')).toBe('scheme');
  });

  it('rejects credentials in the URL, which fool prefix checks', async () => {
    expect(await reason('https://api.partner.test@evil.example/')).toBe('credentials');
  });

  it('allows only listed hosts; a suffix entry does not match lookalikes', async () => {
    expect(await reason('https://evil.example/')).toBe('host');
    expect(await reason('https://evilcdn.test/')).toBe('host');
  });

  it('allows only listed ports', async () => {
    expect(await reason('https://api.partner.test:6379/')).toBe('port');
  });

  it('blocks private addresses even when the host is allowlisted, including integer IP spellings', async () => {
    expect(await reason('https://127.0.0.1/')).toBe('private_address');
    expect(await reason('https://2130706433/')).toBe('private_address');
  });
});
