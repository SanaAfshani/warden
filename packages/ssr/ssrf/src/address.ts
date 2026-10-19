import { isIP } from 'node:net';

function toBigInt(ip: string): { value: bigint; bits: 32 | 128 } | null {
  const version = isIP(ip);
  if (version === 4) {
    let value = 0n;
    for (const part of ip.split('.')) value = (value << 8n) | BigInt(Number(part));
    return { value, bits: 32 };
  }
  if (version !== 6) return null;
  // An IPv4 tail (`::ffff:127.0.0.1`) is converted, not read as hex: that is the mapped-loopback bypass.
  const expand = (group: string): string[] => {
    if (!group.includes('.')) return [group];
    const [a = 0, b = 0, c = 0, d = 0] = group.split('.').map(Number);
    return [((a << 8) | b).toString(16), ((c << 8) | d).toString(16)];
  };
  const [head = '', tail = ''] = ip.split('::');
  const left = head.split(':').filter(Boolean).flatMap(expand);
  const right = tail.split(':').filter(Boolean).flatMap(expand);
  const fill = ip.includes('::') ? 8 - left.length - right.length : 0;
  if (fill < 0) return null;
  const groups = [...left, ...new Array<string>(fill).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(Number.parseInt(group, 16));
  return { value, bits: 128 };
}

const RANGES: { network: bigint; prefix: number; bits: 32 | 128; label: string }[] = [
  ['0.0.0.0/8', 'this network (localhost on Linux)'],
  ['10.0.0.0/8', 'private'],
  ['100.64.0.0/10', 'carrier-grade NAT'],
  ['127.0.0.0/8', 'loopback'],
  ['169.254.0.0/16', 'link-local, cloud metadata'],
  ['172.16.0.0/12', 'private'],
  ['192.0.0.0/24', 'IETF protocol assignments'],
  ['192.0.2.0/24', 'documentation'],
  ['192.168.0.0/16', 'private'],
  ['198.18.0.0/15', 'benchmarking'],
  ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'],
  ['::/128', 'unspecified'],
  ['::1/128', 'loopback'],
  ['::ffff:0:0/96', 'IPv4-mapped'],
  ['64:ff9b::/96', 'NAT64'],
  ['100::/64', 'discard'],
  ['2001:db8::/32', 'documentation'],
  ['fc00::/7', 'unique local'],
  ['fe80::/10', 'link-local'],
  ['ff00::/8', 'multicast'],
].map(([notation = '', label = '']) => {
  const [address = '', prefix = ''] = notation.split('/');
  const parsed = toBigInt(address);
  if (!parsed) throw new Error(`Bad CIDR: ${notation}`);
  return { network: parsed.value, prefix: Number(prefix), bits: parsed.bits, label };
});

/** Private, loopback, link-local (cloud metadata), CGNAT, IPv4-mapped and the rest. Unparseable counts as blocked. */
export function blockedRange(ip: string): string | null {
  const parsed = toBigInt(ip);
  if (!parsed) return 'unparseable';
  for (const range of RANGES) {
    if (range.bits !== parsed.bits) continue;
    const shift = BigInt(range.bits - range.prefix);
    if (parsed.value >> shift === range.network >> shift) return range.label;
  }
  return null;
}
