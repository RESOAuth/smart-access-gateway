// IP address classification for outbound requests.
//
// This is intentionally stricter than "not RFC 1918". Loopback, link-local,
// carrier-grade NAT, documentation, benchmarking, multicast, and reserved
// ranges are not public destinations either, and none belongs behind a client
// metadata URL supplied by an unauthenticated caller.

function ipv4Number(value) {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return undefined;
  return parts.reduce((number, part) => number * 256 + Number(part), 0);
}

function inV4Range(number, base, bits) {
  const size = 2 ** (32 - bits);
  return number >= base && number < base + size;
}

export function isPublicIpv4(value) {
  const number = ipv4Number(value);
  if (number === undefined) return false;
  const blocked = [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
  ];
  return !blocked.some(([base, bits]) => inV4Range(number, ipv4Number(base), bits));
}

function ipv6Parts(value) {
  let text = value.toLowerCase();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);

  const ipv4 = text.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4) {
    const number = ipv4Number(ipv4);
    if (number === undefined) return undefined;
    text = text.slice(0, -ipv4.length) + ((number >>> 16) & 0xffff).toString(16) + ':' + (number & 0xffff).toString(16);
  }

  if ((text.match(/::/g) || []).length > 1) return undefined;
  const [left, right] = text.split('::');
  const before = left ? left.split(':') : [];
  const after = right ? right.split(':') : [];
  if (before.some((part) => !/^[0-9a-f]{1,4}$/.test(part)) || after.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) {
    return undefined;
  }
  const missing = 8 - before.length - after.length;
  if ((text.includes('::') && missing < 1) || (!text.includes('::') && missing !== 0)) return undefined;
  return [...before, ...Array(missing).fill('0'), ...after].map((part) => Number.parseInt(part, 16));
}

export function isLoopbackIp(value) {
  const v4 = ipv4Number(value);
  if (v4 !== undefined) return inV4Range(v4, ipv4Number('127.0.0.0'), 8);
  const parts = ipv6Parts(value);
  return Boolean(parts && parts.slice(0, 7).every((part) => part === 0) && parts[7] === 1);
}

export function isPublicIpv6(value) {
  const parts = ipv6Parts(value);
  if (!parts) return false;

  // IPv4-mapped addresses retain the reachability of their embedded address.
  if (parts.slice(0, 5).every((part) => part === 0) && parts[5] === 0xffff) {
    return isPublicIpv4([parts[6] >>> 8, parts[6] & 255, parts[7] >>> 8, parts[7] & 255].join('.'));
  }

  // Global unicast is 2000::/3. Documentation addresses are syntactically in
  // that range but deliberately not reachable on the public Internet.
  const global = (parts[0] & 0xe000) === 0x2000;
  const documentation = parts[0] === 0x2001 && parts[1] === 0x0db8;
  const benchmarking = parts[0] === 0x2001 && parts[1] === 0x0002 && parts[2] === 0;
  return global && !documentation && !benchmarking;
}

export function isPublicIp(value) {
  return value.includes(':') ? isPublicIpv6(value) : isPublicIpv4(value);
}

export function isIpAddress(value) {
  return ipv4Number(value) !== undefined || ipv6Parts(value) !== undefined;
}
