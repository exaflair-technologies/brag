import net from 'node:net';

const BLOCKED_IPV4 = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const ipv4ToInt = (ip) => ip.split('.').reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);

const inIpv4Cidr = (ip, [base, bits]) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ipv4ToInt(ip) & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
};

export function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    return !BLOCKED_IPV4.some((cidr) => inIpv4Cidr(address, cidr));
  }
  if (family === 6) {
    const firstHextet = parseInt(address.split(':')[0], 16);
    return firstHextet >= 0x2000 && firstHextet <= 0x3fff;
  }
  return false;
}
