import http from 'node:http';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { isPublicAddress } from './ssrf.mjs';

const ALLOWED_PORTS = new Set([80, 443]);
const HOP_BY_HOP = ['proxy-connection', 'proxy-authorization'];

const stripBrackets = (host) => host.replace(/^\[|\]$/g, '');

async function resolvePublic(hostname, port) {
  if (!ALLOWED_PORTS.has(port)) {
    return { refused: 'port_not_allowed' };
  }
  const host = stripBrackets(hostname);
  const addresses = net.isIP(host)
    ? [{ address: host }]
    : await lookup(host, { all: true, verbatim: true }).catch(() => []);
  if (addresses.length === 0) {
    return { refused: 'dns_failed' };
  }
  if (!addresses.every(({ address }) => isPublicAddress(address))) {
    return { refused: 'non_public_address' };
  }
  return { address: addresses[0].address };
}

export function startEgressProxy() {
  const events = [];
  const record = (host, decision, reason) => events.push({ host, decision, reason });

  const server = http.createServer((req, res) => {
    let target;
    try {
      target = new URL(req.url);
    } catch {
      res.writeHead(400).end();
      return;
    }
    const host = stripBrackets(target.hostname);
    if (target.protocol !== 'http:') {
      record(host, 'refused', 'scheme_not_allowed');
      res.writeHead(403).end();
      return;
    }
    resolvePublic(host, Number(target.port || 80)).then((resolved) => {
      if (resolved.refused) {
        record(host, 'refused', resolved.refused);
        res.writeHead(403).end();
        return;
      }
      record(host, 'allowed', 'public');
      const headers = { ...req.headers, host: target.host };
      HOP_BY_HOP.forEach((name) => delete headers[name]);
      const upstream = http.request(
        {
          host: resolved.address,
          port: Number(target.port || 80),
          method: req.method,
          path: `${target.pathname}${target.search}`,
          headers,
        },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
          upstreamRes.pipe(res);
        },
      );
      upstream.on('error', () => {
        if (!res.headersSent) res.writeHead(502);
        res.end();
      });
      req.pipe(upstream);
    });
  });

  server.on('connect', (req, clientSocket, head) => {
    const separator = req.url.lastIndexOf(':');
    const hostname = stripBrackets(req.url.slice(0, separator));
    const port = Number(req.url.slice(separator + 1));
    clientSocket.on('error', () => {});
    resolvePublic(hostname, port).then((resolved) => {
      if (resolved.refused) {
        record(hostname, 'refused', resolved.refused);
        clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        return;
      }
      record(hostname, 'allowed', 'public');
      const upstream = net.connect({ host: resolved.address, port }, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on('error', () => clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
      clientSocket.on('close', () => upstream.destroy());
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        events,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}
