import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { describe, it } from 'node:test';
import { bundleIdFor, captureUrl, CaptureError, normalizeUrl } from './capture.mjs';
import { startEgressProxy } from './proxy.mjs';
import { isPublicAddress } from './ssrf.mjs';
import { rewriteCss, rewriteDocument } from './rewrite.mjs';

function sendConnect(proxyUrl, target) {
  const { port } = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const socket = net.connect(Number(port), '127.0.0.1', () => {
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (data.includes('\r\n')) {
        socket.destroy();
        resolve(data.split('\r\n')[0]);
      }
    });
    socket.on('error', reject);
    socket.on('close', () => resolve(data.split('\r\n')[0]));
  });
}

describe('isPublicAddress', () => {
  it('accepts public IPv4 addresses', () => {
    assert.equal(isPublicAddress('93.184.216.34'), true);
    assert.equal(isPublicAddress('1.1.1.1'), true);
  });

  it('refuses non-public IPv4 ranges', () => {
    for (const address of [
      '0.0.0.0',
      '10.1.2.3',
      '100.64.0.1',
      '127.0.0.1',
      '169.254.169.254',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '198.18.0.1',
      '224.0.0.1',
      '255.255.255.255',
    ]) {
      assert.equal(isPublicAddress(address), false, address);
    }
  });

  it('keeps 172.32.x.x public', () => {
    assert.equal(isPublicAddress('172.32.0.1'), true);
  });

  it('accepts only global-unicast IPv6 and refuses loopback, link-local, ULA', () => {
    assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
    assert.equal(isPublicAddress('::1'), false);
    assert.equal(isPublicAddress('fe80::1'), false);
    assert.equal(isPublicAddress('fd00::1'), false);
    assert.equal(isPublicAddress('::ffff:127.0.0.1'), false);
  });

  it('refuses non-IP input', () => {
    assert.equal(isPublicAddress('example.com'), false);
  });
});

describe('egress proxy', () => {
  it('refuses CONNECT to loopback, metadata, private, and localhost targets', async () => {
    const proxy = await startEgressProxy();
    try {
      for (const target of ['127.0.0.1:443', '169.254.169.254:443', '10.0.0.5:443', 'localhost:443', '[::1]:443']) {
        assert.match(await sendConnect(proxy.url, target), /403/, target);
      }
      assert.ok(proxy.events.every((event) => event.decision === 'refused'));
      assert.equal(proxy.events.length, 5);
    } finally {
      await proxy.close();
    }
  });

  it('refuses ports other than 80 and 443', async () => {
    const proxy = await startEgressProxy();
    try {
      assert.match(await sendConnect(proxy.url, '93.184.216.34:22'), /403/);
      assert.equal(proxy.events[0].reason, 'port_not_allowed');
    } finally {
      await proxy.close();
    }
  });

  it('refuses absolute-URI HTTP requests to private addresses', async () => {
    const proxy = await startEgressProxy();
    try {
      const status = await new Promise((resolve, reject) => {
        const { port } = new URL(proxy.url);
        const socket = net.connect(Number(port), '127.0.0.1', () => {
          socket.write('GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n');
        });
        let data = '';
        socket.on('data', (chunk) => {
          data += chunk.toString();
          if (data.includes('\r\n')) {
            socket.destroy();
            resolve(data.split('\r\n')[0]);
          }
        });
        socket.on('error', reject);
      });
      assert.match(status, /403/);
      assert.equal(proxy.events[0].reason, 'non_public_address');
    } finally {
      await proxy.close();
    }
  });
});

describe('normalizeUrl and bundle ids', () => {
  it('drops fragments and keeps the same bundle id for equal URLs', () => {
    const a = normalizeUrl('https://Example.com/page#top');
    const b = normalizeUrl('https://example.com/page');
    assert.equal(a.href, b.href);
    assert.equal(bundleIdFor(a), bundleIdFor(b));
    assert.match(bundleIdFor(a), /^b_[0-9a-f]{16}$/);
  });

  it('refuses non-http schemes, credentials, and garbage', () => {
    for (const raw of ['file:///etc/passwd', 'ftp://example.com/', 'https://user:pw@example.com/', 'not a url']) {
      assert.throws(() => normalizeUrl(raw), CaptureError, raw);
    }
  });
});

describe('captureUrl cache', () => {
  it('returns the cached bundle without launching a browser', async () => {
    const cacheRoot = await mkdtemp(join(tmpdir(), 'brag-cache-test-'));
    try {
      const url = normalizeUrl('https://example.com/');
      const dir = join(cacheRoot, bundleIdFor(url));
      await mkdir(dir, { recursive: true });
      const manifest = { schema: 'brag.bundle.v1', sourceUrl: url.href, totalBytes: 1, assets: [] };
      await writeFile(join(dir, 'manifest.json'), JSON.stringify(manifest));

      const events = [];
      const result = await captureUrl('https://example.com/', {
        cacheRoot,
        chromeBin: '/nonexistent',
        launchBrowser: async () => {
          throw new Error('browser must not launch on cache hit');
        },
        log: (event) => events.push(event),
      });
      assert.equal(result.cacheHit, true);
      assert.equal(result.manifest.sourceUrl, url.href);
      assert.deepEqual(events.map((event) => event.type), ['capture.cache_hit']);
    } finally {
      await rm(cacheRoot, { recursive: true, force: true });
    }
  });

  it('leaves no partial directory behind when capture fails', async () => {
    const cacheRoot = await mkdtemp(join(tmpdir(), 'brag-cache-test-'));
    try {
      await assert.rejects(
        captureUrl('https://example.com/', {
          cacheRoot,
          chromeBin: '/nonexistent',
          launchBrowser: async () => {
            throw new Error('chrome exploded');
          },
        }),
        /chrome exploded/,
      );
      const { readdir } = await import('node:fs/promises');
      assert.deepEqual(await readdir(cacheRoot), []);
    } finally {
      await rm(cacheRoot, { recursive: true, force: true });
    }
  });
});

describe('rewrite', () => {
  const pageUrl = 'https://example.com/index.html';
  const assets = new Map([
    ['https://example.com/style.css', 'aaaa.css'],
    ['https://example.com/hero.png', 'bbbb.png'],
  ]);

  it('strips scripts and preload links, rewrites refs to local assets, and injects CSP', () => {
    const html = `<html><head><link rel="preload" href="/hero.png"><link rel="stylesheet" href="/style.css"><script>alert(1)</script></head>` +
      `<body><img src="hero.png" srcset="hero.png 1x, /missing.png 2x"><a href="/other">x</a></body></html>`;
    const { html: out, unresolved } = rewriteDocument(html, pageUrl, assets);
    assert.doesNotMatch(out, /<script/i);
    assert.doesNotMatch(out, /rel="preload"/);
    assert.match(out, /href="assets\/aaaa\.css"/);
    assert.match(out, /src="assets\/bbbb\.png"/);
    assert.match(out, /srcset="assets\/bbbb\.png 1x, \/missing\.png 2x"/);
    assert.match(out, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'/);
    assert.deepEqual(unresolved, ['https://example.com/missing.png']);
  });

  it('rewrites CSS url() to local assets and leaves unknown urls alone', () => {
    const css = `.a{background:url('/hero.png')} .b{background:url(/gone.png)}`;
    assert.equal(
      rewriteCss(css, 'https://example.com/css/site.css', new Map([['https://example.com/hero.png', 'bbbb.png']])),
      `.a{background:url('bbbb.png')} .b{background:url(/gone.png)}`,
    );
  });
});
