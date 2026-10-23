import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import { describe, it } from 'node:test';
import { bundleIdFor, captureUrl, CaptureError, normalizeUrl, writeBundle } from './capture.mjs';
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
  it('closes while a client connection is idle', { timeout: 5000 }, async () => {
    const proxy = await startEgressProxy();
    const idle = net.connect(Number(new URL(proxy.url).port), '127.0.0.1');
    await once(idle, 'connect');
    try {
      await proxy.close();
    } finally {
      idle.destroy();
    }
  });

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

describe('writeBundle manifest', () => {
  it('records the size and hash of rewritten CSS and totals the files on disk', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'brag-bundle-test-'));
    try {
      await mkdir(join(dir, 'assets'), { recursive: true });
      await mkdir(join(dir, 'screenshots'), { recursive: true });
      const originalCss = Buffer.from('.a{background:url(/hero.png)}');
      const captured = {
        html: '<html><head><link rel="stylesheet" href="/site.css"></head><body><img src="/hero.png"></body></html>',
        screenshots: {},
        bodies: [
          { url: 'https://example.com/site.css', mimeType: 'text/css', type: 'Stylesheet', data: originalCss },
          { url: 'https://example.com/hero.png', mimeType: 'image/png', type: 'Image', data: Buffer.from('89504e47', 'hex') },
        ],
        missing: [],
      };
      const manifest = await writeBundle(dir, {
        url: normalizeUrl('https://example.com/'),
        finalUrl: 'https://example.com/',
        captured,
        egress: [],
        startedAt: Date.now(),
        skipped: [],
      });

      const css = manifest.assets.find((asset) => asset.mimeType === 'text/css');
      const onDiskCss = await readFile(join(dir, css.file));
      assert.notEqual(onDiskCss.toString(), originalCss.toString());
      assert.equal(css.bytes, onDiskCss.length);
      assert.equal(css.sha256, createHash('sha256').update(onDiskCss).digest('hex'));

      let total = (await readFile(join(dir, manifest.document.file))).length;
      for (const asset of manifest.assets) {
        const onDisk = await readFile(join(dir, asset.file));
        assert.equal(asset.bytes, onDisk.length, asset.file);
        assert.equal(asset.sha256, createHash('sha256').update(onDisk).digest('hex'), asset.file);
        total += onDisk.length;
      }
      assert.equal(manifest.totalBytes, total);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('live capture', { skip: process.env.BRAG_LIVE_TESTS !== '1' }, () => {
  for (const raw of ['http://example.com/', 'https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%2F']) {
    it(`resolves and releases the proxy for ${raw}`, { timeout: 180000 }, async () => {
      const cacheRoot = await mkdtemp(join(tmpdir(), 'brag-live-test-'));
      try {
        const result = await captureUrl(raw, {
          cacheRoot,
          chromeBin: process.env.BRAG_CHROME_BIN ?? '/usr/bin/google-chrome',
        });
        assert.equal(result.cacheHit, false);
        assert.ok(result.manifest.assets.length + result.manifest.document.bytes > 0);
      } finally {
        await rm(cacheRoot, { recursive: true, force: true });
      }
    });
  }
});

describe('rewrite', () => {
  const pageUrl = 'https://example.com/index.html';
  const assets = new Map([
    ['https://example.com/style.css', 'aaaa.css'],
    ['https://example.com/hero.png', 'bbbb.png'],
    ['https://fonts.googleapis.com/css2?family=Roboto&display=swap', 'cccc.css'],
  ]);

  it('localizes stylesheet hrefs whose HTML-escaped ampersands match a captured URL', () => {
    const html = `<head><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto&amp;display=swap"></head>`;
    const { html: out, unresolved } = rewriteDocument(html, pageUrl, assets);
    assert.match(out, /href="assets\/cccc\.css"/);
    assert.deepEqual(unresolved, []);
  });

  it('reports unresolved stylesheet hrefs but not plain anchors', () => {
    const html = `<head><link rel="stylesheet" href="https://fonts.example.net/x.css"></head><body><a href="https://example.com/other">x</a></body>`;
    const { html: out, unresolved } = rewriteDocument(html, pageUrl, assets);
    assert.match(out, /href="https:\/\/fonts\.example\.net\/x\.css"/);
    assert.deepEqual(unresolved, ['https://fonts.example.net/x.css']);
  });

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

  it('reports CSS urls it could not localize', () => {
    const unresolved = new Set();
    rewriteCss(`@font-face{src:url(https://fonts.example.net/a.woff2)}`, pageUrl, assets, unresolved);
    assert.deepEqual([...unresolved], ['https://fonts.example.net/a.woff2']);
  });

  it('rewrites CSS url() to local assets and leaves unknown urls alone', () => {
    const css = `.a{background:url('/hero.png')} .b{background:url(/gone.png)}`;
    assert.equal(
      rewriteCss(css, 'https://example.com/css/site.css', new Map([['https://example.com/hero.png', 'bbbb.png']])),
      `.a{background:url('bbbb.png')} .b{background:url(/gone.png)}`,
    );
  });
});
