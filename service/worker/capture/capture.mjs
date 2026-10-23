import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { connectCdp, launchChrome } from './browser.mjs';
import { startEgressProxy } from './proxy.mjs';
import { rewriteCss, rewriteDocument } from './rewrite.mjs';

const LIMITS = { totalBytes: 60 * 1024 * 1024, assetBytes: 15 * 1024 * 1024 };
const SAVED_TYPES = new Set(['Stylesheet', 'Image', 'Font', 'Media']);
const VIEWPORTS = {
  desktop: { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false },
  mobile: { width: 390, height: 844, deviceScaleFactor: 1, mobile: true },
};
const EXTENSIONS = {
  'text/css': '.css',
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'image/svg+xml': '.svg',
  'image/x-icon': '.ico',
  'image/avif': '.avif',
  'font/woff2': '.woff2',
  'font/woff': '.woff',
  'font/ttf': '.ttf',
  'font/otf': '.otf',
  'application/font-woff2': '.woff2',
  'application/font-woff': '.woff',
  'video/mp4': '.mp4',
  'video/webm': '.webm',
};

const SCROLL_THROUGH = `(async () => {
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const step = Math.max(300, Math.floor(innerHeight * 0.8));
  for (let y = 0; y < document.body.scrollHeight; y += step) {
    window.scrollTo(0, y);
    await sleep(250);
  }
  window.scrollTo(0, 0);
  await sleep(400);
  await document.fonts.ready;
  await Promise.all([...document.images].map((img) => img.complete ? null : new Promise((resolve) => {
    img.addEventListener('load', resolve, { once: true });
    img.addEventListener('error', resolve, { once: true });
    setTimeout(resolve, 5000);
  })));
  return true;
})()`;

export class CaptureError extends Error {
  constructor(failureReason, message) {
    super(message);
    this.failureReason = failureReason;
  }
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function normalizeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new CaptureError('capture_failed', 'input is not a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new CaptureError('capture_failed', 'only http and https URLs are accepted');
  }
  if (url.username || url.password) {
    throw new CaptureError('capture_failed', 'URLs with credentials are refused');
  }
  url.hash = '';
  return url;
}

export function bundleIdFor(url) {
  return `b_${sha256(url.href).slice(0, 16)}`;
}

async function exists(path) {
  return stat(path).then(
    () => true,
    () => false,
  );
}

async function waitUntil(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new CaptureError('timeout', `${label} timed out`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function capturePage(cdp, url) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const call = (method, params) => cdp.send(method, params, sessionId);

  const resources = new Map();
  const state = { inflight: 0, lastActivity: Date.now(), loaded: false };

  cdp.on((message) => {
    if (message.sessionId !== sessionId) return;
    const { method, params } = message;
    if (method === 'Network.requestWillBeSent') {
      state.inflight += 1;
      state.lastActivity = Date.now();
    } else if (method === 'Network.loadingFinished' || method === 'Network.loadingFailed') {
      state.inflight = Math.max(0, state.inflight - 1);
      state.lastActivity = Date.now();
    } else if (method === 'Network.responseReceived') {
      resources.set(params.requestId, {
        url: params.response.url.split('#')[0],
        status: params.response.status,
        mimeType: params.response.mimeType,
        type: params.type,
      });
    } else if (method === 'Page.loadEventFired') {
      state.loaded = true;
    }
  });

  await call('Page.enable');
  await call('Network.enable');
  await call('Runtime.enable');
  await call('Emulation.setDeviceMetricsOverride', VIEWPORTS.desktop);

  const navigation = await call('Page.navigate', { url: url.href });
  if (navigation.errorText) {
    throw new CaptureError('capture_failed', `navigation failed: ${navigation.errorText}`);
  }
  await waitUntil(() => state.loaded, 45000, 'page load');
  const waitIdle = () => waitUntil(
    () => state.inflight === 0 && Date.now() - state.lastActivity > 1500,
    15000,
    'network idle',
  ).catch(() => {});
  await waitIdle();

  await call('Runtime.evaluate', { expression: SCROLL_THROUGH, awaitPromise: true, returnByValue: true });
  await waitIdle();

  const { result: htmlResult } = await call('Runtime.evaluate', {
    expression: 'document.documentElement.outerHTML',
    returnByValue: true,
  });

  const screenshots = {};
  screenshots.desktop = (await call('Page.captureScreenshot', { format: 'jpeg', quality: 85 })).data;
  await call('Emulation.setDeviceMetricsOverride', VIEWPORTS.mobile);
  await new Promise((resolve) => setTimeout(resolve, 600));
  screenshots.mobile = (await call('Page.captureScreenshot', { format: 'jpeg', quality: 85 })).data;

  const bodies = [];
  const missing = [];
  for (const [requestId, resource] of resources) {
    if (!SAVED_TYPES.has(resource.type) || resource.status < 200 || resource.status >= 300) continue;
    const body = await call('Network.getResponseBody', { requestId }).catch(() => null);
    if (!body) {
      missing.push({ url: resource.url, reason: 'body_unavailable' });
      continue;
    }
    bodies.push({
      ...resource,
      data: body.base64Encoded ? Buffer.from(body.body, 'base64') : Buffer.from(body.body, 'utf8'),
    });
  }

  return { html: htmlResult.value, screenshots, bodies, missing };
}

function planAssets(bodies, skipped) {
  const assets = new Map();
  const files = [];
  let totalBytes = 0;
  for (const { url, mimeType, data } of bodies) {
    if (assets.has(url)) continue;
    if (data.length > LIMITS.assetBytes) {
      skipped.push({ url, reason: 'asset_too_large' });
      continue;
    }
    if (totalBytes + data.length > LIMITS.totalBytes) {
      skipped.push({ url, reason: 'bundle_size_cap' });
      continue;
    }
    const digest = sha256(data);
    const file = `${digest.slice(0, 16)}${EXTENSIONS[mimeType] ?? '.bin'}`;
    assets.set(url, file);
    files.push({ url, file, mimeType, data, sha256: digest });
    totalBytes += data.length;
  }
  return { assets, files, totalBytes };
}

async function writeBundle(tmpDir, { url, finalUrl, captured, egress, startedAt, skipped }) {
  const { assets, files, totalBytes: assetBytes } = planAssets(captured.bodies, skipped);
  for (const { file, data } of files) {
    await writeFile(join(tmpDir, 'assets', file), data);
  }
  const cssFiles = files.filter((asset) => asset.mimeType === 'text/css');
  for (const asset of cssFiles) {
    const css = asset.data.toString('utf8');
    await writeFile(join(tmpDir, 'assets', asset.file), rewriteCss(css, asset.url, assets));
  }

  const { html, unresolved } = rewriteDocument(captured.html, finalUrl, assets);
  const documentBytes = Buffer.byteLength(html);
  await writeFile(join(tmpDir, 'index.html'), html);

  const screenshots = [];
  for (const [viewport, data] of Object.entries(captured.screenshots)) {
    const file = `screenshots/${viewport}-top.jpg`;
    await writeFile(join(tmpDir, file), Buffer.from(data, 'base64'));
    screenshots.push({ file, viewport, width: VIEWPORTS[viewport].width, height: VIEWPORTS[viewport].height });
  }

  const manifest = {
    schema: 'brag.bundle.v1',
    sourceUrl: url.href,
    finalUrl,
    capturedAt: new Date().toISOString(),
    captureSeconds: Math.round((Date.now() - startedAt) / 100) / 10,
    document: { file: 'index.html', bytes: documentBytes },
    assets: files.map(({ url: source, file, mimeType, data, sha256: digest }) => ({
      file: `assets/${file}`,
      sourceUrl: source,
      mimeType,
      bytes: data.length,
      sha256: digest,
    })),
    screenshots,
    unresolvedRefs: unresolved,
    skipped,
    egress,
    totalBytes: documentBytes + assetBytes,
  };
  await writeFile(join(tmpDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

function summarizeEgress(events) {
  const seen = new Map();
  for (const { host, decision, reason } of events) {
    const key = `${decision}:${reason}:${host}`;
    seen.set(key, { host, decision, reason, count: (seen.get(key)?.count ?? 0) + 1 });
  }
  return [...seen.values()];
}

export async function captureUrl(rawUrl, options) {
  const { cacheRoot, chromeBin, launchBrowser = launchChrome, log = () => {} } = options;
  const url = normalizeUrl(rawUrl);
  const bundleId = bundleIdFor(url);
  const finalDir = join(cacheRoot, bundleId);
  const manifestPath = join(finalDir, 'manifest.json');

  if (await exists(manifestPath)) {
    log({ type: 'capture.cache_hit', bundleId });
    return { bundleId, cacheHit: true, dir: finalDir, manifest: JSON.parse(await readFile(manifestPath, 'utf8')) };
  }

  const startedAt = Date.now();
  const tmpDir = join(cacheRoot, `.tmp-${bundleId}-${randomBytes(4).toString('hex')}`);
  await mkdir(join(tmpDir, 'assets'), { recursive: true });
  await mkdir(join(tmpDir, 'screenshots'), { recursive: true });

  const proxy = await startEgressProxy();
  let browser;
  try {
    log({ type: 'capture.start', bundleId });
    browser = await launchBrowser({ chromeBin, proxyUrl: proxy.url });
    const cdp = await connectCdp(browser.wsUrl);
    const mainHost = url.hostname.replace(/^\[|\]$/g, '');
    const blocked = () => proxy.events.some((event) => event.decision === 'refused' && event.host === mainHost);
    const blockedError = () => new CaptureError('capture_blocked', 'page host resolves to a non-public address');
    let captured;
    try {
      captured = await capturePage(cdp, url);
    } catch (error) {
      if (blocked()) throw blockedError();
      throw error;
    } finally {
      cdp.close();
    }
    if (blocked()) throw blockedError();

    const egress = summarizeEgress(proxy.events);
    const skipped = [...captured.missing];
    const manifest = await writeBundle(tmpDir, {
      url,
      finalUrl: url.href,
      captured,
      egress,
      startedAt,
      skipped,
    });
    if (manifest.totalBytes > LIMITS.totalBytes) {
      throw new CaptureError('capture_failed', 'bundle exceeds size cap');
    }
    await rename(tmpDir, finalDir).catch(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });
    log({ type: 'capture.done', bundleId, bytes: manifest.totalBytes, assets: manifest.assets.length });
    return { bundleId, cacheHit: false, dir: finalDir, manifest };
  } catch (error) {
    await rm(tmpDir, { recursive: true, force: true });
    throw error;
  } finally {
    if (browser) await browser.close();
    await proxy.close();
  }
}
