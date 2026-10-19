#!/usr/bin/env node
import { resolve } from 'node:path';
import { captureUrl, CaptureError } from './capture.mjs';

const [, , rawUrl] = process.argv;
if (!rawUrl) {
  process.stderr.write('usage: cli.mjs <url>\n');
  process.exit(2);
}

const cacheRoot = resolve(process.env.BRAG_BUNDLE_DIR ?? 'bundles');
const chromeBin = process.env.BRAG_CHROME_BIN ?? '/usr/bin/google-chrome';
const log = (event) => process.stderr.write(`${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n`);

try {
  const result = await captureUrl(rawUrl, { cacheRoot, chromeBin, log });
  process.stdout.write(`${JSON.stringify({
    status: 'done',
    bundleId: result.bundleId,
    cacheHit: result.cacheHit,
    dir: result.dir,
    totalBytes: result.manifest.totalBytes,
    assets: result.manifest.assets.length,
    skipped: result.manifest.skipped.length,
  })}\n`);
} catch (error) {
  const failureReason = error instanceof CaptureError ? error.failureReason : 'capture_failed';
  process.stdout.write(`${JSON.stringify({ status: 'failed', failureReason, message: error.message })}\n`);
  process.exitCode = 1;
}
