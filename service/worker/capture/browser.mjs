import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DEVTOOLS_TIMEOUT_MS = 20000;

async function readDevToolsPort(userDataDir, proc) {
  const deadline = Date.now() + DEVTOOLS_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`chrome exited with code ${proc.exitCode}`);
    const content = await readFile(join(userDataDir, 'DevToolsActivePort'), 'utf8').catch(() => '');
    const [port, path] = content.split('\n');
    if (port && path) return { port: Number(port), path: path.trim() };
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('chrome did not expose a DevTools port');
}

export async function launchChrome({ chromeBin, proxyUrl }) {
  const userDataDir = await mkdtemp(join(tmpdir(), 'brag-chrome-'));
  const proc = spawn(
    chromeBin,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      `--user-data-dir=${userDataDir}`,
      `--proxy-server=${proxyUrl}`,
      '--proxy-bypass-list=<-loopback>',
      '--disable-quic',
      '--dns-prefetch-disable',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-sync',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--mute-audio',
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  const cleanup = async () => {
    if (proc.exitCode === null && proc.signalCode === null) {
      const exited = new Promise((resolve) => proc.once('exit', resolve));
      proc.kill('SIGKILL');
      await exited;
    }
    await rm(userDataDir, { recursive: true, force: true, maxRetries: 5 });
  };

  try {
    const { port, path } = await readDevToolsPort(userDataDir, proc);
    return { wsUrl: `ws://127.0.0.1:${port}${path}`, close: cleanup };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

export async function connectCdp(wsUrl) {
  const socket = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('cdp connection failed')), { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  const listeners = new Set();

  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(`${message.error.message}`));
      else resolve(message.result ?? {});
      return;
    }
    listeners.forEach((listener) => listener(message));
  });

  return {
    send(method, params = {}, sessionId) {
      const id = nextId++;
      const payload = sessionId ? { id, method, params, sessionId } : { id, method, params };
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify(payload));
      });
    },
    on(listener) {
      listeners.add(listener);
    },
    close() {
      socket.close();
    },
  };
}
