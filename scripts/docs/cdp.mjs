// Minimal Chrome DevTools Protocol client over --remote-debugging-pipe (no dependencies).
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DEFAULT_CHROME =
  process.env.CHROME ||
  (process.platform === 'win32'
    ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
    : process.platform === 'darwin'
      ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
      : '/usr/bin/google-chrome');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Launch headless Chrome and attach to its first page.
 * @returns {Promise<{send, evaluate, navigate, screenshot, close}>}
 */
export async function launch({ chromePath = DEFAULT_CHROME, width = 1280, height = 800, scale = 2, extraArgs = [], headless = true, profileSetup = null, emulate = true } = {}) {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'crs-guide-'));
  if (profileSetup) profileSetup(profile);
  const chrome = spawn(
    chromePath,
    [...(headless ? ['--headless=new'] : []), '--remote-debugging-pipe', '--enable-unsafe-extension-debugging', `--user-data-dir=${profile}`, '--no-first-run',
      '--no-default-browser-check', `--window-size=${width},${height}`, `--force-device-scale-factor=${scale}`, '--lang=en-US', ...extraArgs, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] }
  );
  const out = chrome.stdio[3];
  let nextId = 1;
  const pending = new Map();
  let buf = '';
  chrome.stdio[4].on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\0')) >= 0) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      const p = msg.id && pending.get(msg.id);
      if (p) {
        pending.delete(msg.id);
        msg.error ? p.reject(new Error(`${msg.error.message} ${msg.error.data || ''}`)) : p.resolve(msg.result);
      }
    }
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      out.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
    });

  const { targetInfos } = await send('Target.getTargets');
  const page = targetInfos.find((t) => t.type === 'page');
  const { sessionId } = await send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
  await send('Page.enable', {}, sessionId);
  if (emulate) await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile: false }, sessionId);

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  return {
    send: (m, p, sid) => send(m, p, sid),
    profile,
    sendPage: (m, p) => send(m, p, sessionId),
    evaluate,
    async navigate(url, wait = 1500) {
      await send('Page.navigate', { url }, sessionId);
      await sleep(wait);
    },
    async screenshot(file, clip) {
      const params = { format: 'png', captureBeyondViewport: false };
      if (clip) params.clip = { ...clip, scale: 1 };
      const { data } = await send('Page.captureScreenshot', params, sessionId);
      writeFileSync(file, Buffer.from(data, 'base64'));
      console.log('saved', path.basename(file));
    },
    async close() {
      chrome.kill();
      await sleep(500);
      try {
        rmSync(profile, { recursive: true, force: true });
      } catch {}
    },
  };
}
