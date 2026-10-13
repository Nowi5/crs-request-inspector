// Captures the chrome://extensions screenshots used in the user guide.
// Drives headless Chrome over the DevTools protocol (pipe mode, needed for
// Extensions.loadUnpacked) and highlights the relevant controls.
//   node scripts/docs/capture-install-screens.mjs ["C:/Program Files/Google/Chrome/Application/chrome.exe"]
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'guide', 'img');
const CHROME = process.argv[2] || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
mkdirSync(OUT, { recursive: true });

const profile = mkdtempSync(path.join(os.tmpdir(), 'crs-guide-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new', '--remote-debugging-pipe', '--enable-unsafe-extension-debugging', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--window-size=1280,800', '--force-device-scale-factor=2', '--lang=en-US', 'about:blank',
  ],
  { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] }
);
const toChrome = chrome.stdio[3];
const fromChrome = chrome.stdio[4];

let nextId = 1;
const pending = new Map();
let buf = '';
fromChrome.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let i;
  while ((i = buf.indexOf('\0')) >= 0) {
    const msg = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`${msg.error.message} ${msg.error.data || ''}`)) : resolve(msg.result);
    }
  }
});
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    toChrome.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// JS run inside chrome://extensions (shadow DOM helpers).
const PAGE_HELPERS = `
  window.$m = () => document.querySelector('extensions-manager').shadowRoot;
  window.$toolbar = () => $m().querySelector('extensions-toolbar').shadowRoot;
  window.mark = (el) => { if (el) { el.style.outline = '4px solid #e8710a'; el.style.outlineOffset = '4px'; el.style.borderRadius = '6px'; } return !!el; };
  window.unmarkAll = () => { for (const el of [$toolbar().querySelector('#devMode'), $toolbar().querySelector('#loadUnpacked')]) if (el) el.style.outline = ''; };
`;

try {
  const { targetInfos } = await send('Target.getTargets');
  const page = targetInfos.find((t) => t.type === 'page');
  const { sessionId } = await send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
  await send('Page.enable', {}, sessionId);
  const evaluate = async (expression) => (await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId)).result.value;
  const shot = async (name) => {
    const { data } = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
    writeFileSync(path.join(OUT, name), Buffer.from(data, 'base64'));
    console.log('saved', name);
  };
  const open = async (url) => {
    await send('Page.navigate', { url }, sessionId);
    await sleep(1500);
    await evaluate(PAGE_HELPERS);
  };

  // 1. Extensions page, Developer mode off -> highlight the toggle.
  await open('chrome://extensions');
  await evaluate(`(() => { const t = $toolbar().querySelector('#devMode'); if (t.checked) t.click(); })()`);
  await sleep(500);
  await evaluate(`mark($toolbar().querySelector('#devMode'))`);
  await shot('01-extensions-devmode.png');

  // 2. Developer mode on -> highlight "Load unpacked".
  await evaluate(`(() => { unmarkAll(); $toolbar().querySelector('#devMode').click(); })()`);
  await sleep(800);
  await evaluate(`mark($toolbar().querySelector('#loadUnpacked'))`);
  await shot('02-load-unpacked.png');

  // 3. Load the extension and show its card.
  const { id } = await send('Extensions.loadUnpacked', { path: path.join(ROOT, 'extension') });
  console.log('extension id', id);
  await open('chrome://extensions');
  await sleep(500);
  await evaluate(`(() => {
    const list = $m().querySelector('extensions-item-list').shadowRoot;
    const card = list.querySelector('extensions-item');
    if (card) { card.style.outline = '4px solid #e8710a'; card.style.outlineOffset = '3px'; card.style.borderRadius = '8px'; }
  })()`);
  await shot('03-extension-card.png');

  // 4. The standalone analyser page opened by the toolbar icon.
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 2, mobile: false }, sessionId);
  await open(`chrome-extension://${id}/panel.html?standalone=1`);
  await sleep(2500);
  await shot('04-standalone.png');
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  chrome.kill();
  await sleep(500);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {}
}
