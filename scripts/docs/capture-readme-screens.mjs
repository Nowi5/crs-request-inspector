// Captures the README screenshots (docs/images/*) from the fictional "Example Shop" demo data.
// Needs the preview server: node scripts/serve.mjs 5178
//   node scripts/docs/gen-demo-data.mjs && node scripts/docs/capture-readme-screens.mjs
// docs/images/devtools.png (the panel inside real DevTools) comes from scripts/docs/capture-devtools.mjs,
// the Azure shots from scripts/docs/capture-azure-screens.mjs (copied from docs/guide/img if present).
import path from 'node:path';
import { mkdirSync, copyFileSync, existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { launch, sleep } from './cdp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'images');
const GUIDE = path.join(ROOT, 'docs', 'guide', 'img');
const BASE = 'http://localhost:5178/panel.html?mock=1&data=demo';
const W = 1440;
const H = 860;
const SCALE = 1.5;
mkdirSync(OUT, { recursive: true });

const HELPERS = `
window.byText = (sel, text, root = document) => [...root.querySelectorAll(sel)].find((e) => e.textContent.trim().startsWith(text));
window.rect = (el, pad = 0, maxH = Infinity) => {
  el = typeof el === 'string' ? document.querySelector(el) : el;
  const r = el.getBoundingClientRect();
  return { x: Math.max(0, r.left - pad), y: Math.max(0, r.top - pad), width: r.width + 2 * pad, height: Math.min(r.height + 2 * pad, maxH) };
};
`;

const b = await launch({ width: W, height: H, scale: SCALE });
const size = (height) => b.sendPage('Emulation.setDeviceMetricsOverride', { width: W, height, deviceScaleFactor: SCALE, mobile: false });
const page = async (query, wait = 2500) => {
  await b.navigate(`${BASE}&${query}`, wait);
  await b.evaluate(HELPERS);
};
const run = (js) => b.evaluate(js);
const shot = (name, clip) => b.screenshot(path.join(OUT, name), clip);

try {
  // Full panel, light and dark.
  await page('select=d8&theme=light');
  await shot('panel-light.png');
  await page('select=d9&theme=dark');
  await shot('panel-dark.png');

  // A PL2 false positive (product review text) with its "How to fix" recommendation.
  await size(1300);
  await page('select=d6&theme=light');
  await run(`(() => {
    const card = document.querySelector('.card');
    card.id = 'doc-card';
    if (!card.querySelector('.recommendation, .how-to-fix')) card.querySelector('.card-head').click();
  })()`);
  await sleep(500);
  await run(`document.getElementById('doc-card').scrollIntoView({ block: 'start' })`);
  await sleep(300);
  await shot('finding.png', await run(`rect('#doc-card', 6, 900)`));

  // Exclusion helper with the Terraform variant selected.
  await size(1700);
  await sleep(300);
  await run(`byText('#doc-card button', 'Exclusion').click()`);
  await sleep(500);
  await run(`(() => { const t = byText('#doc-card .ex-variants [role=tab]', 'Terraform'); if (t) t.click(); })()`);
  await sleep(400);
  await run(`document.querySelector('#doc-card .ex-variants').closest('.ex').scrollIntoView({ block: 'start' })`);
  await sleep(300);
  await shot('exclusion.png', await run(`rect(document.querySelector('#doc-card .ex-variants').closest('.ex'), 8)`));

  // Issues report.
  await size(H);
  await page('select=d8&report=1&theme=light');
  await run(`(() => { const d = document.querySelector('.report-dialog details.issue'); if (d) d.open = true; })()`);
  await sleep(300);
  await shot('issues-report.png', await run(`rect('.report-dialog', 0)`));

  // Paste dialog with a (fictional) "Copy as PowerShell" request.
  await page('select=d8&paste=1&theme=light');
  const ps = [
    '$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession',
    '$session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/154.0.0.0"',
    '$session.Cookies.Add((New-Object System.Net.Cookie("app_session", "demo-session", "/", "shop.example.com")))',
    'Invoke-WebRequest -UseBasicParsing -Uri "https://shop.example.com/api/auth/login" `',
    '-Method "POST" `',
    '-WebSession $session `',
    '-ContentType "application/x-www-form-urlencoded" `',
    `-Body "email=alex%40example.com&password=%27+OR+%271%27%3D%271%27+--"`,
  ].join('\n');
  await run(`(() => { const ta = document.querySelector('dialog textarea'); ta.value = ${JSON.stringify(ps)}; ta.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await sleep(600);
  await shot('paste-dialog.png', await run(`rect('dialog', 6)`));

  // Settings drawer (CRS profile).
  await page('select=d8&settings=1&theme=light');
  await shot('settings.png', await run(`rect('.drawer', 0)`));
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  await b.close();
}

// Re-use guide shots that already show only fictional data.
for (const [from, to] of [
  ['22-azure-put.png', 'azure-profile.png'],
  ['23-azure-custom-block.png', 'azure-custom-rule.png'],
  ['24-azure-settings.png', 'azure-settings.png'],
  ['01-extensions-devmode.png', 'install-devmode.png'],
  ['02-load-unpacked.png', 'install-load-unpacked.png'],
  ['03-extension-card.png', 'install-card.png'],
]) {
  const src = path.join(GUIDE, from);
  if (existsSync(src) && readFileSync(src).length) {
    copyFileSync(src, path.join(OUT, to));
    console.log('copied', to);
  }
}
