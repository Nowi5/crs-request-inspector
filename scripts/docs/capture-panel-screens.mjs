// Captures annotated screenshots of the panel (mock mode, "Example Shop" demo data) for the user guide.
// Needs the preview server: node scripts/serve.mjs 5178
//   node scripts/docs/capture-panel-screens.mjs
// Run scripts/docs/capture-devtools.mjs first: the DevTools tab strip is cropped from docs/images/devtools.png.
import path from 'node:path';
import { mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { launch, sleep } from './cdp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'guide', 'img');
const BASE = 'http://localhost:5178/panel.html?mock=1&data=demo';
mkdirSync(OUT, { recursive: true });

// Injected into the page: numbered callout badges and highlight boxes.
const HELPERS = `
window.$q = (s, root = document) => typeof s === 'string' ? root.querySelector(s) : s;
window.byText = (sel, text, root = document) => [...root.querySelectorAll(sel)].find((e) => e.textContent.trim().startsWith(text));
window.badge = (n, target, pos = 'tl', dx = 0, dy = 0) => {
  const el = $q(target); if (!el) return 'missing ' + target;
  const r = el.getBoundingClientRect();
  const b = document.createElement('div');
  b.className = 'doc-badge'; b.textContent = n;
  Object.assign(b.style, { position: 'fixed', zIndex: 2147483647, width: '20px', height: '20px', borderRadius: '50%', background: '#e8710a',
    color: '#fff', font: '700 11px system-ui, sans-serif', display: 'flex', alignItems: 'center', justifyContent: 'center',
    boxShadow: '0 0 0 2px #fff, 0 1px 5px rgba(0,0,0,.4)', pointerEvents: 'none' });
  let x = pos.includes('r') ? r.right - 10 : pos.includes('c') ? r.left + r.width / 2 - 10 : r.left - 10;
  let y = pos.includes('b') ? r.bottom - 10 : pos.includes('m') ? r.top + r.height / 2 - 10 : r.top - 10;
  b.style.left = Math.max(2, x + dx) + 'px'; b.style.top = Math.max(2, y + dy) + 'px';
  document.body.appendChild(b); return 'ok';
};
window.box = (target, pad = 2) => {
  const el = $q(target); if (!el) return 'missing';
  const r = el.getBoundingClientRect();
  const b = document.createElement('div');
  Object.assign(b.style, { position: 'fixed', zIndex: 2147483646, left: r.left - pad + 'px', top: r.top - pad + 'px', width: r.width + 2 * pad + 'px',
    height: r.height + 2 * pad + 'px', border: '2px solid #e8710a', borderRadius: '5px', pointerEvents: 'none' });
  document.body.appendChild(b); return 'ok';
};
window.rect = (target, pad = 0) => { const r = $q(target).getBoundingClientRect(); return { x: Math.max(0, r.left - pad), y: Math.max(0, r.top - pad), width: r.width + 2 * pad, height: r.height + 2 * pad }; };
`;

const b = await launch({ width: 1440, height: 860, scale: 2 });
const page = async (query, wait = 2500) => {
  await b.navigate(`${BASE}&${query}`, wait);
  await b.evaluate(HELPERS);
};
const run = (js) => b.evaluate(js);
try {
  // 1. Overview with callouts.
  await page('select=d8');
  console.log(
    await run(`[
      badge(1, '.record-btn', 'tl', 4, 6),
      badge(2, '.btn-primary.btn-tb', 'tl', 0, 6),
      badge(3, '.pl-select', 'ml', -14, 0),
      badge(4, byText('.filterbar button', 'Blocked'), 'tl', -6, -4),
      badge(5, '.list-header .c-status', 'mc', 0, 0),
      badge(6, '.list-header .c-score', 'mr', -16, 0),
      badge(7, '.list-header .c-rules', 'mr', -16, 0),
      badge(8, '.verdict', 'tl', 4, 4),
      badge(9, '.plmatrix', 'tl', 0, 0),
      badge(10, '.section-head', 'tl', 0, 0),
    ].join(',')`)
  );
  await b.screenshot(path.join(OUT, '10-overview.png'));

  // 2. Expanded finding card (first one) with field callouts.
  await page('select=d6');
  await run(`document.querySelector('.card-head').click()`);
  await sleep(500);
  const card = await run(`(() => {
    const head = document.querySelector('.card-head');
    const card = head.closest('.card') || head.parentElement;
    card.id = 'doc-card';
    card.scrollIntoView({ block: 'start' });
    return card.getBoundingClientRect().height;
  })()`);
  await sleep(300);
  console.log(
    await run(`(() => {
      const c = document.getElementById('doc-card');
      return [
        badge(1, c.querySelector('.rule-id'), 'ml', -30, 0),
        badge(2, byText('.k', 'Where', c), 'tl', -4, 0),
        badge(3, byText('.k', 'Matched', c), 'tl', -4, 0),
        badge(4, byText('.k', 'Transforms', c), 'tl', -4, 0),
        badge(5, byText('.k', 'Operator', c), 'tl', -4, 0),
        badge(6, byText('.k', 'Inspects', c), 'tl', -4, 0),
        badge(7, byText('.k', 'Log data', c), 'tl', -4, 0),
        badge(8, c.querySelector('.card-actions') || byText('button', 'Exclusion', c), 'tl', -4, 0),
      ].join(',');
    })()`)
  );
  await b.screenshot(path.join(OUT, '11-finding-card.png'), await run(`rect('#doc-card', 14)`));

  // 3. Exclusion helper (taller viewport so all snippets fit).
  await run(`document.querySelectorAll('.doc-badge').forEach((e) => e.remove())`);
  await b.sendPage('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1700, deviceScaleFactor: 2, mobile: false });
  await sleep(400);
  await run(`byText('#doc-card button', 'Exclusion').click()`);
  await sleep(500);
  await run(`document.querySelector('#doc-card .exclusions').scrollIntoView({ block: 'start' })`);
  await sleep(300);
  await b.screenshot(path.join(OUT, '12-exclusion.png'), await run(`rect('#doc-card .exclusions', 8)`));
  await b.sendPage('Emulation.setDeviceMetricsOverride', { width: 1440, height: 860, deviceScaleFactor: 2, mobile: false });

  // 4. Blocked verdict (SQL injection in a query arg).
  await page('select=d9');
  await b.screenshot(path.join(OUT, '13-verdict-blocked.png'), await run(`rect('.verdict', 10)`));
  await page('select=d6');
  await b.screenshot(path.join(OUT, '14-verdict-latent.png'), await run(`rect('.verdict', 10)`));
  await page('select=d3');
  await b.screenshot(path.join(OUT, '15-verdict-clean.png'), await run(`rect('.verdict', 10)`));

  // 5. Request tab.
  await page('select=d5&tab=request');
  await b.screenshot(path.join(OUT, '16-request-tab.png'), await run(`rect('.details-content', 0)`));

  // 6. Paste dialog with an example.
  await page('select=d8&paste=1');
  await run(`(() => {
    const ta = document.querySelector('dialog textarea');
    ta.value = "curl 'https://shop.example.com/api/search?q=1%27%20OR%20%271%27%3D%271' \\\\\\n  -H 'accept: */*' \\\\\\n  -b 'session=abc123' \\\\\\n  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/154.0.0.0'";
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await sleep(600);
  await b.screenshot(path.join(OUT, '17-paste-dialog.png'), await run(`rect('dialog', 6)`));

  // 7. Settings drawer.
  await page('select=d8&settings=1');
  await b.screenshot(path.join(OUT, '18-settings.png'), await run(`rect('.drawer', 0)`));

  // 7b. "How to fix" recommendation (DELETE -> 911100) and the issues report.
  await page('select=d7');
  await b.sendPage('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1400, deviceScaleFactor: 2, mobile: false });
  await sleep(300);
  await b.screenshot(path.join(OUT, '19-how-to-fix.png'), await run(`(() => { const r = rect('.card', 6); r.height = Math.min(r.height, 720); return r; })()`));
  await b.sendPage('Emulation.setDeviceMetricsOverride', { width: 1440, height: 860, deviceScaleFactor: 2, mobile: false });
  await page('select=d8&report=1');
  await b.screenshot(path.join(OUT, '20-issues-report.png'), await run(`rect('.report-dialog', 0)`));
  await run(`(() => { const d = document.querySelector('.report-dialog details.issue'); d.open = true; })()`);
  await sleep(300);
  await b.screenshot(path.join(OUT, '21-issue-open.png'), await run(`rect('.report-dialog', 0)`));

  // 8. Full dark-theme overview (cover image).
  await page('select=d8&theme=dark');
  await b.screenshot(path.join(OUT, '00-cover-dark.png'));

  // 9. DevTools tab strip, cropped from the real DevTools capture of the demo shop.
  const devtools = path.join(ROOT, 'docs', 'images', 'devtools.png');
  if (existsSync(devtools)) {
    await b.sendPage('Emulation.setDeviceMetricsOverride', { width: 1640, height: 831, deviceScaleFactor: 1, mobile: false });
    await b.navigate(pathToFileURL(devtools).href, 1200);
    await b.evaluate(`(() => { const i = document.querySelector('img'); document.body.style.margin = '0'; i.style.display = 'block'; })()`);
    await b.screenshot(path.join(OUT, '05-devtools-tab.png'), { x: 30, y: 506, width: 1000, height: 26 });
  }
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  await b.close();
}
