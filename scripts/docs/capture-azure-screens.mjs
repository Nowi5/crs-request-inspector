// Verifies the Azure WAF policy simulation in the real UI (standalone page + worker) and captures
// screenshots for the guide. Needs the preview server: node scripts/serve.mjs 5178
//   node scripts/docs/capture-azure-screens.mjs
import { readFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, sleep } from './cdp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'guide', 'img');
mkdirSync(OUT, { recursive: true });
const policy = readFileSync(path.join(ROOT, 'tests/fixtures/azure/afd-policy-portal.json'), 'utf8');
const BASE = 'http://localhost:5178/panel.html?standalone=1';

const requests = [
  `PUT /api/account/profile HTTP/2.0
Host: shop.example.com
accept: */*
content-type: application/json
cookie: cart_id=c-81f2; app_session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJl
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/154.0.0.0

{"displayName":"Alex Example","email":"alex@example.com","newsletter":true}`,
  `GET /admin/users HTTP/2.0
Host: shop.example.com
accept: */*
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/154.0.0.0`,
  `GET /healthz?probe=1 HTTP/1.1
Host: shop.example.com
user-agent: AzureFrontDoor-HealthProbe`,
].join('\n###\n');

const b = await launch({ width: 1440, height: 900, scale: 2 });
try {
  await b.navigate(BASE, 1500);
  await b.evaluate(`localStorage.setItem('crsInspectorSettings', ${JSON.stringify(JSON.stringify({ wafProfile: 'azure', azurePolicy: policy, clientIp: '198.51.100.7', clientCountry: 'SG' }))})`);
  await b.navigate(`${BASE}&paste=1`, 3500);
  await b.evaluate(`(() => { const ta = document.querySelector('dialog textarea'); ta.value = ${JSON.stringify(requests)}; ta.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await sleep(500);
  await b.evaluate(`document.querySelector('dialog .btn-primary').click()`);
  await sleep(4000);
  const rows = await b.evaluate(`[...document.querySelectorAll('.list-rows .row, .list-rows [role=row]')].map((r) => r.textContent.replace(/\\s+/g, ' ').trim()).slice(0, 5)`);
  console.log(rows);
  const verdict = await b.evaluate(`document.querySelector('.verdict')?.textContent.replace(/\\s+/g, ' ').trim()`);
  console.log('verdict:', verdict);
  await b.screenshot(path.join(OUT, '22-azure-put.png'));
  // select the /admin request (2nd row)
  await b.evaluate(`(() => { const rows = [...document.querySelectorAll('.list-rows [role=row]')]; rows[1]?.click(); })()`);
  await sleep(800);
  console.log('verdict 2:', await b.evaluate(`document.querySelector('.verdict')?.textContent.replace(/\\s+/g, ' ').trim()`));
  await b.screenshot(path.join(OUT, '23-azure-custom-block.png'), await b.evaluate(`(() => { const r = document.querySelector('.details-content').getBoundingClientRect(); return { x: r.left, y: r.top, width: r.width, height: Math.min(r.height, 640) }; })()`));
  await b.evaluate(`(() => { const rows = [...document.querySelectorAll('.list-rows [role=row]')]; rows[2]?.click(); })()`);
  await sleep(800);
  console.log('verdict 3:', await b.evaluate(`document.querySelector('.verdict')?.textContent.replace(/\\s+/g, ' ').trim()`));
  // settings drawer with policy summary
  await b.evaluate(`document.querySelector('button[aria-label="Settings"], button[title="Settings"]')?.click()`);
  await sleep(1000);
  await b.screenshot(path.join(OUT, '24-azure-settings.png'), await b.evaluate(`(() => { const r = document.querySelector('.drawer').getBoundingClientRect(); return { x: r.left, y: r.top, width: r.width, height: r.height }; })()`));
  const errs = await b.evaluate(`window.__errors || null`);
  if (errs) console.log('errors', errs);
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  await b.close();
}
