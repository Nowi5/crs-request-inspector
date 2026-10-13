// Renders docs/guide/guide.html with print media at A4 width (for layout checks).
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { launch, sleep } from './cdp.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const b = await launch({ width: 794, height: 1123, scale: 1 });
await b.sendPage('Emulation.setEmulatedMedia', { media: 'print' });
await b.navigate(pathToFileURL(path.join(ROOT, 'docs/guide/guide.html')).href, 2500);
const h = await b.evaluate('document.documentElement.scrollHeight');
const out = process.argv[2] || 'guide-preview';
const n = Math.ceil(h / 1123);
for (let i = 0; i < n; i++) {
  await b.evaluate(`window.scrollTo(0, ${i * 1123})`);
  await sleep(150);
  await b.screenshot(`${out}-${String(i + 1).padStart(2, '0')}.png`);
}
console.log('height', h, 'shots', n);
await b.close();
