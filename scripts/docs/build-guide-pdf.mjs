// Renders docs/guide/guide.html to docs/CRS-Request-Inspector-Guide.pdf (A4) with headless Chrome.
//   node scripts/docs/build-guide-pdf.mjs
import path from 'node:path';
import { writeFileSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { launch } from './cdp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'CRS-Request-Inspector-Guide.pdf');
const b = await launch({ width: 794, height: 1123, scale: 1 });
try {
  await b.navigate(pathToFileURL(path.join(ROOT, 'docs/guide/guide.html')).href, 3000);
  const { data } = await b.sendPage('Page.printToPDF', { printBackground: true, preferCSSPageSize: true, paperWidth: 8.27, paperHeight: 11.69 });
  writeFileSync(OUT, Buffer.from(data, 'base64'));
  console.log('saved', path.relative(ROOT, OUT));
} finally {
  await b.close();
}
