// Generates the extension icons (extension/icons/icon-{16,32,48,128}.png): a blue shield
// with a white check mark. No dependencies: rasterises with 4×4 supersampling and writes
// PNGs with node:zlib.  Run: node scripts/gen-icons.mjs
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'extension', 'icons');

/* ------------------------------------------------------------- geometry */
function cubic(p0, p1, p2, p3, n) {
  const pts = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    pts.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return pts;
}

// Shield outline in unit coordinates (y down).
const right = [
  [0.5, 0.06],
  ...cubic([0.5, 0.06], [0.62, 0.13], [0.76, 0.16], [0.88, 0.17], 12),
  [0.88, 0.47],
  ...cubic([0.88, 0.47], [0.88, 0.72], [0.72, 0.87], [0.5, 0.96], 24),
];
const left = right.slice(1, -1).reverse().map(([x, y]) => [1 - x, y]);
const SHIELD = [...right, ...left];

function inPolygon(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function distToSegment(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

const CHECK = [[0.31, 0.52], [0.45, 0.66], [0.70, 0.38]];

/* -------------------------------------------------------------- raster */
function render(size) {
  const ss = 4;
  const px = Buffer.alloc(size * size * 4);
  const stroke = size <= 16 ? 0.15 : size <= 32 ? 0.12 : 0.1;
  const top = [0x4f, 0x92, 0xf7];
  const bottom = [0x15, 0x58, 0xc9];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let cover = 0;
      let check = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const ux = (x + (sx + 0.5) / ss) / size;
          const uy = (y + (sy + 0.5) / ss) / size;
          if (!inPolygon(ux, uy, SHIELD)) continue;
          cover++;
          const d = Math.min(distToSegment(ux, uy, CHECK[0], CHECK[1]), distToSegment(ux, uy, CHECK[1], CHECK[2]));
          if (d <= stroke / 2) check++;
        }
      }
      const n = ss * ss;
      const a = cover / n;
      const c = cover ? check / cover : 0;
      const t = y / (size - 1);
      const base = top.map((v, i) => v + (bottom[i] - v) * t);
      const rgb = base.map((v) => Math.round(v + (255 - v) * c));
      const o = (y * size + x) * 4;
      px[o] = rgb[0];
      px[o + 1] = rgb[1];
      px[o + 2] = rgb[2];
      px[o + 3] = Math.round(a * 255);
    }
  }
  return px;
}

/* ----------------------------------------------------------------- PNG */
const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync(OUT, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  const file = path.join(OUT, `icon-${size}.png`);
  writeFileSync(file, encodePng(size, render(size)));
  console.log('wrote', path.relative(ROOT, file));
}
