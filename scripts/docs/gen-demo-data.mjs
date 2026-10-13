// Generates extension/src/ui/demo-data.json – the "Example Shop" scenario used for the README
// and guide screenshots (panel.html?mock=1&data=demo). All data is fictitious.
//   node scripts/docs/gen-demo-data.mjs
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { buildRuleSet, ROOT } from '../lib/node-loader.mjs';

const HOST = 'shop.example.com';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
// Fictitious session JWT (header.payload.signature) – url-safe base64 with '-' like real RS256 signatures.
const JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImN1c3RvbWVyIn0.c2ln-bmF0-dXJl-ZXhh-bXBs-ZS1v-bmx5-bm90-LXJl-YWwt-ZGVtbw';
const COOKIE = `shop_session=${JWT}; cart_id=0b9f3c2e-7d41-4a8e-9c6b-5e2d1f0a8b37; _ga=GA1.2.1234567890.1700000000`;
const base = (extra = []) => [
  { name: 'Host', value: HOST },
  { name: 'User-Agent', value: UA },
  { name: 'Accept', value: '*/*' },
  { name: 'Accept-Language', value: 'en-US,en;q=0.9' },
  { name: 'Cookie', value: COOKIE },
  { name: 'Referer', value: `https://${HOST}/` },
  { name: 'Sec-Fetch-Mode', value: 'cors' },
  { name: 'Sec-Fetch-Site', value: 'same-origin' },
  ...extra,
];
const url = (p) => `https://${HOST}${p}`;
const get = (p, extra) => ({ method: 'GET', url: url(p), httpVersion: 'HTTP/2.0', headers: base(extra), body: null });
const json = (method, p, obj) => {
  const body = JSON.stringify(obj);
  return { method, url: url(p), httpVersion: 'HTTP/2.0', headers: base([{ name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(Buffer.byteLength(body)) }, { name: 'Origin', value: `https://${HOST}` }]), body };
};
const form = (p, body) => ({ method: 'POST', url: url(p), httpVersion: 'HTTP/2.0', headers: base([{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }, { name: 'Content-Length', value: String(Buffer.byteLength(body)) }]), body });
const SIG = 'Zm9vYmFy--Xk3Pq9vL2mN8aB7cD1eF4gH~Zr5Tt0Yy6Uu3Ii9Oo2Pp8Ll1Kk4Jj7Hh0Gg5~Ff2Dd9Ss6Aa3Qq-Ww8Ee1Rr4Tt7Yy-Uu0Ii3Oo6Pp9Zz-Nn2Mm5Bb8Vv1Cc4Xx7~Lk3Jh6Gf9Ds2Az5Qw8Er1Ty4Ui7Op0-Mn3Bv6Cx9Za2Sd5Fg8Hj1Kl4__';

const samples = [
  ['devtools', 'document', get('/')],
  ['devtools', 'fetch', get('/api/products?search=wireless+headphones&page=1')],
  ['devtools', 'script', get('/static/js/app.4f9c2.js')],
  ['devtools', 'image', get(`/images/products/1042/hero.webp?Expires=1893456000&Signature=${SIG}&Key-Pair-Id=K2EXAMPLE`)],
  ['devtools', 'fetch', json('POST', '/api/cart/items', { productId: 1042, quantity: 2 })],
  ['devtools', 'fetch', json('POST', '/api/products/1042/reviews', { rating: 5, text: "Great sound! Select the 'bass boost' mode from the app – it works where others don't." })],
  ['devtools', 'fetch', json('PUT', '/api/account/profile', { displayName: 'Alex', newsletter: true })],
  ['devtools', 'fetch', form('/api/auth/login', `username=admin&password=${encodeURIComponent("' OR '1'='1' --")}`)],
  ['paste:curl', 'fetch', get(`/api/search?q=${encodeURIComponent('<script>alert(document.cookie)</script>')}`)],
  ['devtools', 'fetch', get('/api/orders/77/invoice?file=../../../../etc/passwd')],
  [
    'devtools',
    'document',
    {
      ...get('/debug/orders'),
      response: {
        status: 500,
        statusText: 'Internal Server Error',
        httpVersion: 'HTTP/2.0',
        headers: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }],
        mimeType: 'text/html',
        body: '<h1>Error</h1><pre>Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near \'\'\' at line 1 in /var/www/shop/src/Orders.php:88</pre>',
        bodyEncoding: 'text',
      },
    },
  ],
];

const rs = await buildRuleSet({});
const out = { generatedAt: new Date().toISOString(), scenario: 'Example Shop (fictitious)', ruleset: { version: rs.meta.version, rules: rs.ruleCount, settings: rs.meta.settings }, entries: [] };
let t = Date.UTC(2026, 9, 13, 9, 30, 0);
samples.forEach(([source, type, req], i) => {
  const result = rs.evaluate(req);
  out.entries.push({ id: `d${i + 1}`, source, resourceType: type, startedAt: (t += 400 + i * 150), request: { ...req, source: source.split(':').pop(), notes: [] }, result });
});
writeFileSync(path.join(ROOT, 'extension/src/ui/demo-data.json'), JSON.stringify(out));
console.log(out.entries.map((e) => `${e.id} ${e.request.method} ${e.request.url.slice(25, 80)} → ${e.result.blocked ? 'BLOCK ' + e.result.interruption.ruleId : 'pass'} PL ${Object.values(e.result.inbound.cumulative).join('/')}`).join('\n'));
