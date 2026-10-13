#!/usr/bin/env node
// "Example Shop" – a tiny fictitious web shop that produces typical API traffic (and a few
// attack-looking requests) so the extension can be tried out without a real application.
//   node demo/server.mjs [port]      → http://localhost:5180/
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2]) || 5180;
const JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImN1c3RvbWVyIn0.c2ln-bmF0-dXJl-ZXhh-bXBs-ZS1v-bmx5-bm90-LXJl-YWwt-ZGVtbw';

const json = (res, status, obj) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
const products = [
  { id: 1042, name: 'Aurora Wireless Headphones', price: 129, rating: 4.7, color: '#3d5afe' },
  { id: 2077, name: 'Nimbus Smart Speaker', price: 89, rating: 4.4, color: '#00897b' },
  { id: 3150, name: 'Pulse Fitness Band', price: 59, rating: 4.2, color: '#f4511e' },
  { id: 4471, name: 'Lumen Desk Lamp', price: 45, rating: 4.8, color: '#fbc02d' },
];

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  let body = '';
  for await (const chunk of req) body += chunk;
  if (p === '/' || p === '/index.html') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': [`shop_session=${JWT}; Path=/; SameSite=Lax`, 'cart_id=0b9f3c2e-7d41-4a8e-9c6b-5e2d1f0a8b37; Path=/; SameSite=Lax'],
    });
    res.end(await readFile(path.join(DIR, 'index.html')));
    return;
  }
  if (p.startsWith('/static/')) {
    try {
      res.writeHead(200, { 'Content-Type': p.endsWith('.js') ? 'text/javascript' : 'text/css' });
      res.end(await readFile(path.join(DIR, path.basename(p))));
    } catch {
      res.writeHead(404).end();
    }
    return;
  }
  if (p.startsWith('/images/')) {
    const id = Number(p.split('/')[3]) || 0;
    const c = products.find((x) => x.id === id)?.color || '#888';
    res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
    res.end(`<svg xmlns="http://www.w3.org/2000/svg" width="320" height="200"><defs><linearGradient id="g" x2="1" y2="1"><stop offset="0" stop-color="${c}"/><stop offset="1" stop-color="#111"/></linearGradient></defs><rect width="320" height="200" rx="16" fill="url(#g)"/></svg>`);
    return;
  }
  if (p === '/api/products') return json(res, 200, { items: products.filter((x) => x.name.toLowerCase().includes((url.searchParams.get('search') || '').split(' ')[0].toLowerCase())) });
  if (/^\/api\/products\/\d+\/reviews$/.test(p)) return json(res, 201, { ok: true });
  if (p === '/api/cart/items') return json(res, 201, { ok: true, items: 2 });
  if (p === '/api/account/profile') return json(res, 200, { ok: true });
  if (p === '/api/auth/login') return json(res, 401, { error: 'invalid credentials' });
  if (p === '/api/search') return json(res, 200, { query: url.searchParams.get('q'), items: [] });
  if (/^\/api\/orders\/\d+\/invoice$/.test(p)) return json(res, 404, { error: 'not found' });
  if (p === '/debug/orders') {
    res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end("<h1>Error</h1><pre>Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1 in /var/www/shop/src/Orders.php:88</pre>");
    return;
  }
  res.writeHead(404).end('not found');
}).listen(port, () => console.log(`Example Shop: http://localhost:${port}/`));
