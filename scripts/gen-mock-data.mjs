// Generates extension/src/ui/mock-data.json: real engine results for sample requests,
// used by the UI in mock mode (panel.html?mock=1) for design work and screenshots.
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { buildRuleSet, ROOT } from './lib/node-loader.mjs';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
const COOKIE = 'AppServiceAuthSession=cjky+ZV4b2KyZjwmsRIuCPOLNEPO/aE7+eMJvWmwtgiaES/J0Cn+r+4RP==; app_session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl; app_csrf=rvqs8QY0fdXWv8qPmqIdwB.4e0823d35aa61ac819ee1bfb708d0333';
const base = [
  { name: 'Host', value: 'dev.example.com' }, { name: 'User-Agent', value: UA }, { name: 'Cookie', value: COOKIE },
  { name: 'accept', value: '*/*' }, { name: 'accept-language', value: 'en-SG,en;q=0.9,de-DE;q=0.8' },
  { name: 'referer', value: 'https://dev.example.com/docs/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63' },
  { name: 'sec-fetch-mode', value: 'cors' }, { name: 'sec-fetch-site', value: 'same-origin' },
];
const json = (url, obj, method = 'POST') => {
  const b = JSON.stringify(obj);
  return { method, url, httpVersion: 'HTTP/2.0', headers: [...base, { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(Buffer.byteLength(b)) }], body: b, bodyEncoding: 'text' };
};
const msgUrl = 'https://dev.example.com/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/comments';
const msg = (content) => json(msgUrl, { content, resourceItems: [], linkedResourceItemIds: [], sourceLinks: [] });
const get = (url, v = 'HTTP/2.0') => ({ method: 'GET', url, httpVersion: v, headers: base, body: null });
// Fake CloudFront-style signed URL (url-safe base64 with '-' and '~'), a classic PL2 false positive.
const SIG = 'Qm9vZ3VzU2lnbmF0dXJl--Xk3Pq9vL2mN8aB7cD1eF4gH~Zr5Tt0Yy6Uu3Ii9Oo2Pp8Ll1Kk4Jj7Hh0Gg5~Ff2Dd9Ss6Aa3Qq-Ww8Ee1Rr4Tt7Yy-Uu0Ii3Oo6Pp9Zz-Nn2Mm5Bb8Vv1Cc4Xx7~Lk3Jh6Gf9Ds2Az5Qw8Er1Ty4Ui7Op0-Mn3Bv6Cx9Za2Sd5Fg8Hj1Kl4-Po7Iu0Yt3Re6Wq9As2Df5Gh8Jk1Lz4Xc7Vb0Nm3__';
const signedImage = (n) =>
  get(`https://dev.example.com/uploads/profile/picture/${n}/normal_${n}.jpg?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9jZG4uZXhhbXBsZS5jb20vKiJ9XX0_&Signature=${SIG}&Key-Pair-Id=K2EXAMPLE123`);
const samples = [
  ['devtools', 'fetch', get('https://dev.example.com/api/v1/workspace-options')],
  ['devtools', 'fetch', msg('enc:hex1:48656c6c6f')],
  ['devtools', 'fetch', msg("Can you select the latest rows from the table where the user's name is O'Brien?")],
  ['devtools', 'document', get('https://dev.example.com/docs/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63')],
  ['devtools', 'fetch', { ...get('https://dev.example.com/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63'), method: 'DELETE' }],
  ['devtools', 'script', get('https://dev.example.com/assets/index-4f9c2.js')],
  ['devtools', 'fetch', get("https://dev.example.com/api/v1/search?q=1' OR '1'='1")],
  ['paste:powershell', 'fetch', msg('<script>alert(document.cookie)</script>')],
  ['devtools', 'fetch', get('https://dev.example.com/api/v1/files/download?path=../../../../etc/passwd')],
  ['devtools', 'image', signedImage(489275)],
];
const rs = await buildRuleSet({});
const out = { generatedAt: new Date().toISOString(), ruleset: { version: rs.meta.version, rules: rs.ruleCount, settings: rs.meta.settings }, entries: [] };
let t = Date.now() - 60000;
samples.forEach(([source, type, req], i) => {
  const result = rs.evaluate(req);
  out.entries.push({ id: `r${i + 1}`, source, resourceType: type, startedAt: (t += 1500 + i * 700), request: { ...req, source: source.split(':').pop(), notes: source === 'paste:powershell' ? ['Detected HTTP/2 pseudo-headers (authority, method, path, scheme); treated as an HTTP/2 request and removed from the header list.'] : [] }, result });
});
writeFileSync(path.join(ROOT, 'extension/src/ui/mock-data.json'), JSON.stringify(out, null, 1));
console.log('wrote', out.entries.length, 'entries', out.entries.map((e) => `${e.request.method} ${e.result.blocked ? 'BLOCK' : 'pass'} ${JSON.stringify(e.result.inbound.cumulative)}`).join('\n'));
