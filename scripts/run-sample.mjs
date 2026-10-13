// Evaluate a few sample requests and print a compact report. Usage:
//   node scripts/run-sample.mjs [version]
import { buildRuleSet } from './lib/node-loader.mjs';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
const COOKIE =
  'AppServiceAuthSession=cjky+ZV4b2KyZjwmsRIuCPOLNEPOCPOLNEPO/aE7+eMJvWmwtgiaES/J0Cn+r+4RPDcsTwXRjkwSs2maLamcYuuEShOKB8BpEm==; ' +
  'app_session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJlLXJlZGFjdGVkLWZvci10ZXN0cw; ' +
  'app_csrf=rvqs8QY0fdXWv8qPmqIdwB.4e0823d35aa61ac819ee1bfb708d03335efe856b1bad53806489fb06af5fd6a7';
const common = [
  { name: 'Host', value: 'dev.example.com' },
  { name: 'User-Agent', value: UA },
  { name: 'Cookie', value: COOKIE },
  { name: 'accept', value: '*/*' },
  { name: 'accept-encoding', value: 'gzip, deflate, br, zstd' },
  { name: 'accept-language', value: 'en-SG,en;q=0.9,de-DE;q=0.8,de;q=0.7,en-US;q=0.6,zh-CN;q=0.5,zh;q=0.4' },
  { name: 'referer', value: 'https://dev.example.com/docs/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63' },
  { name: 'sec-ch-ua', value: '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"' },
  { name: 'sec-ch-ua-mobile', value: '?0' },
  { name: 'sec-ch-ua-platform', value: '"Windows"' },
  { name: 'sec-fetch-dest', value: 'empty' },
  { name: 'sec-fetch-mode', value: 'cors' },
  { name: 'sec-fetch-site', value: 'same-origin' },
];
const body = (content) => JSON.stringify({ content, resourceItems: [], linkedResourceItemIds: [], sourceLinks: [] });
const post = (content, extra = []) => {
  const b = body(content);
  return {
    method: 'POST',
    url: 'https://dev.example.com/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/comments',
    httpVersion: 'HTTP/2.0',
    headers: [...common, { name: 'origin', value: 'https://dev.example.com' }, { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(Buffer.byteLength(b)) }, ...extra],
    body: b,
    bodyEncoding: 'text',
  };
};

const samples = {
  'GET workspace-options': { method: 'GET', url: 'https://dev.example.com/api/v1/workspace-options', httpVersion: 'HTTP/2.0', headers: common, body: null },
  'POST hex message': post('enc:hex1:48656c6c6f'),
  'POST plain chat text': post("Hello, can you select the latest rows from the table where the user's name is O'Brien?"),
  'POST sqli': post("1' OR '1'='1' -- "),
  'POST xss': post('<script>alert(document.cookie)</script>'),
  'DELETE thread': { method: 'DELETE', url: 'https://dev.example.com/api/v1/docs/folders/5d2c6e1a', httpVersion: 'HTTP/2.0', headers: common, body: null },
  'GET query lfi': { method: 'GET', url: 'https://dev.example.com/download?file=../../../../etc/passwd', httpVersion: 'HTTP/1.1', headers: common, body: null },
};

const version = process.argv[2];
const t0 = Date.now();
const rs = await buildRuleSet({ version });
console.log(`Loaded ${rs.meta.version}: ${rs.ruleCount} rules in ${Date.now() - t0} ms; ${rs.errors.length} errors, ${rs.warnings.length} warnings`);
for (const e of rs.errors.slice(0, 10)) console.log('  ERROR', e);
for (const w of rs.warnings.slice(0, 15)) console.log('  WARN', `${w.file}:${w.line}`, w.message);

for (const [name, req] of Object.entries(samples)) {
  const r = rs.evaluate(req);
  console.log(`\n=== ${name}: ${r.blocked ? 'BLOCKED by ' + r.interruption.ruleId : 'pass'}  inbound=${JSON.stringify(r.inbound.cumulative)} (threshold ${r.inbound.threshold}) ${r.elapsedMs}ms, ${r.evaluatedRules} rules`);
  for (const m of r.matches.filter((m) => !m.isMeta || m.disruptive === 'deny')) {
    const lm = m.links[m.links.length - 1]?.matches[0] || m.links[0]?.matches[0];
    console.log(`  ${m.id} PL${m.pl ?? '-'} ${m.severity ?? ''} +${m.scores.reduce((a, s) => a + s.delta, 0)} ${m.msg}`);
    if (lm) console.log(`      ${lm.var} = ${JSON.stringify(lm.value).slice(0, 120)}  matched=${JSON.stringify(lm.matched)?.slice(0, 80)}`);
  }
  for (const w of r.warnings) console.log('  warn:', w);
}
