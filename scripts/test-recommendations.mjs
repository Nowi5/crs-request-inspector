// Tests for extension/src/ui/recommendations.js using real engine results.
//   node scripts/test-recommendations.mjs
import assert from 'node:assert/strict';
import { buildRuleSet } from './lib/node-loader.mjs';
import { recommend, classifyValue, platformCookie, buildIssues, issuesToMarkdown, routeKey } from '../extension/src/ui/recommendations.js';
import { isDetection } from '../extension/src/ui/format.js';

let passed = 0, failed = 0;
const test = async (name, fn) => {
  try {
    await fn();
    passed++;
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n  ${e.message}`);
  }
};

const rs = await buildRuleSet({});
// Fake values with the same shape as the real ones (no real credentials).
const COOKIE = 'AppServiceAuthSession=cjky+ZV4b2KyZjwmsRIuueoLk5kUGA5WgyVbjRZAAX59OXTiOTZVf9H5p6d6mRmIx7sl13OoTXiXr7rb1fcQPNgNyV00h6voM9eBDfjwv32u3hXnJuC/aE7+eMJvWmwtgiaES/J0Cn+r+4RPDcsTwXRjkwSs2maLamcYuuEShOKB8BpEmjihkTUCYeCXNMZnl6CmoE2jA/SjEUwtmTe4Lxyh+9JWhOZPRZ/IQAicTh5Uq/Knloug5PRKN3dS75ss3XOns6+IaXce2uDuwPfTjFwo3jC0YdZZgpaxwUMfxL8Iq7hvRoRkJbHiDopFTiY8zjVGzKsX05CnX9vOe8ATik3bjfo+DiTprbZ922dP5U60tdcVh2NRHmKbS0D5tPiw7FO6BcomI9i9gxPXEQ5QFRCfMsGTehjkP7rL1keiM9PJnfkOY5kLFcK1hqv7LAMGdiMXsBDM5Eo9CTIiwUg39/u6YwyDFe8wIYQ5va0y99ljnunQGolBgmno0IPbizK+8qxkwTiAmog6fGfW6B+OxsHYr8rx==; app_csrf=abc; app_session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.NQaLBTSUwqza-lBhmYiVLHiN2Mwdq-z1aI-f5SzLeaFmcSso-hT4qjLKs-1Z_mchxY1r7WW-LkrXLcjYzbqwFZe-fEdAcrah8iI0gALAeET5M-glBchtkRkY';
const H = [{ name: 'Host', value: 'app.example.com' }, { name: 'User-Agent', value: 'Mozilla/5.0' }, { name: 'Accept', value: '*/*' }, { name: 'Cookie', value: COOKIE }];
const json = (method, obj) => {
  const body = JSON.stringify(obj);
  return { method, url: 'https://app.example.com/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/layout', httpVersion: 'HTTP/2.0', headers: [...H, { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(body.length) }], body };
};
const ctxFor = (r) => ({ varCtx: { argsGet: new Set((r.variables.ARGS_GET || []).map((a) => a.name)), argsPost: new Set((r.variables.ARGS_POST || []).map((a) => a.name)), bodyProcessor: r.bodyProcessor } });
const find = (r, id) => r.matches.find((m) => m.id === id);

const put = rs.evaluate(json('PUT', { openResourceItem: null, mode: 'preview', workspace: { version: 1, panes: [] }, generation: 3 }));

await test('classifyValue', () => {
  assert.equal(classifyValue('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'), 'jwt');
  assert.equal(classifyValue('cjky+ZV4b2KyZjwmsRIuueoLk5kUGA5WgyVb/jRZAAX5=='), 'token');
  assert.equal(classifyValue('5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63'), 'uuid');
  assert.equal(classifyValue('select the rows from the table'), 'text');
  assert.equal(classifyValue('<b>hi</b>'), 'markup');
  assert.equal(platformCookie('AppServiceAuthSession'), 'Azure App Service Authentication (Easy Auth)');
  assert.equal(platformCookie('app_session'), null);
});

await test('PUT -> 911100 is a policy issue with Azure guidance', () => {
  const m = find(put, 911100);
  assert.ok(m, 'expected 911100');
  const rec = recommend(m, ctxFor(put));
  assert.equal(rec.assessment, 'policy');
  assert.match(rec.why, /allowed methods/);
  assert.ok(rec.waf.some((t) => /tx\.allowed_methods/.test(t)));
  assert.ok(rec.azure.some((t) => /disable rule 911100|action to Log/.test(t)));
  assert.ok(rec.azure.some((t) => /Prevention mode/.test(t)));
});

await test('JWT session cookie special chars -> false positive, opaque id advice, not relevant on Azure', () => {
  const m = put.matches.find((x) => x.id === 942420 && x.links[0].matches[0].var === 'REQUEST_COOKIES:app_session');
  assert.ok(m, 'expected 942420 on the app_session cookie');
  const rec = recommend(m, ctxFor(put));
  assert.equal(rec.assessment, 'false-positive');
  assert.ok(rec.app.some((t) => /opaque random session id/.test(t)));
  assert.ok(rec.waf.some((t) => /REQUEST_COOKIES:app_session/.test(t)));
  assert.ok(rec.azure.some((t) => /Not relevant on Azure WAF/.test(t)));
});

await test('platform cookie advice (Easy Auth)', () => {
  const fake = { id: 942420, pl: 3, tags: [], links: [{ matches: [{ var: 'REQUEST_COOKIES:AppServiceAuthSession', collection: 'REQUEST_COOKIES', key: 'AppServiceAuthSession', value: 'cjky+ZV4b2KyZjwmsRIuueoLk5kUGA5WgyVb/jRZAAX5==' }] }], scores: [{ dir: 'inbound', pl: 3, delta: 3 }] };
  const rec = recommend(fake, {});
  assert.ok(rec.app.some((t) => /Easy Auth/.test(t)));
});

await test('free text in JSON at PL2 -> review with app guidance', () => {
  const r = rs.evaluate(json('POST', { content: "Can you select the latest rows from the table where the user's name is O'Brien?" }));
  const m = r.matches.find((x) => isDetection(x) && x.pl === 2 && x.links[0].matches[0]?.var === 'ARGS:json.content');
  assert.ok(m);
  const rec = recommend(m, ctxFor(r));
  assert.equal(rec.assessment, 'review');
  assert.ok(rec.app.some((t) => /parameterised queries/.test(t)));
  assert.ok(rec.app.some((t) => /encoding them on the client/.test(t)));
  assert.match(rec.headline, /JSON body field/);
});

await test('real SQL injection at PL1 -> likely attack', () => {
  const r = rs.evaluate(json('POST', { content: "1' OR '1'='1" }));
  const rec = recommend(find(r, 942100), ctxFor(r));
  assert.equal(rec.assessment, 'likely-attack');
});

await test('signed URL signature -> false positive', () => {
  const sig = 'Qm9vZ3VzU2lnbmF0dXJl--Xk3Pq9vL2mN8aB7cD1eF4gH~Zr5Tt0Yy6Uu3Ii9Oo2Pp8Ll1Kk4Jj7Hh0Gg5~Ff2Dd9Ss6Aa3Qq-Ww8Ee1Rr4Tt7Yy-Uu0Ii3Oo6Pp9Zz-Nn2Mm5Bb8Vv1Cc4Xx7';
  const r = rs.evaluate({ method: 'GET', url: `https://app.example.com/uploads/p/1/n_1.jpg?Signature=${sig}`, httpVersion: 'HTTP/2.0', headers: H.slice(0, 3) });
  const rec = recommend(find(r, 942440), ctxFor(r));
  assert.equal(rec.assessment, 'false-positive');
  assert.ok(rec.azure.some((t) => /99031002/.test(t)));
});

await test('issues report groups by rule + variable', () => {
  const entries = [put, put, rs.evaluate(json('PUT', { a: 1 }))].map((result, i) => ({ id: `e${i}`, request: { method: 'PUT' }, result }));
  const issues = buildIssues(entries, { blockingPL: 1, isDetection, varCtxFor: (e) => ctxFor(e.result).varCtx });
  const method = issues.find((i) => i.id === 911100);
  assert.equal(method.count, 3);
  assert.equal(method.counted, true);
  assert.equal(issues[0].id, 911100, 'counted findings first');
  assert.equal(method.routes[0].route, 'PUT /api/v1/docs/folders/:id/layout');
  const md = issuesToMarkdown(issues, { blockingPL: 1, version: 'v4.30.0', total: 3 });
  assert.match(md, /# WAF findings report/);
  assert.match(md, /### 911100/);
});

await test('routeKey', () => {
  assert.equal(routeKey('/uploads/profile/picture/489275/normal_489275.jpg'), '/uploads/profile/picture/:id/normal_N.jpg');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
