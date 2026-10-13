// Unit tests for the pure UI logic modules (no DOM). Run: node scripts/test-ui-logic.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  splitUrl, parseQuery, parseCookies, typeGroup, sourceInfo, attackCategory, severityClass,
  isDetection, matchScore, matchPL, groupFindings, plMatrix, blockingPLFrom, entryStatus,
  summarizeEntry, verdict, describeVar, displayArgName, describeOperator, normalizeVersion,
  ruleSourceUrl, countRequests, prettyBody, decodeBody, compareBy, hitKey, buildHitIndex,
} from '../extension/src/ui/format.js';
import {
  generalizePath, isIdSegment, escapeRegex, exclusionTarget, buildExclusions, ruleGroupName,
} from '../extension/src/ui/exclusions.js';
import { toCurl, toRawHttp, shellQuote } from '../extension/src/ui/export.js';
import { tokenizeSecLang } from '../extension/src/ui/seclang.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mock = JSON.parse(readFileSync(path.join(ROOT, 'extension/src/ui/mock-data.json'), 'utf8'));
const byId = Object.fromEntries(mock.entries.map((e) => [e.id, e]));

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    console.error(`FAIL ${name}\n  ${e.stack.split('\n').slice(0, 4).join('\n  ')}`);
  }
}

/* ---------------------------------------------------------------- URLs */
test('splitUrl keeps raw query', () => {
  const u = splitUrl("https://dev.example.com/api/v1/search?q=1' OR '1'='1");
  assert.equal(u.host, 'dev.example.com');
  assert.equal(u.path, '/api/v1/search');
  assert.equal(u.query, "?q=1' OR '1'='1");
  assert.equal(u.pathAndQuery, "/api/v1/search?q=1' OR '1'='1");
  assert.equal(splitUrl('https://a.b').path, '/');
  assert.equal(splitUrl('/x?y=1').path, '/x');
});
test('parseQuery / parseCookies', () => {
  assert.deepEqual(parseQuery('?a=1&b=x%20y&c'), [{ name: 'a', value: '1' }, { name: 'b', value: 'x y' }, { name: 'c', value: '' }]);
  assert.deepEqual(parseCookies('a=1; b=x=y;c'), [{ name: 'a', value: '1' }, { name: 'b', value: 'x=y' }, { name: 'c', value: '' }]);
});
test('typeGroup / sourceInfo', () => {
  assert.equal(typeGroup('xhr'), 'fetch');
  assert.equal(typeGroup('document'), 'doc');
  assert.equal(typeGroup('stylesheet'), 'css');
  assert.equal(typeGroup('font'), 'other');
  assert.equal(sourceInfo('devtools').short, 'live');
  assert.equal(sourceInfo('paste:powershell').long, 'Pasted · PowerShell');
  assert.equal(sourceInfo('paste:har').kind, 'har');
});

/* ----------------------------------------------------------- categories */
test('attackCategory', () => {
  assert.equal(attackCategory(['attack-sqli', 'paranoia-level/1'], 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf'), 'SQL injection');
  assert.equal(attackCategory(['attack-xss']), 'XSS');
  assert.equal(attackCategory(['attack-protocol'], 'REQUEST-920-PROTOCOL-ENFORCEMENT.conf'), 'Protocol enforcement');
  assert.equal(attackCategory(['attack-protocol'], 'REQUEST-921-PROTOCOL-ATTACK.conf'), 'Protocol attack');
  assert.equal(attackCategory(['attack-something-new']), 'Something new');
  assert.equal(attackCategory([], 'REQUEST-911-METHOD-ENFORCEMENT.conf'), 'Method enforcement');
  assert.equal(attackCategory([], 'x.conf'), null);
  assert.equal(severityClass('CRITICAL'), 'critical');
  assert.equal(severityClass('WARNING'), 'warning');
  assert.equal(severityClass(null), 'info');
});

/* -------------------------------------------------------------- matches */
test('detections, scores and grouping (r8)', () => {
  const r = byId.r8.result;
  const ev = r.matches.find((m) => m.id === 949110);
  assert.equal(isDetection(ev), false);
  const det = r.matches.filter(isDetection);
  assert.ok(det.length >= 9);
  const m = det.find((x) => x.id === 941100);
  assert.equal(matchScore(m), 5);
  assert.equal(matchPL(m), 1);
  const { active, higher } = groupFindings(r.matches, 1);
  assert.ok(active.every((x) => matchPL(x) <= 1));
  assert.ok(higher.every((x) => matchPL(x) > 1));
  assert.deepEqual(higher.map(matchPL), [...higher.map(matchPL)].sort());
});
test('multi-match rule scores add up (r9 930100)', () => {
  const m = byId.r9.result.matches.find((x) => x.id === 930100);
  assert.equal(matchScore(m), 10);
});

/* -------------------------------------------------------------- verdicts */
test('plMatrix / blockingPLFrom', () => {
  const r3 = byId.r3.result;
  const mx = plMatrix(r3);
  assert.equal(mx.length, 4);
  assert.equal(mx[0].blocked, false);
  assert.equal(mx[1].blocked, true);
  assert.equal(mx[0].current, true);
  assert.equal(blockingPLFrom(r3), 2);
  assert.equal(blockingPLFrom(byId.r1.result), null);
});
test('entryStatus classification', () => {
  assert.equal(entryStatus(byId.r1), 'clean');
  assert.equal(entryStatus(byId.r2), 'latent');
  assert.equal(entryStatus(byId.r3), 'latent');
  assert.equal(entryStatus(byId.r5), 'blocked');
  assert.equal(entryStatus({ ...byId.r1, status: 'pending' }), 'pending');
  assert.equal(entryStatus({ ...byId.r1, status: 'error', result: null }), 'error');
  const warn = structuredClone(byId.r7);
  warn.result.blocked = false;
  assert.equal(entryStatus(warn), 'warn');
});
test('summarizeEntry', () => {
  const s = summarizeEntry(byId.r7);
  assert.equal(s.status, 'blocked');
  assert.equal(s.score, 8);
  assert.equal(s.threshold, 5);
  assert.equal(s.blockAt, 1);
  assert.equal(s.rules[0].active, true);
  assert.ok(s.rules.some((x) => x.id === 942100));
  assert.equal(new Set(s.rules.map((x) => x.id)).size, s.rules.length);
});
test('verdict texts', () => {
  const b = verdict(byId.r8.result);
  assert.equal(b.kind, 'blocked');
  assert.equal(b.detail, 'Inbound anomaly score 25 ≥ threshold 5 (PL1)');
  const l = verdict(byId.r3.result);
  assert.equal(l.kind, 'latent');
  assert.match(l.hint, /PL2/);
  assert.equal(verdict(byId.r1.result).kind, 'clean');
});

/* -------------------------------------------------------- variable labels */
test('describeVar', () => {
  const ctx = { argsGet: new Set(['q']), argsPost: new Set(['json.content']), bodyProcessor: 'JSON' };
  let d = describeVar({ var: 'ARGS:json.content', collection: 'ARGS', key: 'json.content' }, ctx);
  assert.equal(d.kind, 'json');
  assert.equal(d.name, 'content');
  assert.equal(d.label, 'JSON body field “content”');
  d = describeVar({ var: 'ARGS:q', collection: 'ARGS', key: 'q' }, ctx);
  assert.equal(d.kind, 'query');
  assert.equal(d.label, 'Query arg “q”');
  assert.equal(describeVar('REQUEST_HEADERS:User-Agent').label, 'Header “User-Agent”');
  assert.equal(describeVar('REQUEST_COOKIES:app_session').label, 'Cookie “app_session”');
  assert.equal(describeVar('REQUEST_FILENAME').label, 'URL path');
  assert.equal(describeVar('REQUEST_METHOD').kind, 'method');
  assert.equal(describeVar('TX:1').kind, 'internal');
  assert.equal(describeVar('ARGS_NAMES:foo', { argsPost: ['foo'], bodyProcessor: 'URLENCODED' }).label, 'Form field name “foo”');
  assert.equal(describeVar('ARGS:json.a.b').kind, 'json');
  assert.equal(displayArgName('json.a.b', 'json'), 'a.b');
});

/* -------------------------------------------------------------- operators */
test('describeOperator', () => {
  const sqli = byId.r7.result.matches.find((m) => m.id === 942100);
  const d = describeOperator(sqli.links[0].op, sqli.links[0].matches[0]);
  assert.equal(d.kind, 'libinjection');
  assert.equal(d.note, 'fingerprint s&sos');
  const within = byId.r5.result.matches.find((m) => m.id === 911100);
  const w = describeOperator(within.links[0].op, within.links[0].matches[0]);
  assert.match(w.text, /^!@within /);
  assert.match(w.note, /not in the allowed list/);
  assert.equal(describeOperator({ name: 'rx', negated: false, param: 'a+' }).kind, 'regex');
});

/* ----------------------------------------------------------------- links */
test('rule links', () => {
  assert.equal(normalizeVersion('OWASP_CRS/4.30.0'), 'v4.30.0');
  assert.equal(normalizeVersion('v3.3.10'), 'v3.3.10');
  const m = { file: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf', line: 735, origin: 'crs' };
  assert.equal(ruleSourceUrl(m, 'v4.30.0'), 'https://github.com/coreruleset/coreruleset/blob/v4.30.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L735');
  assert.equal(ruleSourceUrl({ file: 'custom-before-crs.conf', line: 1, origin: 'custom' }, 'v4.30.0'), null);
  assert.match(ruleSourceUrl({ file: 'modsecurity.conf-recommended', line: 5, origin: 'modsecurity' }), /ModSecurity/);
});

/* ------------------------------------------------------------ exclusions */
test('generalizePath', () => {
  assert.equal(generalizePath('/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/comments'), '^/api/v1/docs/folders/[^/]+/comments$');
  assert.equal(generalizePath('/users/12345/orders/507f1f77bcf86cd799439011'), '^/users/[^/]+/orders/[^/]+$');
  assert.equal(generalizePath('/assets/index-4f9c2.js'), '^/assets/index-4f9c2\\.js$');
  assert.equal(generalizePath('/a/b?x=1'), '^/a/b$');
  assert.equal(generalizePath('/v1/(x)'), '^/v1/\\x28x\\x29$');
  assert.equal(generalizePath('/a,b/"c"'), '^/a\\x2cb/\\x22c\\x22$', 'no SecLang metacharacters in generated rules');
  assert.equal(isIdSegment('v1'), false);
  assert.equal(isIdSegment('01ARZ3NDEKTSV4RRFFQ69G5FAV'), true);
  assert.equal(escapeRegex('a.b*c'), 'a\\.b\\*c');
});
test('exclusionTarget', () => {
  assert.equal(exclusionTarget({ var: 'ARGS:json.content', collection: 'ARGS', key: 'json.content' }), 'ARGS:json.content');
  assert.equal(exclusionTarget({ var: 'REQUEST_URI_RAW', collection: 'REQUEST_URI_RAW', key: null }), 'REQUEST_URI_RAW');
  assert.equal(exclusionTarget({ var: 'TX:1', collection: 'TX', key: '1' }), null);
  assert.equal(exclusionTarget({ var: 'ARGS:a b', collection: 'ARGS', key: 'a b' }), 'ARGS:/^a\\x20b$/');
  assert.equal(exclusionTarget({ var: 'ARGS:a,ctl:ruleEngine=Off', collection: 'ARGS', key: 'a,ctl:ruleEngine=Off' }), 'ARGS:/^a\\x2cctl\\x3aruleEngine\\x3dOff$/', 'no action injection');
});
test('buildExclusions', () => {
  const ex = buildExclusions({
    ruleId: 942100,
    match: { var: 'ARGS:json.content', collection: 'ARGS', key: 'json.content' },
    path: '/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/comments',
    file: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
    ctx: { argsPost: ['json.content'], bodyProcessor: 'JSON' },
  });
  const rt = ex.find((x) => x.id === 'runtime-target');
  assert.match(rt.code, /^SecRule REQUEST_FILENAME "@rx \^\/api\/v1\/docs\/folders\/\[\^\/\]\+\/comments\$"/);
  assert.match(rt.code, /ctl:ruleRemoveTargetById=942100;ARGS:json\.content"/);
  assert.match(rt.code, /id:1000001/);
  assert.equal(ex.find((x) => x.id === 'configure-target').code, 'SecRuleUpdateTargetById 942100 "!ARGS:json.content"');
  const azItem = ex.find((x) => x.id === 'azure');
  const az = JSON.parse(azItem.code);
  const azEx = az.ruleGroupOverrides[0].rules[0].exclusions[0];
  assert.equal(azEx.matchVariable, 'RequestBodyJsonArgNames');
  assert.equal(azEx.selector, 'content');
  assert.equal(az.ruleGroupOverrides[0].ruleGroupName, 'SQLI');
  assert.deepEqual(azItem.variants.map((v) => v.id), ['json', 'cli', 'terraform', 'bicep', 'appgw']);
  assert.match(azItem.variants.find((v) => v.id === 'terraform').code, /rule_group_name = "SQLI"/);
  assert.match(azItem.variants.find((v) => v.id === 'cli').code, /--match-variable RequestBodyJsonArgNames --operator Equals --value content/);
  assert.equal(ruleGroupName('x.conf'), 'x');
  const cookie = buildExclusions({ ruleId: 941100, match: { var: 'REQUEST_COOKIES:app_session', collection: 'REQUEST_COOKIES', key: 'app_session' }, path: '/' });
  assert.equal(JSON.parse(cookie.find((x) => x.id === 'azure').code).ruleGroupOverrides[0].rules[0].exclusions[0].matchVariable, 'RequestCookieNames');
  const method = buildExclusions({ ruleId: 911100, match: { var: 'REQUEST_METHOD', collection: 'REQUEST_METHOD', key: null }, path: '/x/1' });
  assert.equal(method.find((x) => x.id === 'azure').available, false);
  assert.match(method.find((x) => x.id === 'runtime-rule').code, /ctl:ruleRemoveById=911100/);
});

/* --------------------------------------------------------------- export */
test('shellQuote', () => {
  assert.equal(shellQuote("it's"), "'it'\\''s'");
  assert.equal(shellQuote('a\x01b'), "$'a\\x01b'");
});
test('toCurl / toRawHttp', () => {
  const req = byId.r8.request;
  const c = toCurl(req);
  assert.match(c, /^curl 'https:\/\/dev\.example\.com\/api\/v1\/docs\/folders\/.*\/comments'/);
  assert.match(c, /-H 'Content-Type: application\/json'/);
  assert.doesNotMatch(c, /Content-Length/);
  assert.doesNotMatch(c, /-X 'POST'/);
  assert.match(c, /--data-raw '\{"content":"<script>alert\(document\.cookie\)<\/script>"/);
  assert.match(c, /--http2$/);
  const del = toCurl(byId.r5.request);
  assert.match(del, /-X 'DELETE'/);
  const raw = toRawHttp(byId.r7.request);
  assert.ok(raw.startsWith("GET /api/v1/search?q=1' OR '1'='1 HTTP/2.0\r\nHost: dev.example.com\r\n"));
  assert.ok(raw.endsWith('\r\n\r\n'));
  const b64 = toRawHttp({ method: 'POST', url: 'http://x/y', headers: [], body: Buffer.from('héllo').toString('base64'), bodyEncoding: 'base64' });
  assert.ok(b64.endsWith('héllo'));
  assert.match(toCurl({ method: 'PUT', url: 'http://x/', headers: [], body: 'AAE=', bodyEncoding: 'base64' }), /^printf %s 'AAE=' \| base64 -d \| curl/);
});

/* --------------------------------------------------------------- seclang */
test('tokenizeSecLang', () => {
  const raw = byId.r8.result.matches.find((m) => m.id === 942131).raw;
  const toks = tokenizeSecLang(raw);
  assert.equal(toks.map((t) => t.text).join(''), raw, 'lossless');
  assert.equal(toks[0].type, 'dir');
  assert.ok(toks.some((t) => t.type === 'var' && t.text.startsWith('ARGS_NAMES')));
  assert.ok(toks.some((t) => t.type === 'op' && t.text === '@rx'));
  assert.ok(toks.some((t) => t.type === 'id' && t.text === '942131'));
  assert.ok(toks.some((t) => t.type === 'str' && t.text.startsWith("'SQL Injection")));
  assert.ok(toks.some((t) => t.type === 'op' && t.text === '!@streq'));
  for (const e of mock.entries) for (const m of e.result.matches) if (m.raw) assert.equal(tokenizeSecLang(m.raw).map((t) => t.text).join(''), m.raw);
  const c = tokenizeSecLang('# comment\nSecAction "id:1,phase:1,pass"');
  assert.equal(c[0].type, 'com');
});

/* ----------------------------------------------------------------- misc */
test('countRequests', () => {
  assert.equal(countRequests('$session = New-Object x\nInvoke-WebRequest -Uri a\nInvoke-WebRequest -Uri b', 'powershell'), 2);
  assert.equal(countRequests("curl 'a' -H x ;\ncurl 'b'", 'curl'), 2);
  assert.equal(countRequests('fetch("a"); fetch("b"); fetch("c")', 'fetch'), 3);
  assert.equal(countRequests('GET / HTTP/1.1\nHost: a\n\nPOST /x HTTP/1.1\nHost: a\n', 'raw'), 2);
  assert.equal(countRequests('{"log":{"entries":[{},{}]}}', 'har'), 2);
});
test('prettyBody / decodeBody', () => {
  assert.equal(prettyBody('{"a":1}').text, '{\n  "a": 1\n}');
  assert.equal(prettyBody('not json').json, false);
  assert.equal(decodeBody('aGk=', 'base64'), 'hi');
  assert.equal(decodeBody('x', 'text'), 'x');
});
test('compareBy', () => {
  const cache = new Map();
  const sum = (e) => cache.get(e) || (cache.set(e, summarizeEntry(e)), cache.get(e));
  const sorted = [...mock.entries].sort(compareBy('status', sum));
  assert.equal(entryStatus(sorted[0]), 'blocked');
  const byScore = [...mock.entries].sort(compareBy('score', sum)).reverse();
  assert.equal(byScore[0].id, 'r9');
});

test('hitKey / buildHitIndex', () => {
  assert.equal(hitKey('REQUEST_HEADERS:User-Agent'), 'h:user-agent');
  assert.equal(hitKey('REQUEST_COOKIES_NAMES:app_session'), 'c:app_session');
  assert.equal(hitKey('ARGS:json.content'), 'a:json.content');
  assert.equal(hitKey('ARGS_GET:q'), 'a:q');
  assert.equal(hitKey('REQUEST_URI_RAW'), 's:REQUEST_URI_RAW');
  assert.equal(hitKey('TX:1'), null);
  const idx = buildHitIndex(byId.r9.result.matches, 1);
  const a = idx.get('a:path');
  assert.ok(a.some((x) => x.id === 930120 && x.active));
  assert.ok(a.some((x) => x.id === 920273 && !x.active));
  assert.ok(a[0].active);
  assert.ok(idx.get('s:REQUEST_URI_RAW').some((x) => x.id === 930110));
});

console.log(`${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
