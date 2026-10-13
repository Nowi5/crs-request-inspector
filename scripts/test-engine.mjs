// Unit + integration tests for the rule engine.  node scripts/test-engine.mjs
import assert from 'node:assert/strict';
import { translatePcre, compilePcre } from '../extension/src/engine/pcre.js';
import { TRANSFORMS as T } from '../extension/src/engine/transforms.js';
import { parseJsonArgs, parseUrlencoded, parseCookies, parseMultipart, normalizeProtocol } from '../extension/src/engine/transaction.js';
import { parseActions, parseVariables, parseOperator, logicalLines } from '../extension/src/engine/seclang.js';
import { sha1Binary } from '../extension/src/engine/hash.js';
import { AhoCorasick } from '../extension/src/engine/ahocorasick.js';
import { buildRuleSet } from './lib/node-loader.mjs';

let passed = 0, failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n  ${e.message.split('\n').join('\n  ')}`);
  }
}
const rx = (p, s) => compilePcre(p).re.test(s);

// ---- PCRE translation ----------------------------------------------------------
await test('leading (?i) becomes a flag', () => assert.equal(translatePcre('(?i)abc').flags, 'is'));
await test('(?i) after ^ is scoped', () => {
  assert.ok(rx('^(?i)multipart/', 'MULTIPART/form'));
  assert.ok(!rx('^(?i)multipart/', 'xMULTIPART/'));
});
await test('mid-alternative (?i) keeps alternation semantics', () => {
  assert.ok(rx('a(?i)b|c', 'aB'));
  assert.ok(rx('a(?i)b|c', 'C'));
  assert.ok(!rx('a(?i)b|c', 'AB'));
});
await test('(?-i) turns off', () => assert.ok(!rx('(?i)a(?-i)b', 'AB')) || assert.ok(rx('(?i)a(?-i)b', 'Ab')));
await test('\\s is PCRE whitespace (no NBSP)', () => {
  assert.ok(rx('a\\sb', 'a\tb'));
  assert.ok(!rx('a\\sb', 'a\xa0b'));
  assert.ok(rx('a[\\S]b', 'a\xa0b'));
});
await test('\\A \\z \\Z anchors', () => {
  assert.ok(rx('\\Aab\\z', 'ab'));
  assert.ok(!rx('\\Aab\\z', 'ab\n'));
  assert.ok(rx('ab\\Z', 'ab\n'));
});
await test('possessive and atomic are accepted', () => {
  assert.ok(rx('a++b', 'aab'));
  assert.ok(rx('(?>a|ab)c', 'ac'));
});
await test('POSIX classes', () => assert.ok(rx('[[:alpha:]]+[[:digit:]]', 'abc1')));
await test('\\x{..} and \\Q..\\E', () => {
  assert.ok(rx('\\x{41}', 'A'));
  assert.ok(rx('\\Qa.b\\E', 'a.b'));
  assert.ok(!rx('\\Qa.b\\E', 'axb'));
});
await test('literal braces', () => {
  assert.ok(rx('a{,2}', 'a{,2}'));
  assert.ok(rx('{', '{'));
});
await test('dotall by default', () => assert.ok(rx('a.b', 'a\nb')));
await test('$ is end-only', () => assert.ok(!rx('ab$', 'ab\n')));

// ---- SecLang -----------------------------------------------------------------------
await test('actions parsing', () => {
  const a = parseActions("id:1,phase:2,t:none,t:lowercase,msg:'a, b',setvar:'tx.x=+%{tx.y}',ctl:ruleRemoveTargetById=1;ARGS:a");
  assert.deepEqual(a.map((x) => x.name), ['id', 'phase', 't', 't', 'msg', 'setvar', 'ctl']);
  assert.equal(a[4].value, 'a, b');
  assert.equal(a[6].value, 'ruleRemoveTargetById=1;ARGS:a');
});
await test('variables parsing', () => {
  const v = parseVariables('ARGS|!ARGS:foo|&REQUEST_HEADERS:Content-Type|REQUEST_COOKIES:/^(?:a|b)$/|XML:/*|XML://@*');
  assert.equal(v.length, 6);
  assert.equal(v[1].exclude, true);
  assert.equal(v[2].count, true);
  assert.equal(v[3].keyRegex, '^(?:a|b)$');
  assert.equal(v[4].key, '/*');
  assert.equal(v[5].key, '//@*');
});
await test('operator parsing', () => {
  assert.deepEqual(parseOperator('!@within %{tx.x}'), { name: 'within', negated: true, param: '%{tx.x}' });
  assert.deepEqual(parseOperator('^foo'), { name: 'rx', negated: false, param: '^foo' });
});
await test('continuation lines', () => {
  const l = logicalLines('# c\nSecRule A "b" \\\n    "id:1"\nSecMarker X');
  assert.equal(l.length, 2);
  assert.equal(l[0].line, 2);
  assert.equal(l[0].endLine, 3);
});

// ---- transformations ----------------------------------------------------------------
await test('urlDecodeUni incl. %u, best-fit map and invalid', () => {
  assert.equal(T.urldecodeuni('%27%u0027%uff1c+%zz%'), "''< %zz%");
  assert.equal(T.urldecodeuni('%u2019'), "'");
  assert.equal(T.urldecodeuni('%u00ab'), '<');
});
await test('htmlEntityDecode', () => assert.equal(T.htmlentitydecode('&lt;&#x3c;&#60&quot;&foo;&'), '<<<"&foo;&'));
await test('jsDecode', () => assert.equal(T.jsdecode('\\u003c\\x3c\\74\\n\\q'), '<<<\nq'));
await test('cssDecode', () => assert.equal(T.cssdecode('\\3c \\00003c\\a'), '<<\n'));
await test('cmdLine', () => assert.equal(T.cmdline('C:\\WINDOWS\\sys tem32 /c "Ech^o" , ; (x)'), 'c:windowssys tem32/c echo(x)'));
await test('normalizePath', () => assert.equal(T.normalizepath('/a/./b/../../c//d/'), '/c/d/'));
await test('utf8toUnicode', () => assert.equal(T.utf8tounicode('a\xc3\xa9\xe2\x82\xac'), 'a%u00e9%u20ac'));
await test('removeComments / replaceComments', () => {
  assert.equal(T.replacecomments('a/*x*/b/*'), 'a b ');
  assert.equal(T.removecomments('a--b'), 'a');
});
await test('sha1', () => assert.equal(T.hexencode(sha1Binary('abc')), 'a9993e364706816aba3e25717850c26c9cd0d89d'));
await test('lowercase is ASCII-only', () => assert.equal(T.lowercase('AÀ'), 'aÀ'));
await test('base64Decode stops at invalid char', () => assert.equal(T.base64decode('YWJj$ZGVm'), 'abc'));

// ---- body parsing ----------------------------------------------------------------------
await test('JSON args flattening', () => {
  const a = parseJsonArgs('{"content":"x","n":1.50,"a":[1,{"b":null}],"o":{"p":true},"e":[]}');
  assert.deepEqual(a.map((x) => `${x.name}=${x.value}`), ['json.content=x', 'json.n=1.50', 'json.a.0=1', 'json.a.1.b=', 'json.o.p=true']);
  assert.throws(() => parseJsonArgs('{"a":'));
});
await test('urlencoded + cookies', () => {
  assert.deepEqual(parseUrlencoded('a=1&b=%27x+y&c'), [{ name: 'a', value: '1' }, { name: 'b', value: "'x y" }, { name: 'c', value: '' }]);
  assert.deepEqual(parseCookies('a=1; b=x=y;c'), [{ name: 'a', value: '1' }, { name: 'b', value: 'x=y' }, { name: 'c', value: '' }]);
});
await test('multipart', () => {
  const body = '--XX\r\nContent-Disposition: form-data; name="a"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name="f"; filename="x.php"\r\nContent-Type: text/plain\r\n\r\n<?php ?>\r\n--XX--\r\n';
  const r = parseMultipart(body, 'multipart/form-data; boundary=XX');
  assert.deepEqual(r.args, [{ name: 'a', value: 'hello' }]);
  assert.equal(r.files[0].filename, 'x.php');
  assert.equal(r.error, null);
});
await test('protocol normalisation', () => {
  assert.equal(normalizeProtocol('h2'), 'HTTP/2.0');
  assert.equal(normalizeProtocol('http/2.0'), 'HTTP/2.0');
  assert.equal(normalizeProtocol('h3'), 'HTTP/3.0');
  assert.equal(normalizeProtocol('HTTP/1.1'), 'HTTP/1.1');
  assert.equal(normalizeProtocol(''), 'HTTP/1.1');
});
await test('Aho-Corasick', () => {
  const ac = new AhoCorasick(['he', 'she', 'his', 'hers']);
  assert.deepEqual(ac.search('ushers'), { start: 1, end: 4, phrase: 'she' });
  assert.equal(ac.search('xyz'), null);
});

// ---- end to end -----------------------------------------------------------------------------
const rs = await buildRuleSet({});
assert.equal(rs.errors.length, 0, JSON.stringify(rs.errors));
const H = [{ name: 'Host', value: 'dev.example.com' }, { name: 'User-Agent', value: 'Mozilla/5.0' }, { name: 'Accept', value: '*/*' }];
const jsonPost = (obj) => {
  const body = JSON.stringify(obj);
  return { method: 'POST', url: 'https://dev.example.com/api/v1/x', httpVersion: 'HTTP/2.0', headers: [...H, { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(body.length) }], body };
};
const ids = (r) => r.matches.filter((m) => m.log && !m.isMeta).map((m) => m.id);

await test('clean GET passes', () => {
  const r = rs.evaluate({ method: 'GET', url: 'https://dev.example.com/api/v1/workspace-options', httpVersion: 'HTTP/2.0', headers: H });
  assert.equal(r.blocked, false);
  assert.deepEqual(ids(r), []);
});
await test('hex-encoded chat message passes at PL1', () => {
  const r = rs.evaluate(jsonPost({ content: 'enc:hex1:48656c6c6f', resourceItems: [] }));
  assert.equal(r.blocked, false);
  assert.equal(r.inbound.cumulative[1], 0);
});
await test('SQLi in JSON is blocked by 942100 with fingerprint', () => {
  const r = rs.evaluate(jsonPost({ content: "1' OR '1'='1" }));
  assert.equal(r.blocked, true);
  assert.equal(r.interruption.ruleId, 949110);
  const m = r.matches.find((x) => x.id === 942100);
  assert.equal(m.links[0].matches[0].var, 'ARGS:json.content');
  assert.match(m.links[0].matches[0].detail, /fingerprint: s&sos/);
});
await test('DELETE is not an allowed method by default', () => {
  const r = rs.evaluate({ method: 'DELETE', url: 'https://dev.example.com/api/x', httpVersion: 'HTTP/2.0', headers: H });
  assert.ok(ids(r).includes(911100));
  assert.equal(r.blocked, true);
});
await test('custom rules before CRS can allow DELETE', async () => {
  const rs2 = await buildRuleSet({ customRulesBefore: `SecAction "id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"` });
  const r = rs2.evaluate({ method: 'DELETE', url: 'https://dev.example.com/api/x', httpVersion: 'HTTP/2.0', headers: H });
  assert.equal(r.blocked, false);
});
await test('runtime exclusion removes a target', async () => {
  const rs2 = await buildRuleSet({ customRulesBefore: `SecRule REQUEST_FILENAME "@streq /api/v1/x" "id:1000,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:json.content"` });
  const r = rs2.evaluate(jsonPost({ content: "1' OR '1'='1" }));
  assert.ok(!ids(r).includes(942100));
});
await test('SecRuleUpdateTargetById after CRS', async () => {
  const rs2 = await buildRuleSet({ customRulesAfter: `SecRuleUpdateTargetById 942100 "!ARGS:json.content"` });
  const r = rs2.evaluate(jsonPost({ content: "1' OR '1'='1" }));
  assert.ok(!ids(r).includes(942100));
});
await test('higher PL matches are reported but do not block at PL1', () => {
  const r = rs.evaluate(jsonPost({ content: "Can you select the rows from the table where the user's name is O'Brien?" }));
  assert.equal(r.blocked, false);
  assert.ok(r.inbound.cumulative[2] >= 5);
  assert.ok(r.matches.some((m) => m.pl === 2 && !m.isMeta));
});
await test('invalid JSON triggers ModSecurity 200002', () => {
  const r = rs.evaluate({ ...jsonPost({}), body: '{"a":' });
  assert.equal(r.blocked, true);
  assert.equal(r.interruption.ruleId, 200002);
});
await test('body above SecRequestBodyNoFilesLimit is rejected', () => {
  const r = rs.evaluate(jsonPost({ content: 'x'.repeat(140000) }));
  assert.equal(r.interruption.ruleId, 'ENGINE');
  assert.equal(r.interruption.status, 413);
});
await test('response leakage detection (phase 4)', () => {
  const r = rs.evaluate({
    method: 'GET', url: 'https://dev.example.com/page', httpVersion: 'HTTP/1.1', headers: H,
    response: { status: 500, statusText: 'Error', httpVersion: 'HTTP/1.1', headers: [{ name: 'Content-Type', value: 'text/html' }], mimeType: 'text/html', body: '<b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/x.php on line 3' },
  });
  assert.ok(r.matches.some((m) => String(m.id).startsWith('95')), 'expected a RESPONSE-95x match');
});

for (const v of ['v4.25.2', 'v3.3.10']) {
  await test(`ruleset ${v} loads and detects SQLi`, async () => {
    const rsv = await buildRuleSet({ version: v });
    assert.equal(rsv.errors.length, 0, JSON.stringify(rsv.errors.slice(0, 3)));
    const r = rsv.evaluate(jsonPost({ content: "1' OR '1'='1" }));
    assert.equal(r.blocked, true);
    assert.ok(ids(r).includes(942100));
  });
}

// ---- regression tests (review findings) --------------------------------------------------------
const { RuleSet } = await import('../extension/src/engine/engine.js');
const { parseXml } = await import('../extension/src/engine/transaction.js');
const mini = (text, origin) => {
  const r = new RuleSet();
  r.addFile('t.conf', `SecDefaultAction "phase:1,log,pass"\nSecDefaultAction "phase:2,log,pass"\n${text}`, { origin });
  r.finalize();
  assert.deepEqual(r.errors, []);
  return r;
};
const mreq = (o = {}) => ({ method: 'GET', url: 'http://h/', httpVersion: 'HTTP/1.1', headers: [{ name: 'Host', value: 'h' }], body: null, ...o });
const mids = (res) => res.matches.map((m) => m.id);

await test('rule action override log: a deny rule passes (no interruption, no score)', () => {
  const r = mini(`SecRule ARGS "@contains x" "id:5,phase:1,deny,status:400,setvar:'tx.anomaly_score_pl1=+5'"`);
  const res = r.evaluate(mreq({ url: 'http://h/?a=x' }), { ruleActions: new Map([[5, 'log']]) });
  assert.equal(res.blocked, false);
  assert.deepEqual(mids(res), [5]);
  assert.equal(res.matches[0].override, 'log');
  assert.equal(res.matches[0].disruptive, 'pass');
  assert.equal(res.inbound.cumulative[4], 0);
  assert.equal(r.evaluate(mreq({ url: 'http://h/?a=x' })).blocked, true);
});
await test('SecRuleRemoveByTag / ByMsg: unanchored case-sensitive regex (ModSecurity v2)', () => {
  const rule = `SecRule ARGS "@contains x" "id:1,phase:1,pass,msg:'Some XSS Attack',tag:'OWASP_CRS/WEB_ATTACK/XSS'"`;
  assert.deepEqual(mids(mini(`${rule}\nSecRuleRemoveByTag "WEB_ATTACK/XSS"`).evaluate(mreq({ url: 'http://h/?a=x' }))), []);
  assert.deepEqual(mids(mini(`${rule}\nSecRuleRemoveByTag "web_attack/xss"`).evaluate(mreq({ url: 'http://h/?a=x' }))), [1]);
  assert.deepEqual(mids(mini(`${rule}\nSecRuleRemoveByMsg "XSS"`).evaluate(mreq({ url: 'http://h/?a=x' }))), []);
  assert.deepEqual(mids(mini(`${rule}\nSecRuleUpdateTargetByTag "^OWASP_CRS" "!ARGS:a"`).evaluate(mreq({ url: 'http://h/?a=x' }))), []);
});
await test('ctl:ruleRemoveByTag is a regex, ctl:ruleRemoveTargetByTag an exact tag', () => {
  const r1 = mini(`SecAction "id:1,phase:1,pass,ctl:ruleRemoveByTag=attack-sql"\nSecRule ARGS "@contains x" "id:2,phase:1,pass,tag:'attack-sqli'"`);
  assert.deepEqual(mids(r1.evaluate(mreq({ url: 'http://h/?a=x' }))), [1]);
  const r2 = mini(`SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:a"\nSecRule ARGS "@contains x" "id:2,phase:1,pass,tag:'OWASP_CRS'"\nSecRule ARGS "@contains x" "id:3,phase:1,pass,tag:'OWASP_CRS/x'"`);
  assert.deepEqual(mids(r2.evaluate(mreq({ url: 'http://h/?a=x' }))), [1, 3]);
  const r3 = mini(`SecAction "id:1,phase:1,pass,ctl:ruleRemoveByTag=OWASP_CRS"\nSecRule ARGS "@contains x" "id:2,phase:1,pass,tag:'OWASP_CRS'"`);
  assert.deepEqual(mids(r3.evaluate(mreq({ url: 'http://h/?a=x' }))), [1]);
});
await test('!ARGS_GET:x excludes ARGS entries only for Azure-profile directives', () => {
  const rules = `SecRule ARGS "@contains x" "id:1,phase:2,pass"`;
  const post = mreq({ method: 'POST', url: 'http://h/?q=x', headers: [{ name: 'Host', value: 'h' }, { name: 'Content-Type', value: 'application/x-www-form-urlencoded' }], body: 'q=x' });
  const vars = (rs) => rs.evaluate(post).matches[0].links[0].matches.map((m) => m.var);
  const plain = mini(rules);
  plain.addFile('u.conf', 'SecRuleUpdateTargetById 1 "!ARGS_GET:q"');
  plain.finalize();
  assert.deepEqual(vars(plain), ['ARGS:q', 'ARGS:q'], 'ModSecurity: different collection, no effect');
  const az = mini(rules);
  az.addFile('azure.conf', 'SecRuleUpdateTargetById 1 "!ARGS_GET:q"', { origin: 'azure' });
  az.finalize();
  const m = az.evaluate(post).matches[0].links[0].matches;
  assert.equal(m.length, 1);
  assert.equal(m[0].value, 'x');
  assert.deepEqual(az.evaluate(mreq({ url: 'http://h/?q=x' })).matches, []);
});
await test('multipart: boundary only recognised at line start', () => {
  const body = '--XYZ\r\nContent-Disposition: form-data; name="note"\r\n\r\nsee x--XYZy\r\n--XYZ--\r\n';
  const r = parseMultipart(body, 'multipart/form-data; boundary=XYZ');
  assert.deepEqual(r.args, [{ name: 'note', value: 'see x--XYZy' }]);
  assert.equal(r.flags.INVALID_PART, 0);
  assert.equal(r.error, null);
  const lf = parseMultipart('--XYZ\nContent-Disposition: form-data; name="a"\n\n1\n--XYZ--\n', 'multipart/form-data; boundary=XYZ');
  assert.deepEqual(lf.args, [{ name: 'a', value: '1' }]);
});
await test('PCRE: (?m) and non-DOTALL use LF only as line terminator', () => {
  assert.ok(!rx('(?m)^abc', 'x\rabc'));
  assert.ok(rx('(?m)^abc', 'x\nabc'));
  assert.ok(rx('(?m)abc$', 'abc\nx'));
  assert.ok(!rx('(?m)abc$', 'abc\rx'));
  assert.ok(rx('(?m)^abc$', 'abc'));
  assert.ok(rx('(?-s)a.b', 'a\rb'));
  assert.ok(!rx('(?-s)a.b', 'a\nb'));
  assert.ok(rx('(?-s:a.)b.c', 'a\rb\nc'), '(?-s:...) is scoped');
  assert.ok(!rx('^b', 'a\nb'));
  assert.ok(!compilePcre('(?m)^x').re.flags.includes('m'));
});
await test('PCRE: negated POSIX class inside a class', () => {
  assert.ok(rx('^[[:^digit:]]+$', 'ab-\xff'));
  assert.ok(!rx('[[:^digit:]]', '123'));
  assert.ok(rx('^[[:^alpha:][:digit:]]+$', '1-2'));
  assert.ok(!rx('[[:^alpha:]0]', 'a'));
});
await test('PCRE: (?i) does not fold Latin-1 letters (byte mode)', () => {
  assert.ok(!rx('(?i)\xc9', '\xe9'));
  assert.ok(rx('(?i)\xc9', '\xc9'));
  assert.ok(!rx('(?i)\\xc9', '\xe9'));
  assert.ok(rx('(?i)a\xe9+', 'A\xe9\xe9'));
  assert.ok(compilePcre('(?i)[\xc0-\xde]').warnings.some((w) => /Latin-1/.test(w)));
  assert.deepEqual(compilePcre('(?i)[\\x80-\\xff\\S]').warnings, []);
  // unicode subjects (Azure custom rules) keep Unicode-style folding
  assert.ok(compilePcre('(?i)\xc9', { unicode: true, baseFlags: '' }).re.test('\xe9'));
});
await test('XML parser is linear on hostile input and keeps quoted > in attributes', () => {
  const t0 = Date.now();
  parseXml('<r>' + '<a'.repeat(200000));
  parseXml('<r>' + '<!--'.repeat(100000));
  parseXml('<!DOCTYPE [' + ']x'.repeat(100000));
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  const x = parseXml('<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ANY>]><r a="1>2"><!-- c --><b>t&lt;x</b><![CDATA[<y>]]></r>');
  assert.equal(x.error, null);
  assert.equal(x.text, 't<x<y>');
  assert.deepEqual(x.attrs.map((a) => a.value), ['1>2']);
  assert.ok(parseXml('<r><!-- open').error);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
