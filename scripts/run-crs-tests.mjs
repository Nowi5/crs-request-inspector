// Runs the official CRS regression tests (go-ftw YAML) against the JS engine.
//
//   node scripts/fetch-crs.mjs --tests v4.30.0   (once, downloads tests to vendor/)
//   node scripts/run-crs-tests.mjs [v4.30.0] [--rule 942100] [--verbose] [--file REQUEST-942]
//
// Configuration mirrors the CRS CI (tests/docker-compose.yml): paranoia level 4,
// arg/file size limits, ModSecurity v2 overrides (tests/regression/httpd-overrides.yaml).
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { buildRuleSet, ROOT } from './lib/node-loader.mjs';

const args = process.argv.slice(2);
const version = args.find((a) => /^v\d/.test(a)) || 'v4.30.0';
const ruleFilter = args.includes('--rule') ? args[args.indexOf('--rule') + 1] : null;
const fileFilter = args.includes('--file') ? args[args.indexOf('--file') + 1] : null;
const verbose = args.includes('--verbose');
const testsDir = path.join(ROOT, 'vendor', `tests-${version}`);
if (!existsSync(testsDir)) {
  console.error(`Missing ${testsDir}. Run: node scripts/fetch-crs.mjs --tests ${version}`);
  process.exit(2);
}

function walk(dir) {
  const out = [];
  for (const f of readdirSync(dir)) {
    const p = path.join(dir, f);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (f.endsWith('.yaml') || f.endsWith('.yml')) out.push(p);
  }
  return out;
}

// --- overrides --------------------------------------------------------------
const overrides = [];
const ovPath = path.join(ROOT, 'vendor', 'httpd-overrides.yaml');
if (existsSync(ovPath)) {
  const ov = yaml.load(readFileSync(ovPath, 'utf8'));
  for (const o of ov.test_overrides || []) overrides.push(o);
}
function overrideFor(ruleId, testId) {
  return overrides.find((o) => {
    if (String(o.rule_id) !== String(ruleId)) return false;
    const ids = o.test_ids || (o.test_id != null ? [o.test_id] : null);
    return !ids || ids.map(String).includes(String(testId));
  });
}

// --- raw request parsing (encoded_request) ------------------------------------
function parseRaw(raw) {
  const sep = raw.search(/\r?\n\r?\n/);
  const head = sep >= 0 ? raw.slice(0, sep) : raw;
  const body = sep >= 0 ? raw.slice(sep).replace(/^\r?\n\r?\n/, '') : '';
  const lines = head.split(/\r?\n/);
  const [method, uri, version] = lines[0].split(' ');
  const headers = [];
  for (const l of lines.slice(1)) {
    const i = l.indexOf(':');
    if (i > 0) headers.push({ name: l.slice(0, i), value: l.slice(i + 1).trim() });
  }
  return { method, uri, version, headers, body };
}

function buildRequest(input) {
  let method, uri, versionStr, headers, data;
  if (input.encoded_request) {
    const raw = Buffer.from(input.encoded_request, 'base64').toString('latin1');
    const r = parseRaw(raw);
    ({ method, uri } = r);
    versionStr = r.version;
    headers = r.headers;
    data = r.body;
    // keep raw bytes: convert latin1 -> base64 body
    return {
      method,
      url: `http://${headers.find((h) => /^host$/i.test(h.name))?.value || 'localhost'}${uri.startsWith('/') ? uri : '/' + uri}`,
      requestTarget: uri,
      httpVersion: versionStr || 'HTTP/1.1',
      headers: headers.map((h) => ({ name: Buffer.from(h.name, 'latin1').toString('utf8'), value: Buffer.from(h.value, 'latin1').toString('utf8') })),
      body: data ? Buffer.from(data, 'latin1').toString('base64') : null,
      bodyEncoding: 'base64',
    };
  }
  method = input.method || 'GET';
  uri = input.uri ?? '/';
  versionStr = input.version || 'HTTP/1.1';
  headers = Object.entries(input.headers || {}).map(([name, value]) => ({ name, value: String(value) }));
  data = input.data;
  if (Array.isArray(data)) data = data.join('\r\n');
  if (data != null) data = String(data);
  const auto = input.autocomplete_headers !== false;
  if (auto && data) {
    if (!headers.some((h) => /^content-length$/i.test(h.name))) headers.push({ name: 'Content-Length', value: String(Buffer.byteLength(data)) });
    if (!headers.some((h) => /^content-type$/i.test(h.name))) headers.push({ name: 'Content-Type', value: 'application/x-www-form-urlencoded' });
  }
  if (auto && !headers.some((h) => /^connection$/i.test(h.name))) headers.push({ name: 'Connection', value: 'close' });
  const host = headers.find((h) => /^host$/i.test(h.name))?.value || 'localhost';
  let response;
  // Emulate the albedo backend's /reflect endpoint used by RESPONSE-* tests.
  if (/^\/reflect/.test(uri) && data) {
    try {
      const spec = JSON.parse(data);
      let body = spec.body ?? '';
      if (spec.encodedBody) body = Buffer.from(spec.encodedBody, 'base64').toString('utf8');
      response = {
        status: spec.status || 200,
        statusText: 'OK',
        httpVersion: 'HTTP/1.1',
        headers: Object.entries(spec.headers || {}).map(([name, value]) => ({ name, value: String(value) })),
        mimeType: spec.headers?.['Content-Type'] || 'text/plain',
        body,
        bodyEncoding: 'text',
      };
    } catch {}
  }
  return {
    method,
    url: `http://${host}${uri.startsWith('/') ? uri : '/' + uri}`,
    requestTarget: uri,
    httpVersion: versionStr,
    headers,
    body: data ?? null,
    bodyEncoding: 'text',
    response,
  };
}

// --- run ------------------------------------------------------------------------
const rs = await buildRuleSet({
  version,
  blockingParanoiaLevel: 4,
  detectionParanoiaLevel: 4,
  customRulesBefore: [
    'SecResponseBodyMimeType text/plain text/html text/xml application/json',
    'SecAction "id:900200,phase:1,pass,nolog,setvar:tx.arg_length=400,setvar:tx.total_arg_length=6400,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.crs_xml_attr_inspect=1"',
  ].join('\n'),
});
console.log(`CRS ${rs.meta.version}: ${rs.ruleCount} rules, ${rs.errors.length} errors, ${rs.warnings.length} warnings`);
for (const w of rs.warnings.slice(0, 20)) console.log('  WARN', `${w.file}:${w.line}`, w.message);

let total = 0, passed = 0, skipped = 0;
const failures = [];
const byFile = {};
for (const file of walk(testsDir).sort()) {
  const rel = path.relative(testsDir, file);
  if (fileFilter && !rel.includes(fileFilter)) continue;
  let doc;
  try {
    doc = yaml.load(readFileSync(file, 'utf8'));
  } catch (e) {
    console.log('YAML error', rel, e.message);
    continue;
  }
  if (!doc) continue;
  const ruleId = doc.rule_id;
  if (ruleFilter && String(ruleId) !== ruleFilter) continue;
  for (const test of doc.tests || []) {
    const testId = test.test_id ?? test.test_title;
    for (const [si, stage] of (test.stages || []).entries()) {
      const s = stage.stage || stage;
      const input = s.input || {};
      let output = s.output || {};
      const ov = overrideFor(ruleId, testId);
      if (ov?.output) output = ov.output;
      const log = output.log || {};
      const expect = (log.expect_ids || output.log_contains_ids || []).map(Number);
      const noExpect = (log.no_expect_ids || []).map(Number);
      if (output.expect_error || (!expect.length && !noExpect.length)) {
        skipped++;
        continue;
      }
      total++;
      let res;
      try {
        res = rs.evaluate(buildRequest(input), { continueAfterInterruption: true, responseAfterBlock: true });
      } catch (e) {
        failures.push({ rel, ruleId, testId, si, reason: `exception ${e.stack}` });
        continue;
      }
      const ids = new Set(res.matches.filter((m) => m.log).map((m) => m.id));
      const missing = expect.filter((id) => !ids.has(id));
      const unexpected = noExpect.filter((id) => ids.has(id));
      const key = rel.split(path.sep)[0];
      byFile[key] ||= { total: 0, passed: 0 };
      byFile[key].total++;
      if (!missing.length && !unexpected.length) {
        passed++;
        byFile[key].passed++;
      } else {
        failures.push({ rel, ruleId, testId, si, missing, unexpected, desc: test.desc, input, res });
      }
    }
  }
}

console.log(`\nPassed ${passed}/${total} (${((passed / total) * 100).toFixed(2)}%), skipped ${skipped}`);
for (const [k, v] of Object.entries(byFile)) if (v.passed !== v.total) console.log(`  ${k}: ${v.passed}/${v.total}`);
const show = verbose ? failures : failures.slice(0, 40);
for (const f of show) {
  console.log(`\nFAIL ${f.rel} test ${f.testId} stage ${f.si}: ${f.desc || ''}`);
  if (f.reason) console.log('  ', f.reason);
  if (f.missing?.length) console.log('   missing:', f.missing.join(','));
  if (f.unexpected?.length) console.log('   unexpected:', f.unexpected.join(','));
  if (verbose && f.input) console.log('   input:', JSON.stringify(f.input).slice(0, 600));
  if (verbose && f.res) console.log('   matched:', f.res.matches.filter((m) => m.log).map((m) => m.id).join(','), f.res.warnings.join(' | '));
}
