#!/usr/bin/env node
// Test runner for the JavaScript libinjection port (extension/src/engine/libinjection.js).
//
// Runs the upstream libinjection unit tests (vendor/libinjection/tests/test-*.txt) with
// the semantics of upstream src/testdriver.c, the upstream sample tests
// (vendor/libinjection/data/*.txt) with the semantics of src/reader.c and the
// thresholds of src/test-samples-*.sh, plus a few sanity checks.
//
// Usage: node scripts/test-libinjection.mjs [-v] [path/to/libinjection]
//   -v   print every failing sample line (not only unit test failures)
//
// Files are read as bytes (latin1), so each char code is one byte, like the C harness.

import fs from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  detectSQLi,
  detectXSS,
  sqliTokenize,
  sqliFold,
  html5Tokenize,
  FLAG_QUOTE_NONE,
  FLAG_SQL_ANSI,
  LIBINJECTION_VERSION,
} from '../extension/src/engine/libinjection.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const verbose = args.includes('-v');
const LIBDIR = path.resolve(args.find((a) => !a.startsWith('-')) || path.join(ROOT, 'vendor', 'libinjection'));
if (!fs.existsSync(path.join(LIBDIR, 'tests'))) {
  console.log(`SKIP libinjection upstream tests: ${path.relative(ROOT, LIBDIR)}/tests not found – run "node scripts/fetch-test-data.mjs" first.`);
  process.exit(0);
}

/* ---- C harness helpers ------------------------------------------------------ */

/** fgets() with a buffer of `size` bytes: lines of at most size-1 chars, keeping '\n'. */
function fgetsLines(content, size = 8192) {
  const out = [];
  let i = 0;
  while (i < content.length) {
    const nl = content.indexOf('\n', i);
    let end = nl === -1 ? content.length : nl + 1;
    if (end - i > size - 1) end = i + size - 1;
    out.push(content.slice(i, end));
    i = end;
  }
  return out;
}

/** C-string view: everything up to the first NUL. */
function cstr(s) {
  const i = s.indexOf('\0');
  return i === -1 ? s : s.slice(0, i);
}

/** modp_rtrim() */
function rtrim(s) {
  let len = s.length;
  while (len) {
    const c = s[len - 1];
    if (c === ' ' || c === '\n' || c === '\t' || c === '\r') len--;
    else break;
  }
  return s.slice(0, len);
}

/** testdriver.c print_string() */
function printString(t) {
  let out = '';
  if (t.strOpen !== '\0') out += t.strOpen;
  out += cstr(t.val);
  if (t.strClose !== '\0') out += t.strClose;
  return out;
}

/** testdriver.c print_token() */
function printToken(t) {
  let out = `${t.type} `;
  if (t.type === 's') {
    out += printString(t);
  } else if (t.type === 'v') {
    if (t.count >= 1) out += '@';
    if (t.count === 2) out += '@';
    out += printString(t);
  } else {
    out += cstr(t.val);
  }
  return out + '\n';
}

/** reader.c modp_url_decode() (note: a %XX at the very end is NOT decoded, like upstream). */
function urlDecode(s) {
  const hex = (c) => {
    const v = parseInt(c, 16);
    return /^[0-9a-fA-F]$/.test(c) ? v : 256;
  };
  let out = '';
  const len = s.length;
  let i = 0;
  while (i < len) {
    const c = s[i];
    if (c === '+') {
      out += ' ';
      i += 1;
    } else if (c === '%') {
      if (i + 2 < len) {
        const d = (hex(s[i + 1]) << 4) | hex(s[i + 2]);
        if (d < 256) {
          out += String.fromCharCode(d);
          i += 3;
        } else {
          out += '%';
          i += 1;
        }
      } else {
        out += '%';
        i += 1;
      }
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/* ---- unit tests (testdriver.c) --------------------------------------------- */

function runUnitTest(content, testtype) {
  let count = 0;
  const bufs = { test: '', input: '', expected: '' };
  let buf = null;
  for (const line of fgetsLines(content)) {
    if (count === 0 && line === '--TEST--\n') {
      buf = 'test';
      count = 1;
    } else if (count === 1 && line === '--INPUT--\n') {
      buf = 'input';
      count = 2;
    } else if (count === 2 && line === '--EXPECTED--\n') {
      buf = 'expected';
      count = 3;
    } else {
      if (buf === null) return { ok: false, error: 'content before --TEST--' };
      bufs[buf] += cstr(line); // strcat()
    }
  }
  if (count !== 3) return { ok: true, skipped: true }; // testdriver treats this as "ok"

  const expected = rtrim(bufs.expected);
  const input = rtrim(bufs.input);
  let actual = '';
  switch (testtype) {
    case 'tokens':
      for (const t of sqliTokenize(input, FLAG_QUOTE_NONE | FLAG_SQL_ANSI)) actual += printToken(t);
      break;
    case 'folding':
      for (const t of sqliFold(input, FLAG_QUOTE_NONE | FLAG_SQL_ANSI)) actual += printToken(t);
      break;
    case 'sqli': {
      const r = detectSQLi(input);
      if (r.isSqli) actual = r.fingerprint;
      break;
    }
    case 'html5':
      for (const t of html5Tokenize(input)) actual += `${t.type},${t.len},${cstr(t.value)}\n`;
      break;
    case 'xss':
      actual = detectXSS(input) ? '1' : '0';
      break;
    default:
      throw new Error(`unknown test type ${testtype}`);
  }
  actual = rtrim(cstr(actual));
  return { ok: actual === expected, input, expected, actual };
}

function testTypeOf(name) {
  if (name.includes('test-tokens-')) return 'tokens';
  if (name.includes('test-folding-')) return 'folding';
  if (name.includes('test-sqli-')) return 'sqli';
  if (name.includes('test-html5-')) return 'html5';
  if (name.includes('test-xss-')) return 'xss';
  return null;
}

/* ---- sample tests (reader.c) ------------------------------------------------- */

async function runSamples(files, mode) {
  let positives = 0;
  let negatives = 0;
  const hits = [];
  const misses = [];
  for (const file of files) {
    const content = await readFile(file, 'latin1');
    let linenum = 0;
    for (const raw of fgetsLines(content)) {
      linenum += 1;
      const line = rtrim(cstr(raw));
      if (line.length === 0 || line[0] === '#') continue;
      const input = urlDecode(line);
      let detected;
      let fp = '';
      if (mode === 'sqli') {
        const r = detectSQLi(input);
        detected = r.isSqli;
        fp = r.fingerprint;
      } else {
        detected = detectXSS(input);
      }
      const rec = `${path.basename(file)}:${linenum}\t${fp}\t${line}`;
      if (detected) {
        positives += 1;
        hits.push(rec);
      } else {
        negatives += 1;
        misses.push(rec);
      }
    }
  }
  return { positives, negatives, hits, misses };
}

/* ---- main -------------------------------------------------------------------- */

const results = [];
let failed = false;

function report(name, pass, total, extra = '') {
  results.push({ name, pass, total, extra });
  if (pass !== total) failed = true;
}

async function main() {
  console.log(`libinjection JS port, data version ${LIBINJECTION_VERSION}; upstream files from ${LIBDIR}`);

  // Unit tests
  const testDir = path.join(LIBDIR, 'tests');
  let names = [];
  try {
    names = (await readdir(testDir)).filter((n) => /^test-.*\.txt$/.test(n)).sort();
  } catch {
    console.log(`(no upstream tests found in ${testDir})`);
  }
  const perType = new Map();
  for (const n of names) {
    const type = testTypeOf(n);
    if (!type) {
      console.log(`Unknown test type: ${n}`);
      continue;
    }
    if (!perType.has(type)) perType.set(type, { pass: 0, total: 0, skipped: 0 });
    const st = perType.get(type);
    let content;
    try {
      content = await readFile(path.join(testDir, n), 'latin1');
    } catch (e) {
      console.log(`could not read ${n} (${e.code || e.message}) -- skipped`);
      st.skipped += 1;
      continue;
    }
    const r = runUnitTest(content, type);
    st.total += 1;
    if (r.skipped) st.skipped += 1;
    if (r.ok) {
      st.pass += 1;
    } else {
      console.log(`FAIL ${n}\nINPUT:\n${JSON.stringify(r.input)}\nEXPECTED:\n${r.expected}\nGOT:\n${r.actual}\n==`);
    }
  }
  for (const type of ['tokens', 'folding', 'sqli', 'html5', 'xss']) {
    const st = perType.get(type);
    if (!st) continue;
    report(`unit: test-${type}-*`, st.pass, st.total, st.skipped ? `(${st.skipped} malformed/unreadable)` : '');
  }

  // Sample tests
  const dataDir = path.join(LIBDIR, 'data');
  let dataFiles = [];
  try {
    dataFiles = (await readdir(dataDir)).sort();
  } catch {
    console.log(`(no upstream sample data found in ${dataDir})`);
  }
  const pick = (re) => dataFiles.filter((n) => re.test(n)).map((n) => path.join(dataDir, n));
  const samples = [
    // [name, files, mode, invert, max] -- from src/test-samples-*.sh
    ['samples: sqli positive (data/sqli-*.txt), misses <= 18', pick(/^sqli-.*\.txt$/), 'sqli', true, 18],
    ['samples: sqli negative (data/false_*.txt), detections <= 21', pick(/^false_.*\.txt$/), 'sqli', false, 21],
    ['samples: xss positive (data/xss*), misses <= 20', pick(/^xss/), 'xss', true, 20],
  ];
  for (const [name, files, mode, invert, max] of samples) {
    if (files.length === 0) continue;
    const r = await runSamples(files, mode);
    const bad = invert ? r.misses : r.hits;
    const total = r.positives + r.negatives;
    const ok = bad.length <= max;
    results.push({
      name,
      pass: ok ? 1 : 0,
      total: 1,
      extra: `${files.length} files, ${total} inputs, ${invert ? 'missed' : 'detected'} ${bad.length}`,
    });
    if (!ok) failed = true;
    if (verbose || !ok) for (const b of bad) console.log(`  ${invert ? 'MISS' : 'HIT '} ${b}`);
  }

  // Sanity checks
  const sanity = [
    ["detectSQLi(\"1' OR '1'='1\") is SQLi", () => detectSQLi("1' OR '1'='1").isSqli === true],
    ['detectSQLi("hello world") is not SQLi', () => detectSQLi('hello world').isSqli === false],
    ['detectSQLi("enc:hex1:48656c6c6f") is not SQLi', () => detectSQLi('enc:hex1:48656c6c6f').isSqli === false],
    ['detectSQLi("") is not SQLi', () => detectSQLi('').isSqli === false && detectSQLi('').fingerprint === ''],
    ["detectSQLi(\"1' OR '1'='1\") fingerprint is s&sos", () => detectSQLi("1' OR '1'='1").fingerprint === 's&sos'],
    ['detectSQLi("1 UNION SELECT password FROM users--") is SQLi', () => detectSQLi('1 UNION SELECT password FROM users--').isSqli],
    ['detectXSS("<script>alert(1)</script>")', () => detectXSS('<script>alert(1)</script>') === true],
    ['detectXSS("<img src=x onerror=alert(1)>")', () => detectXSS('<img src=x onerror=alert(1)>') === true],
    ['detectXSS("hello") is false', () => detectXSS('hello') === false],
    ['detectXSS("") is false', () => detectXSS('') === false],
    ['detectXSS("<a href=\\"javascript:alert(1)\\">")', () => detectXSS('<a href="javascript:alert(1)">') === true],
    ['detectXSS("<a href=\\"https://example.com/\\">x</a>") is false', () => detectXSS('<a href="https://example.com/">x</a>') === false],
    ['NUL bytes inside tag names are ignored: "<scr\\0ipt>"', () => detectXSS('<scr\0ipt>') === true],
  ];
  let sanePass = 0;
  for (const [name, fn] of sanity) {
    let ok = false;
    try {
      ok = fn();
    } catch (e) {
      console.log(`sanity check threw: ${name}: ${e.stack}`);
    }
    if (ok) sanePass += 1;
    else console.log(`FAIL sanity: ${name}`);
  }
  report('sanity checks', sanePass, sanity.length);

  console.log('');
  for (const r of results) {
    const status = r.pass === r.total ? 'PASS' : 'FAIL';
    console.log(`${status}  ${r.name}: ${r.pass}/${r.total} ${r.extra}`.trimEnd());
  }
  process.exitCode = failed ? 1 : 0;
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
