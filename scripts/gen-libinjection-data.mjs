#!/usr/bin/env node
// Generates extension/src/engine/libinjection-data.js from the vendored upstream
// libinjection sources (vendor/libinjection/src):
//
//   - libinjection_sqli_data.h : sql_keywords[] (keywords, operators, SQL types and
//                                the 'F' fingerprint table) and char_parse_map[]
//   - libinjection_xss.c       : BLACKATTREVENT[], BLACKATTR[], BLACKTAG[]
//
// Usage: node scripts/gen-libinjection-data.mjs [path/to/libinjection/src]
//
// The C keyword lookup is a binary search with an ASCII-only case-insensitive
// compare (`cstrcasecmp`, the table entry must be upper case). This script verifies
// the assumptions that make a plain Map lookup on the ASCII-upper-cased word
// equivalent: the table is strictly sorted (byte order), entries contain no
// lower-case ASCII letters, and no entry is empty.

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.resolve(process.argv[2] || path.join(ROOT, 'vendor', 'libinjection', 'src'));
const OUT = path.join(ROOT, 'extension', 'src', 'engine', 'libinjection-data.js');

/** Decode a C string literal body (without quotes) into a byte string. */
function cUnescape(lit) {
  let out = '';
  for (let i = 0; i < lit.length; i++) {
    const c = lit[i];
    if (c !== '\\') { out += c; continue; }
    const n = lit[++i];
    if (n >= '0' && n <= '7') {
      let oct = n;
      while (oct.length < 3 && lit[i + 1] >= '0' && lit[i + 1] <= '7') oct += lit[++i];
      out += String.fromCharCode(parseInt(oct, 8) & 0xff);
    } else if (n === 'x') {
      let hex = '';
      while (/[0-9a-fA-F]/.test(lit[i + 1] || '')) hex += lit[++i];
      out += String.fromCharCode(parseInt(hex, 16) & 0xff);
    } else {
      const map = { n: '\n', t: '\t', r: '\r', v: '\v', f: '\f', a: '\x07', b: '\b', '\\': '\\', "'": "'", '"': '"', '?': '?' };
      if (!(n in map)) throw new Error(`unknown escape \\${n}`);
      out += map[n];
    }
  }
  return out;
}

/** Decode a C char literal body like `k`, `\\'`, `&`. */
function cChar(lit) {
  const s = cUnescape(lit);
  if (s.length !== 1) throw new Error(`bad char literal '${lit}'`);
  return s;
}

function stripComments(src) {
  // Good enough for these files: no comment markers inside the string literals we parse.
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}

function extractArrayBody(src, name) {
  const re = new RegExp(`${name}\\s*\\[\\s*\\]\\s*=\\s*\\{`);
  const m = re.exec(src);
  if (!m) throw new Error(`array ${name} not found`);
  let depth = 1;
  let i = m.index + m[0].length;
  const start = i;
  let inStr = false;
  let inChr = false;
  for (; i < src.length; i++) {
    const c = src[i];
    if (inStr || inChr) {
      if (c === '\\') { i++; continue; }
      if (inStr && c === '"') inStr = false;
      else if (inChr && c === "'") inChr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "'") inChr = true;
    else if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return src.slice(start, i); }
  }
  throw new Error(`unterminated array ${name}`);
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d) return d;
  }
  return a.length - b.length;
}

async function main() {
  const dataH = stripComments(await readFile(path.join(SRC, 'libinjection_sqli_data.h'), 'latin1'));
  const xssC = stripComments(await readFile(path.join(SRC, 'libinjection_xss.c'), 'latin1'));
  const sqliC = await readFile(path.join(SRC, 'libinjection_sqli.c'), 'latin1');
  const version = (/#define\s+LIBINJECTION_VERSION\s+"([^"]+)"/.exec(sqliC) || [])[1] || 'unknown';

  // ---- char_parse_map ------------------------------------------------------
  const mapBody = extractArrayBody(dataH, 'char_parse_map');
  const parsers = [...mapBody.matchAll(/&?\s*(parse_[a-z0-9_]+)/g)].map((m) => m[1]);
  if (parsers.length !== 256) throw new Error(`char_parse_map has ${parsers.length} entries, expected 256`);
  const parserNames = [...new Set(parsers)].sort();
  if (parserNames.length > 26) throw new Error('too many parser functions for 1-letter encoding');
  const parserCode = (name) => String.fromCharCode(65 + parserNames.indexOf(name));
  const charMapEncoded = parsers.map(parserCode).join('');

  // ---- sql_keywords --------------------------------------------------------
  const kwBody = extractArrayBody(dataH, 'sql_keywords');
  const kwRe = /\{\s*"((?:[^"\\]|\\.)*)"\s*,\s*'((?:[^'\\]|\\.)+)'\s*\}/g;
  const keywords = [];
  for (const m of kwBody.matchAll(kwRe)) keywords.push([cUnescape(m[1]), cChar(m[2])]);
  const declaredSz = Number((/sql_keywords_sz\s*=\s*(\d+)/.exec(dataH) || [])[1]);
  if (keywords.length !== declaredSz) {
    throw new Error(`parsed ${keywords.length} keywords but sql_keywords_sz = ${declaredSz}`);
  }
  for (let i = 0; i < keywords.length; i++) {
    const [w] = keywords[i];
    if (w.length === 0) throw new Error('empty keyword');
    if (/[a-z]/.test(w)) throw new Error(`keyword with lower case letter (unreachable in C): ${w}`);
    if (/[\x00\x80-\xff]/.test(w)) throw new Error(`keyword with NUL / high byte: ${JSON.stringify(w)}`);
    if (i > 0 && cmpBytes(keywords[i - 1][0], w) >= 0) {
      throw new Error(`sql_keywords not strictly sorted at ${JSON.stringify(keywords[i - 1][0])} / ${JSON.stringify(w)}`);
    }
  }
  // Group by type; join each group with a separator that occurs in none of its words.
  const groups = new Map();
  for (const [w, t] of keywords) {
    if (!groups.has(t)) groups.set(t, []);
    groups.get(t).push(w);
  }
  const SEPS = [' ', '|', '\n'];
  const kwEntries = [];
  for (const t of [...groups.keys()].sort()) {
    let words = groups.get(t);
    let prefix = '';
    // All fingerprints start with the v1 marker '0': store them without it.
    if (t === 'F' && words.every((w) => w[0] === '0')) {
      prefix = '0';
      words = words.map((w) => w.slice(1));
    }
    const sep = SEPS.find((s) => words.every((w) => !w.includes(s)));
    if (sep === undefined) throw new Error(`no separator usable for type ${t}`);
    kwEntries.push({ type: t, prefix, sep, words: words.join(sep) });
  }

  // ---- XSS tables ----------------------------------------------------------
  const evBody = extractArrayBody(xssC, 'BLACKATTREVENT');
  const events = [];
  for (const m of evBody.matchAll(/\{\s*(?:"((?:[^"\\]|\\.)*)"|NULL)\s*,\s*(TYPE_[A-Z_]+)\s*\}/g)) {
    if (m[1] === undefined) continue; // {NULL, TYPE_NONE} terminator
    if (m[2] !== 'TYPE_BLACK') throw new Error(`unexpected event type ${m[2]}`);
    events.push(cUnescape(m[1]));
  }
  const attrBody = extractArrayBody(xssC, 'BLACKATTR');
  const attrs = [];
  for (const m of attrBody.matchAll(/\{\s*(?:"((?:[^"\\]|\\.)*)"|NULL)\s*,\s*(TYPE_[A-Z_]+)\s*\}/g)) {
    if (m[1] === undefined) continue;
    attrs.push([cUnescape(m[1]), m[2]]);
  }
  const tagBody = extractArrayBody(xssC, 'BLACKTAG');
  const tags = [...tagBody.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => cUnescape(m[1]));
  for (const w of [...events, ...attrs.map((a) => a[0]), ...tags]) {
    if (/[a-z\x00]/.test(w)) throw new Error(`XSS table entry not upper case: ${w}`);
  }

  // ---- emit ------------------------------------------------------------------
  const lines = [];
  lines.push('// GENERATED FILE - DO NOT EDIT.');
  lines.push('// Generated by scripts/gen-libinjection-data.mjs from libinjection');
  lines.push(`// ${version} (src/libinjection_sqli_data.h, src/libinjection_xss.c).`);
  lines.push('// libinjection: Copyright (c) 2012-2016 Nick Galbreath, (c) 2017-2024 libinjection contributors,');
  lines.push('// BSD-3-Clause, see LICENSE.libinjection.');
  lines.push('');
  lines.push(`export const LIBINJECTION_VERSION = ${JSON.stringify(version)};`);
  lines.push('');
  lines.push('/** Parser function names used by CHAR_PARSE_MAP (index = letter - "A"). */');
  lines.push(`export const CHAR_PARSERS = ${JSON.stringify(parserNames)};`);
  lines.push('');
  lines.push('/** char_parse_map[256]: one letter per byte value, indexing CHAR_PARSERS. */');
  lines.push(`export const CHAR_PARSE_MAP =\n  ${JSON.stringify(charMapEncoded.slice(0, 128))} +\n  ${JSON.stringify(charMapEncoded.slice(128))};`);
  lines.push('');
  lines.push('/**');
  lines.push(' * sql_keywords[] grouped by token type: [type, prefix, separator, words].');
  lines.push(' * Each word is `prefix + item`; all words are upper case ASCII.');
  lines.push(` * ${keywords.length} entries in total.`);
  lines.push(' */');
  lines.push('export const SQL_KEYWORDS = [');
  for (const e of kwEntries) {
    lines.push(`  [${JSON.stringify(e.type)}, ${JSON.stringify(e.prefix)}, ${JSON.stringify(e.sep)},`);
    lines.push(`    ${JSON.stringify(e.words)}],`);
  }
  lines.push('];');
  lines.push('');
  lines.push('/** BLACKATTREVENT[]: event handler names (without "ON"), all TYPE_BLACK, in C order. */');
  lines.push(`export const XSS_BLACK_ATTR_EVENTS = ${JSON.stringify(events.join(' '))}.split(' ');`);
  lines.push('');
  lines.push('/** BLACKATTR[]: [name, attribute type], in C order. */');
  lines.push(`export const XSS_BLACK_ATTRS = ${JSON.stringify(attrs)};`);
  lines.push('');
  lines.push('/** BLACKTAG[], in C order. */');
  lines.push(`export const XSS_BLACK_TAGS = ${JSON.stringify(tags)};`);
  lines.push('');
  await writeFile(OUT, lines.join('\n'), 'latin1');
  console.log(`wrote ${path.relative(ROOT, OUT)}: ${keywords.length} keywords (${kwEntries.length} types), ` +
    `${events.length} events, ${attrs.length} attrs, ${tags.length} tags, version ${version}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
