/**
 * Parser for Chrome DevTools "Copy as fetch", "Copy as fetch (Node.js)" and the
 * "Copy all as ..." variants: one or more `fetch(url, options)` calls.
 *
 * The arguments are read with a small JavaScript literal parser (no eval): strings in
 * single/double/backtick quotes (no interpolation), numbers, true/false/null/undefined,
 * object and array literals (bare or quoted keys, trailing commas, comments), plus
 * `JSON.stringify(literal)`, `new URLSearchParams(...)` and `new Headers(...)`.
 *
 * @module parsers/fetch
 */

import { normalizeRequest } from './normalize.js';
import { findHeaderIndex, hasHeader, formUrlEncode, ellipsis } from './util.js';

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

class JsSyntaxError extends Error {}

/** Ordered object literal (keeps duplicate keys and order). */
class JsObject {
  constructor() {
    /** @type {Array<[string, any]>} */
    this.entries = [];
  }
  has(key) {
    return this.entries.some(([k]) => k === key);
  }
  get(key) {
    for (let i = this.entries.length - 1; i >= 0; i--) if (this.entries[i][0] === key) return this.entries[i][1];
    return undefined;
  }
}

/** Value of `new URLSearchParams(...)`. */
class JsSearchParams {
  /** @param {string} text */
  constructor(text) {
    this.text = text;
  }
}

/**
 * Convert a parsed literal to a plain JS value (for JSON.stringify).
 * @param {any} v
 */
function toPlain(v) {
  if (v instanceof JsObject) {
    const o = {};
    for (const [k, x] of v.entries) o[k] = toPlain(x);
    return o;
  }
  if (Array.isArray(v)) return v.map(toPlain);
  if (v instanceof JsSearchParams) return {};
  return v;
}

class JsLiteralParser {
  /**
   * @param {string} src
   * @param {number} pos
   */
  constructor(src, pos) {
    this.src = src;
    this.pos = pos;
  }

  peek(o = 0) {
    return this.src[this.pos + o];
  }

  skipWs() {
    for (;;) {
      const c = this.peek();
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === ' ' || c === '﻿') this.pos++;
      else if (c === '/' && this.peek(1) === '/') {
        while (this.pos < this.src.length && this.peek() !== '\n') this.pos++;
      } else if (c === '/' && this.peek(1) === '*') {
        const end = this.src.indexOf('*/', this.pos + 2);
        this.pos = end < 0 ? this.src.length : end + 2;
      } else return;
    }
  }

  expect(ch) {
    this.skipWs();
    if (this.peek() !== ch) {
      throw new JsSyntaxError(`Expected '${ch}' but found ${this.pos >= this.src.length ? 'end of input' : `'${this.peek()}'`}`);
    }
    this.pos++;
  }

  readIdent() {
    const m = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(this.src.slice(this.pos, this.pos + 100));
    if (!m) return '';
    this.pos += m[0].length;
    return m[0];
  }

  /** @returns {any} */
  parseValue() {
    this.skipWs();
    const c = this.peek();
    if (c === '"' || c === "'") return this.parseString(c);
    if (c === '`') return this.parseTemplate();
    if (c === '{') return this.parseObject();
    if (c === '[') return this.parseArray();
    if (c === '-' || c === '+' || c === '.' || (c >= '0' && c <= '9')) return this.parseNumber();
    const start = this.pos;
    const id = this.readIdent();
    switch (id) {
      case 'true': return true;
      case 'false': return false;
      case 'null': return null;
      case 'undefined': return undefined;
      case 'new': return this.parseNew();
      case 'JSON': {
        this.expect('.');
        this.skipWs();
        const fn = this.readIdent();
        if (fn !== 'stringify') throw new JsSyntaxError(`JSON.${fn}() is not supported`);
        const args = this.parseArgs();
        const json = JSON.stringify(toPlain(args[0]), null, args[2] === undefined ? undefined : args[2]);
        return json;
      }
      case 'String': {
        const args = this.parseArgs();
        return String(toPlain(args[0]));
      }
      default:
        break;
    }
    this.pos = start;
    throw new JsSyntaxError(`Unsupported expression "${ellipsis(this.src.slice(start, start + 30), 30)}" (only literals are supported)`);
  }

  parseArgs() {
    this.expect('(');
    const args = [];
    this.skipWs();
    if (this.peek() === ')') {
      this.pos++;
      return args;
    }
    for (;;) {
      args.push(this.parseValue());
      this.skipWs();
      if (this.peek() === ',') {
        this.pos++;
        this.skipWs();
        if (this.peek() === ')') {
          this.pos++;
          return args;
        }
        continue;
      }
      this.expect(')');
      return args;
    }
  }

  parseNew() {
    this.skipWs();
    const ctor = this.readIdent();
    const args = this.peek() === '(' || (this.skipWs(), this.peek() === '(') ? this.parseArgs() : [];
    switch (ctor) {
      case 'URLSearchParams': {
        const a = args[0];
        if (a === undefined || a === null) return new JsSearchParams('');
        if (typeof a === 'string') return new JsSearchParams(a.replace(/^\?/, ''));
        const pairs = a instanceof JsObject ? a.entries : Array.isArray(a) ? a : [];
        return new JsSearchParams(pairs.map(([k, v]) => `${formUrlEncode(String(k))}=${formUrlEncode(String(toPlain(v)))}`).join('&'));
      }
      case 'Headers':
        return args[0] ?? new JsObject();
      case 'URL':
        return String(args[0]);
      default:
        throw new JsSyntaxError(`new ${ctor}() is not supported`);
    }
  }

  parseNumber() {
    const m = /^[-+]?(0x[0-9a-fA-F]+|(\d+\.?\d*|\.\d+)(e[-+]?\d+)?)/i.exec(this.src.slice(this.pos, this.pos + 50));
    if (!m) throw new JsSyntaxError('Invalid number');
    this.pos += m[0].length;
    return Number(m[0]);
  }

  /** @param {string} q */
  parseString(q) {
    this.pos++;
    let out = '';
    for (;;) {
      if (this.pos >= this.src.length) throw new JsSyntaxError('Unterminated string literal');
      const c = this.peek();
      if (c === q) {
        this.pos++;
        return out;
      }
      if (c === '\\') {
        out += this.readEscape();
        continue;
      }
      if (c === '\n') throw new JsSyntaxError('Unterminated string literal');
      out += c;
      this.pos++;
    }
  }

  parseTemplate() {
    this.pos++;
    let out = '';
    for (;;) {
      if (this.pos >= this.src.length) throw new JsSyntaxError('Unterminated template literal');
      const c = this.peek();
      if (c === '`') {
        this.pos++;
        return out;
      }
      if (c === '$' && this.peek(1) === '{') throw new JsSyntaxError('Template literal interpolation ${...} is not supported');
      if (c === '\\') {
        out += this.readEscape();
        continue;
      }
      out += c;
      this.pos++;
    }
  }

  /** Escape sequence at pos (which is a backslash). */
  readEscape() {
    const n = this.peek(1);
    this.pos += 2;
    switch (n) {
      case 'n': return '\n';
      case 'r': return '\r';
      case 't': return '\t';
      case 'b': return '\b';
      case 'f': return '\f';
      case 'v': return '\v';
      case '0':
        if (!/[0-9]/.test(this.peek() ?? '')) return '\0';
        break;
      case '\r':
        if (this.peek() === '\n') this.pos++;
        return '';
      case '\n': case ' ': case ' ':
        return '';
      case 'x': {
        const hex = this.src.slice(this.pos, this.pos + 2);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new JsSyntaxError('Invalid \\x escape');
        this.pos += 2;
        return String.fromCharCode(parseInt(hex, 16));
      }
      case 'u': {
        if (this.peek() === '{') {
          const end = this.src.indexOf('}', this.pos);
          const hex = this.src.slice(this.pos + 1, end);
          if (end < 0 || !/^[0-9a-fA-F]{1,6}$/.test(hex)) throw new JsSyntaxError('Invalid unicode escape');
          this.pos = end + 1;
          return String.fromCodePoint(parseInt(hex, 16));
        }
        const hex = this.src.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JsSyntaxError('Invalid unicode escape');
        this.pos += 4;
        return String.fromCharCode(parseInt(hex, 16));
      }
      default:
        break;
    }
    if (n === undefined) throw new JsSyntaxError('Unterminated string literal');
    return n;
  }

  parseObject() {
    this.pos++;
    const obj = new JsObject();
    for (;;) {
      this.skipWs();
      const c = this.peek();
      if (c === '}') {
        this.pos++;
        return obj;
      }
      let key;
      if (c === '"' || c === "'") key = this.parseString(c);
      else if (c === '`') key = this.parseTemplate();
      else if (c >= '0' && c <= '9') key = String(this.parseNumber());
      else if (c === '[') {
        this.pos++;
        key = String(this.parseValue());
        this.expect(']');
      } else {
        key = this.readIdent();
        if (!key) throw new JsSyntaxError(`Unexpected '${c ?? 'end of input'}' in object literal`);
      }
      this.skipWs();
      if (this.peek() === ',' || this.peek() === '}') throw new JsSyntaxError(`Shorthand property "${key}" is not supported (variables are not available)`);
      this.expect(':');
      obj.entries.push([key, this.parseValue()]);
      this.skipWs();
      if (this.peek() === ',') this.pos++;
      else if (this.peek() !== '}') throw new JsSyntaxError(`Expected ',' or '}' in object literal but found '${this.peek() ?? 'end of input'}'`);
    }
  }

  parseArray() {
    this.pos++;
    const arr = [];
    for (;;) {
      this.skipWs();
      if (this.peek() === ']') {
        this.pos++;
        return arr;
      }
      arr.push(this.parseValue());
      this.skipWs();
      if (this.peek() === ',') this.pos++;
      else if (this.peek() !== ']') throw new JsSyntaxError(`Expected ',' or ']' in array literal but found '${this.peek() ?? 'end of input'}'`);
    }
  }
}

/**
 * Compute the Referer header a browser sends for `referrer` under `policy`
 * (https://w3c.github.io/webappsec-referrer-policy/). Returns null when none is sent.
 *
 * @param {string} referrer
 * @param {string} target
 * @param {string} [policy]  Defaults to Chrome's strict-origin-when-cross-origin.
 * @returns {string|null}
 */
export function computeReferer(referrer, target, policy) {
  let ref;
  let tgt;
  try {
    ref = new URL(referrer);
    tgt = new URL(target);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(ref.protocol)) return null;
  const full = referrer.replace(/#.*$/, '');
  const origin = ref.origin + '/';
  const sameOrigin = ref.origin === tgt.origin;
  const downgrade = ref.protocol === 'https:' && tgt.protocol === 'http:';
  switch ((policy || '').toLowerCase()) {
    case 'no-referrer': return null;
    case 'unsafe-url': return full;
    case 'origin': return origin;
    case 'same-origin': return sameOrigin ? full : null;
    case 'strict-origin': return downgrade ? null : origin;
    case 'origin-when-cross-origin': return sameOrigin ? full : origin;
    case 'no-referrer-when-downgrade': return downgrade ? null : full;
    default: return sameOrigin ? full : downgrade ? null : origin;
  }
}

/**
 * Build a request from parsed fetch() arguments.
 * @param {any} urlArg
 * @param {any} opts
 * @param {ParseOptions} options
 * @returns {ParsedRequest}
 */
function fetchCallToRequest(urlArg, opts, options) {
  if (typeof urlArg !== 'string') throw new Error('The first fetch() argument must be a string URL.');
  const o = opts instanceof JsObject ? opts : new JsObject();
  /** @type {string[]} */
  const notes = [];
  const nodeVariant = !o.has('mode') && !o.has('credentials');

  /** @type {Header[]} */
  let headers = [];
  const h = o.get('headers');
  if (h instanceof JsObject) headers = h.entries.map(([k, v]) => ({ name: k, value: String(toPlain(v) ?? '') }));
  else if (Array.isArray(h)) headers = h.filter(Array.isArray).map(([k, v]) => ({ name: String(k), value: String(v ?? '') }));
  else if (h !== undefined && h !== null) notes.push('Unsupported "headers" value; ignored.');

  const rp = findHeaderIndex(headers, 'referrer-policy');
  if (rp >= 0) {
    notes.push(`Dropped the "Referrer-Policy: ${headers[rp].value}" entry Chrome adds to Node.js fetch copies (it is not a request header the browser sent).`);
    headers.splice(rp, 1);
  }

  const method = String(o.get('method') ?? 'GET');

  /** @type {string|null} */
  let body = null;
  let contentType;
  const b = o.get('body');
  if (typeof b === 'string') body = b;
  else if (b instanceof JsSearchParams) {
    body = b.text;
    if (!hasHeader(headers, 'content-type')) contentType = 'application/x-www-form-urlencoded;charset=UTF-8';
  } else if (b instanceof JsObject || Array.isArray(b)) {
    body = JSON.stringify(toPlain(b));
    notes.push('fetch body was an object literal; serialized as JSON (a real fetch would send "[object Object]").');
  } else if (typeof b === 'number' || typeof b === 'boolean') body = String(b);
  if (body !== null && !contentType && !hasHeader(headers, 'content-type')) {
    contentType = 'text/plain;charset=UTF-8';
    notes.push('No content-type header for a string body; fetch sends text/plain;charset=UTF-8.');
  }

  const referrer = o.get('referrer');
  const policy = o.get('referrerPolicy');
  if (typeof referrer === 'string' && referrer && referrer !== 'about:client' && !hasHeader(headers, 'referer')) {
    const value = computeReferer(referrer, urlArg, typeof policy === 'string' ? policy : undefined);
    if (value) {
      headers.push({ name: 'Referer', value });
      notes.push(`Referer header derived from the fetch "referrer" option (policy ${policy || 'strict-origin-when-cross-origin'}).`);
    } else notes.push(`No Referer sent for referrer ${referrer} under policy ${policy || 'strict-origin-when-cross-origin'}.`);
  }

  if (!nodeVariant) {
    notes.push("Cookies are not included in 'Copy as fetch' output; use 'Copy as cURL' or PowerShell to include them.");
    notes.push("Browser-controlled headers (User-Agent, Accept-Encoding, Origin, Cookie, ...) are omitted by 'Copy as fetch' and are missing from this request.");
  } else if (!hasHeader(headers, 'user-agent')) {
    notes.push("'Copy as fetch (Node.js)' omits browser-controlled headers such as User-Agent, Accept-Encoding and Origin.");
  }

  return normalizeRequest({
    method,
    url: urlArg,
    headers,
    body,
    bodyEncoding: 'text',
    source: 'fetch',
    notes,
    contentType,
  }, options);
}

/**
 * Parse one or more `fetch(...)` calls.
 * @param {string} text
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], errors: string[]}}
 */
export function parseFetch(text, options = {}) {
  /** @type {ParsedRequest[]} */
  const requests = [];
  /** @type {string[]} */
  const errors = [];
  const re = /(?<![A-Za-z0-9_$.])fetch\s*\(/g;
  let m;
  let n = 0;
  while ((m = re.exec(text))) {
    n++;
    const p = new JsLiteralParser(text, m.index + m[0].length);
    try {
      const url = p.parseValue();
      p.skipWs();
      let opts;
      if (p.peek() === ',') {
        p.pos++;
        p.skipWs();
        if (p.peek() !== ')') opts = p.parseValue();
        p.skipWs();
        if (p.peek() === ',') p.pos++;
      }
      p.expect(')');
      re.lastIndex = p.pos;
      requests.push(fetchCallToRequest(url, opts, options));
    } catch (e) {
      errors.push(`fetch call #${n}: ${e.message}`);
    }
  }
  if (!n) errors.push('fetch: no fetch(...) call found.');
  return { requests, errors };
}
