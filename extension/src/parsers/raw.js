/**
 * Parser for raw HTTP request text:
 *
 *     POST /path?x=1 HTTP/1.1
 *     Host: example.com
 *     Content-Type: application/json
 *
 *     {"a":1}
 *
 * - CRLF or LF line endings; the body is kept byte-exact (line endings included).
 * - The request target may be origin-form (/path, uses Host), absolute-form
 *   (http://host/path) or "*". Without a scheme, https is assumed (http for port 80).
 * - HTTP/2 style dumps without a request line, starting with `:method: GET`,
 *   `:path: /x`, `:authority: host`, `:scheme: https` pseudo-header lines, are supported.
 * - Obsolete header line folding (continuation lines starting with whitespace) is unfolded.
 * - Several requests can be pasted at once, separated by a line containing only `###` or
 *   `---` (as in .http files).
 * - When a Content-Length header is present the body is cut to that many bytes; otherwise
 *   trailing newlines after the body are removed (they usually come from copy/paste).
 *
 * @module parsers/raw
 */

import { normalizeRequest } from './normalize.js';
import { getHeader, mapHttpVersion, splitUrl } from './util.js';

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

const REQUEST_LINE = /^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)[ \t]+(\S+)(?:[ \t]+(HTTP\/\d(?:\.\d)?))?[ \t]*$/i;

/** True if the line looks like an HTTP request line or an HTTP/2 pseudo-header line. */
export function isRequestStartLine(line) {
  const t = line.trim();
  if (/^:(method|path|authority|scheme):/i.test(t)) return true;
  const m = REQUEST_LINE.exec(t);
  return !!m && /^[A-Z]+$/.test(m[1]) && (!!m[3] || /^(\/|\*|https?:\/\/)/i.test(m[2]));
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Split pasted text into separate raw requests.
 * @param {string} text
 * @returns {string[]}
 */
function splitBlocks(text) {
  return text.split(/^[ \t]*(?:###|---)[^\S\r\n]*(?:\r?\n|$)/m).filter((b) => b.trim());
}

/**
 * @param {string} block
 * @param {ParseOptions} options
 * @returns {ParsedRequest}
 */
function parseBlock(block, options) {
  /** @type {string[]} */
  const notes = [];
  const text = block.replace(/^(?:[ \t]*\r?\n)+/, '');
  const sep = /\r?\n\r?\n/.exec(text);
  const head = sep ? text.slice(0, sep.index) : text.replace(/\s+$/, '');
  let body = sep ? text.slice(sep.index + sep[0].length) : null;
  const lines = head.split(/\r?\n/);

  let method;
  let target;
  let version;
  if (!lines[0].startsWith(':')) {
    const m = REQUEST_LINE.exec(lines[0].trim());
    if (!m) throw new Error(`Invalid request line "${lines[0].slice(0, 80)}"`);
    method = m[1];
    target = m[2];
    version = m[3];
    lines.shift();
  }

  /** @type {Header[]} */
  const headers = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ' ' + line.trim();
      continue;
    }
    if (!line.trim()) continue;
    const hm = /^(:?[^:\s][^:]*):(.*)$/.exec(line);
    if (!hm) {
      notes.push(`Ignored malformed header line "${line.slice(0, 80)}".`);
      continue;
    }
    headers.push({ name: hm[1].trim(), value: hm[2].trim() });
  }

  const pseudo = (n) => headers.find((h) => h.name.toLowerCase() === ':' + n)?.value;
  if (method === undefined) {
    method = pseudo('method') || 'GET';
    target = pseudo('path') || '/';
    if (!pseudo('method')) notes.push('No :method pseudo-header; assumed GET.');
  }
  const httpVersion = version ? mapHttpVersion(version) ?? undefined : headers.some((h) => h.name.startsWith(':')) ? 'HTTP/2.0' : undefined;
  if (!version && !headers.some((h) => h.name.startsWith(':'))) notes.push('Request line has no HTTP version; assumed HTTP/1.1.');

  // Build the absolute URL.
  let url;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) url = target;
  else {
    const authority = getHeader(headers, 'host') ?? pseudo('authority');
    if (!authority) throw new Error('Request target is not an absolute URL and there is no Host header.');
    let scheme = pseudo('scheme');
    if (!scheme) {
      if (/:80$/.test(authority)) {
        scheme = 'http';
        notes.push('Scheme not specified; assumed http because the Host header uses port 80.');
      } else {
        scheme = 'https';
        notes.push('Scheme not specified; assumed https.');
      }
    }
    if (target === '*') {
      notes.push('Asterisk-form request target (*); URL uses path "/".');
      url = `${scheme}://${authority}/`;
    } else if (method.toUpperCase() === 'CONNECT' && !target.startsWith('/')) {
      notes.push('CONNECT authority-form request target; URL uses path "/".');
      url = `${scheme}://${target}/`;
    } else url = `${scheme}://${authority}${target.startsWith('/') ? '' : '/'}${target}`;
  }
  if (!splitUrl(url)) throw new Error(`Invalid URL "${url}"`);

  // Body
  if (body !== null) {
    const cl = getHeader(headers, 'content-length');
    const te = getHeader(headers, 'transfer-encoding');
    if (cl !== undefined && /^\d+$/.test(cl.trim())) {
      const want = Number(cl.trim());
      const bytes = encoder.encode(body);
      if (bytes.length > want) {
        const extra = decoder.decode(bytes.subarray(want));
        body = decoder.decode(bytes.subarray(0, want));
        if (extra.trim()) notes.push(`Body is longer than Content-Length (${want}); ${bytes.length - want} extra bytes ignored.`);
      } else if (bytes.length < want) {
        notes.push(`Body (${bytes.length} bytes) is shorter than Content-Length (${want}).`);
      }
    } else {
      // A single trailing newline is almost always an artifact of copy/paste; drop it silently.
      const trimmed = body.replace(/(\r?\n)+$/, '');
      const removedLines = (body.slice(trimmed.length).match(/\n/g) || []).length;
      if (removedLines > 1 && trimmed) notes.push(`${removedLines} trailing newlines after the body were removed (add a Content-Length header to keep them).`);
      body = trimmed;
    }
    if (te && /chunked/i.test(te)) notes.push('Transfer-Encoding: chunked body kept as-is (not de-chunked).');
    if (body === '') body = null;
  }

  return normalizeRequest({
    method,
    url,
    httpVersion,
    headers,
    body,
    bodyEncoding: 'text',
    source: 'raw',
    notes,
  }, options);
}

/**
 * Parse one or more raw HTTP requests (separated by `###` or `---` lines).
 * @param {string} text
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], errors: string[]}}
 */
export function parseRaw(text, options = {}) {
  /** @type {ParsedRequest[]} */
  const requests = [];
  /** @type {string[]} */
  const errors = [];
  const blocks = splitBlocks(text.replace(/^﻿/, ''));
  blocks.forEach((block, i) => {
    try {
      requests.push(parseBlock(block, options));
    } catch (e) {
      errors.push(`Raw request #${i + 1}: ${e.message}`);
    }
  });
  if (!blocks.length) errors.push('Raw HTTP: empty input.');
  return { requests, errors };
}
