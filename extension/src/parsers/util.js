/**
 * Small helpers shared by the parsers (URL splitting, byte lengths, base64, encoders,
 * cookie matching, multipart building). Runs in browsers and Node without dependencies.
 *
 * @module parsers/util
 */

/** @typedef {import('./types.js').Header} Header */

/** Default ports per scheme; the Host header omits these. */
export const DEFAULT_PORTS = Object.freeze({ http: '80', https: '443', ws: '80', wss: '443' });

const encoder = new TextEncoder();

/**
 * UTF-8 byte length of a string.
 * @param {string} str
 * @returns {number}
 */
export function utf8ByteLength(str) {
  return encoder.encode(str).length;
}

/**
 * Number of bytes encoded by a base64 string (padding and whitespace aware).
 * @param {string} b64
 * @returns {number}
 */
export function base64DecodedLength(b64) {
  const clean = b64.replace(/[\s=]+$/g, '').replace(/\s+/g, '');
  return Math.floor((clean.length * 3) / 4);
}

/**
 * Byte length of a body in either encoding.
 * @param {string} body
 * @param {'text'|'base64'} encoding
 */
export function bodyByteLength(body, encoding) {
  return encoding === 'base64' ? base64DecodedLength(body) : utf8ByteLength(body);
}

/**
 * Base64-encode raw bytes.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)));
  }
  return btoa(bin);
}

/**
 * Base64 of the UTF-8 encoding of a string.
 * @param {string} str
 */
export function utf8ToBase64(str) {
  return bytesToBase64(encoder.encode(str));
}

/**
 * Base64 of the UTF-16LE encoding of a string (.NET `Encoding.Unicode`).
 * @param {string} str
 */
export function utf16leToBase64(str) {
  const bytes = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    bytes[i * 2] = code & 0xff;
    bytes[i * 2 + 1] = code >> 8;
  }
  return bytesToBase64(bytes);
}

/**
 * @typedef {Object} UrlParts
 * @property {string} scheme        Lowercase scheme without colon.
 * @property {string} userinfo      "user:pass" or ''.
 * @property {string} authority     host[:port] without userinfo, as written.
 * @property {string} host          Lowercase host (IPv6 keeps brackets).
 * @property {string} port          Port as written or ''.
 * @property {string} pathAndQuery  Raw path + query ("/" when empty), no fragment.
 * @property {string} path          Raw path.
 * @property {string|null} query    Raw query without "?" or null.
 * @property {string} fragment      "#..." or ''.
 */

const URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^#]*)(#[\s\S]*)?$/;

/**
 * Split an absolute URL into raw components without re-encoding anything.
 * @param {string} url
 * @returns {UrlParts|null} null when the string is not an absolute hierarchical URL.
 */
export function splitUrl(url) {
  const m = URL_RE.exec(url);
  if (!m) return null;
  let authority = m[2];
  let userinfo = '';
  const at = authority.lastIndexOf('@');
  if (at >= 0) {
    userinfo = authority.slice(0, at);
    authority = authority.slice(at + 1);
  }
  let host = authority;
  let port = '';
  const hp = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(authority);
  if (hp) {
    host = hp[1];
    port = hp[2] || '';
  }
  let pathAndQuery = m[3] || '';
  if (!pathAndQuery.startsWith('/')) pathAndQuery = '/' + pathAndQuery;
  const qi = pathAndQuery.indexOf('?');
  return {
    scheme: m[1].toLowerCase(),
    userinfo,
    authority,
    host: host.toLowerCase(),
    port,
    pathAndQuery,
    path: qi >= 0 ? pathAndQuery.slice(0, qi) : pathAndQuery,
    query: qi >= 0 ? pathAndQuery.slice(qi + 1) : null,
    fragment: m[4] || '',
  };
}

/**
 * Host header value for a URL: host plus port only when non-default.
 * @param {UrlParts} parts
 */
export function hostHeaderValue(parts) {
  return parts.port && parts.port !== DEFAULT_PORTS[parts.scheme] ? `${parts.host}:${parts.port}` : parts.host;
}

/**
 * Append a query string to a URL (before any fragment).
 * @param {string} url
 * @param {string} query  Already encoded query, without "?".
 */
export function appendQuery(url, query) {
  if (!query) return url;
  const hash = url.indexOf('#');
  const base = hash >= 0 ? url.slice(0, hash) : url;
  const frag = hash >= 0 ? url.slice(hash) : '';
  const sep = !base.includes('?') ? '?' : /[?&]$/.test(base) ? '' : '&';
  return base + sep + query + frag;
}

/**
 * Map the many ways of spelling an HTTP version to the model's canonical values.
 * @param {unknown} v
 * @returns {string|null} canonical version, or null when empty/unknown.
 */
export function mapHttpVersion(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim().toLowerCase().replace(/\s+/g, '');
  if (!s) return null;
  if (/^(http\/)?2(\.0)?$|^h2c?$|^http2$/.test(s)) return 'HTTP/2.0';
  if (/^(http\/)?3(\.0)?$|^h3(-\d+)?$|^http3$|^quic$/.test(s)) return 'HTTP/3.0';
  if (/^(http\/)?1\.1$|^http1\.1$/.test(s)) return 'HTTP/1.1';
  if (/^(http\/)?1(\.0)?$|^http1\.0$/.test(s)) return 'HTTP/1.0';
  return null;
}

/**
 * Index of the first header with the given name (case-insensitive), or -1.
 * @param {Header[]} headers
 * @param {string} name
 */
export function findHeaderIndex(headers, name) {
  const lower = name.toLowerCase();
  return headers.findIndex((h) => h.name.toLowerCase() === lower);
}

/**
 * Value of the first header with the given name, or undefined.
 * @param {Header[]} headers
 * @param {string} name
 */
export function getHeader(headers, name) {
  const i = findHeaderIndex(headers, name);
  return i >= 0 ? headers[i].value : undefined;
}

/**
 * @param {Header[]} headers
 * @param {string} name
 */
export function hasHeader(headers, name) {
  return findHeaderIndex(headers, name) >= 0;
}

function isIpAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || host.startsWith('[');
}

/**
 * Browser-style cookie domain match (RFC 6265 5.1.3); a leading dot is ignored.
 * @param {string} host     Request host (lowercase).
 * @param {string} domain   Cookie domain.
 */
export function domainMatches(host, domain) {
  if (!domain) return true;
  const h = host.toLowerCase();
  const d = domain.trim().toLowerCase().replace(/^\./, '');
  if (!d || h === d) return true;
  if (isIpAddress(h)) return false;
  return h.endsWith('.' + d);
}

/**
 * Cookie path match (RFC 6265 5.1.4).
 * @param {string} requestPath
 * @param {string} cookiePath
 */
export function pathMatches(requestPath, cookiePath) {
  if (!cookiePath || cookiePath === '/') return true;
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

function percentEncodeBytes(str, keep, spaceAsPlus) {
  let out = '';
  for (const ch of str) {
    if (keep.test(ch)) out += ch;
    else if (spaceAsPlus && ch === ' ') out += '+';
    else for (const b of encoder.encode(ch)) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/**
 * curl_easy_escape(): everything except RFC 3986 unreserved characters is %XX encoded.
 * @param {string} str
 */
export function curlEscape(str) {
  return percentEncodeBytes(str, /^[A-Za-z0-9\-._~]$/, false);
}

/**
 * application/x-www-form-urlencoded serializer as used by URLSearchParams and browsers.
 * @param {string} str
 */
export function formUrlEncode(str) {
  return percentEncodeBytes(str, /^[A-Za-z0-9*\-._]$/, true);
}

/**
 * Lowercase hex string of n random bytes (crypto when available).
 * @param {number} nBytes
 */
export function randomHex(nBytes) {
  const bytes = new Uint8Array(nBytes);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
  else for (let i = 0; i < nBytes; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * @typedef {Object} MultipartPart
 * @property {string} name
 * @property {string} value          Part content (text).
 * @property {string} [filename]
 * @property {string} [contentType]
 */

/**
 * Build a multipart/form-data body (CRLF line endings).
 * @param {MultipartPart[]} parts
 * @param {string} boundary   Boundary without the leading "--".
 * @returns {string}
 */
export function buildMultipartBody(parts, boundary) {
  const esc = (s) => String(s).replace(/"/g, '%22').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  let out = '';
  for (const p of parts) {
    out += `--${boundary}\r\n`;
    out += `Content-Disposition: form-data; name="${esc(p.name)}"`;
    if (p.filename !== undefined) out += `; filename="${esc(p.filename)}"`;
    out += '\r\n';
    if (p.contentType) out += `Content-Type: ${p.contentType}\r\n`;
    out += `\r\n${p.value}\r\n`;
  }
  out += `--${boundary}--\r\n`;
  return out;
}

const MIME_BY_EXT = {
  txt: 'text/plain', html: 'text/html', htm: 'text/html', css: 'text/css', csv: 'text/csv',
  js: 'application/javascript', json: 'application/json', xml: 'application/xml',
  pdf: 'application/pdf', zip: 'application/zip', gif: 'image/gif', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', svg: 'image/svg+xml', webp: 'image/webp',
};

/**
 * Guess a MIME type from a file name (like curl does for -F name=@file).
 * @param {string} filename
 */
export function guessMimeType(filename) {
  const ext = /\.([A-Za-z0-9]+)$/.exec(filename)?.[1]?.toLowerCase();
  return (ext && MIME_BY_EXT[ext]) || 'application/octet-stream';
}

/**
 * Shorten a string for use in notes/errors.
 * @param {string} s
 * @param {number} [max]
 */
export function ellipsis(s, max = 60) {
  const one = String(s).replace(/\s+/g, ' ').trim();
  return one.length > max ? one.slice(0, max - 1) + '…' : one;
}
