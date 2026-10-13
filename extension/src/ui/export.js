// Request export helpers (Copy as cURL / raw HTTP). Pure, unit-tested.

import { splitUrl, decodeBody } from './format.js';

/** Quote a string for POSIX shells (single quotes; ' -> '\''). */
export function shellQuote(s) {
  const str = String(s ?? '');
  // ANSI-C quoting when control characters (other than tab/newline) are present.
  if (/[\x00-\x08\x0b-\x1f\x7f]/.test(str)) {
    return "$'" + str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/[\x00-\x1f\x7f]/g, (c) => {
      const map = { '\n': '\\n', '\r': '\\r', '\t': '\\t' };
      return map[c] || '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0');
    }) + "'";
  }
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

const SKIP_CURL_HEADERS = new Set(['content-length', 'host']);

/**
 * Build a bash cURL command reproducing the request.
 * @param {{method: string, url: string, httpVersion?: string, headers?: {name: string, value: string}[], body?: string|null, bodyEncoding?: string}} req
 */
export function toCurl(req) {
  const lines = [`curl ${shellQuote(req.url)}`];
  const method = String(req.method || 'GET').toUpperCase();
  const hasBody = req.body != null && req.body !== '';
  if (!(method === 'GET' && !hasBody) && !(method === 'POST' && hasBody)) lines.push(`-X ${shellQuote(method)}`);
  const host = splitUrl(req.url).host;
  for (const h of req.headers || []) {
    const n = String(h.name).toLowerCase();
    if (SKIP_CURL_HEADERS.has(n) && !(n === 'host' && h.value !== host)) continue;
    lines.push(`-H ${shellQuote(`${h.name}: ${h.value}`)}`);
  }
  let prefix = '';
  if (hasBody) {
    if (req.bodyEncoding === 'base64') {
      prefix = `printf %s ${shellQuote(req.body)} | base64 -d | `;
      lines.push('--data-binary @-');
    } else {
      lines.push(`--data-raw ${shellQuote(req.body)}`);
    }
  }
  if (/^HTTP\/2/i.test(req.httpVersion || '')) lines.push('--http2');
  else if (/^HTTP\/1\.0/i.test(req.httpVersion || '')) lines.push('--http1.0');
  return prefix + lines.join(' \\\n  ');
}

/**
 * Raw HTTP/1.1-style text of the request (as the WAF sees it).
 * HTTP/2 requests are rendered with their protocol name for readability.
 */
export function toRawHttp(req) {
  const { pathAndQuery } = splitUrl(req.url);
  const lines = [`${String(req.method || 'GET').toUpperCase()} ${pathAndQuery} ${req.httpVersion || 'HTTP/1.1'}`];
  for (const h of req.headers || []) lines.push(`${h.name}: ${h.value}`);
  let text = lines.join('\r\n') + '\r\n\r\n';
  if (req.body != null && req.body !== '') text += decodeBody(req.body, req.bodyEncoding);
  return text;
}
