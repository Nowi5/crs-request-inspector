/**
 * Shared normalization applied by every parser: HTTP/2 pseudo-header handling, Host,
 * Cookie, User-Agent, Content-Type and Content-Length synthesis, version inference.
 *
 * @module parsers/normalize
 */

import {
  splitUrl, hostHeaderValue, mapHttpVersion, findHeaderIndex, hasHeader, bodyByteLength,
} from './util.js';

/** @typedef {import('./types.js').Header} Header */
/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').RequestDraft} RequestDraft */
/** @typedef {import('./util.js').UrlParts} UrlParts */

/** Names Chrome's "Copy as PowerShell" produces from HTTP/2 pseudo-headers (colon stripped). */
const COLONLESS_PSEUDO = ['authority', 'method', 'path', 'scheme'];

/** Methods for which browsers and PowerShell send `Content-Length: 0` when there is no body. */
const LENGTH_REQUIRED = new Set(['POST', 'PUT', 'PATCH']);

/**
 * Decide which headers are HTTP/2 pseudo-headers.
 *
 * Colon-prefixed names (`:authority`, ...) are always pseudo-headers. The colon-less names
 * emitted by Chrome's PowerShell export are only treated as such when at least two of
 * authority/method/path/scheme are present (one of them authority, scheme or path) and all
 * present values are consistent with the request URL and method.
 *
 * @param {Header[]} headers
 * @param {string} method
 * @param {UrlParts} parts
 * @returns {{pseudo: Map<string,string>, removeIdx: Set<number>, names: string[], inconsistent: string[]}}
 */
function detectPseudoHeaders(headers, method, parts) {
  /** @type {Map<string,string>} */
  const pseudo = new Map();
  const removeIdx = new Set();
  const names = [];

  headers.forEach((h, i) => {
    if (h.name.startsWith(':')) {
      const key = h.name.slice(1).toLowerCase();
      if (!pseudo.has(key)) pseudo.set(key, h.value);
      removeIdx.add(i);
      names.push(h.name);
    }
  });

  const candidates = [];
  headers.forEach((h, i) => {
    const lower = h.name.toLowerCase();
    if (COLONLESS_PSEUDO.includes(lower)) candidates.push({ i, key: lower, name: h.name, value: h.value });
  });
  const keys = new Set(candidates.map((c) => c.key));
  /** @type {string[]} */
  let inconsistent = [];
  if (keys.size >= 2 && (keys.has('authority') || keys.has('scheme') || keys.has('path'))) {
    const consistent = candidates.every((c) => isConsistentPseudo(c.key, c.value, method, parts));
    if (consistent) {
      for (const c of candidates) {
        if (!pseudo.has(c.key)) pseudo.set(c.key, c.value);
        removeIdx.add(c.i);
        names.push(c.name);
      }
    } else {
      inconsistent = candidates.map((c) => c.name);
    }
  }
  return { pseudo, removeIdx, names, inconsistent };
}

/**
 * @param {string} key
 * @param {string} value
 * @param {string} method
 * @param {UrlParts} parts
 */
function isConsistentPseudo(key, value, method, parts) {
  const v = value.trim();
  switch (key) {
    case 'authority': {
      const lv = v.toLowerCase();
      return lv === parts.authority.toLowerCase() || lv === hostHeaderValue(parts);
    }
    case 'method':
      return v.toUpperCase() === method;
    case 'scheme':
      return v.toLowerCase() === parts.scheme;
    case 'path': {
      if (v === parts.pathAndQuery) return true;
      try {
        return decodeURI(v) === decodeURI(parts.pathAndQuery);
      } catch {
        return false;
      }
    }
    default:
      return false;
  }
}

/**
 * Turn a parser draft into a {@link ParsedRequest}. Idempotent: normalizing an already
 * normalized request returns an equivalent request.
 *
 * Rules: uppercase method; HTTP/2 pseudo-headers removed (unless `keepPseudoHeaders`) and
 * used to infer HTTP/2.0; separate cookies/user agent/content type merged into headers;
 * Host added first when missing; Content-Length added for bodies (and `0` for body-less
 * POST/PUT/PATCH) unless Content-Length or Transfer-Encoding is present.
 *
 * @param {RequestDraft} draft
 * @param {{keepPseudoHeaders?: boolean}} [options]
 * @returns {ParsedRequest}
 * @throws {Error} when the URL is missing or not absolute.
 */
export function normalizeRequest(draft, options = {}) {
  if (!draft || typeof draft.url !== 'string' || !draft.url.trim()) throw new Error('Request has no URL.');
  const url = draft.url.trim();
  const parts = splitUrl(url);
  if (!parts || !parts.host) throw new Error(`Not an absolute URL: ${url}`);

  /** @type {string[]} */
  const notes = [...(draft.notes || [])];
  const method = String(draft.method || 'GET').trim().toUpperCase() || 'GET';
  /** @type {Header[]} */
  let headers = (draft.headers || []).map((h) => ({
    name: String(h.name).trim(),
    value: h.value === undefined || h.value === null ? '' : String(h.value).trim(),
  }));
  let httpVersion = mapHttpVersion(draft.httpVersion);
  /** @type {string|undefined} */
  let pseudoAuthority;
  /** @type {string[]} */
  const synthesized = [];

  // --- HTTP/2 pseudo-headers -------------------------------------------------------
  if (!options.keepPseudoHeaders) {
    const { pseudo, removeIdx, names, inconsistent } = detectPseudoHeaders(headers, method, parts);
    if (removeIdx.size) {
      headers = headers.filter((_, i) => !removeIdx.has(i));
      pseudoAuthority = pseudo.get('authority');
      if (!httpVersion) httpVersion = 'HTTP/2.0';
      notes.push(`Detected HTTP/2 pseudo-headers (${names.join(', ')}); treated as an HTTP/2 request and removed from the header list.`);
      const pm = pseudo.get('method');
      if (pm && pm.toUpperCase() !== method) notes.push(`Pseudo-header method "${pm}" differs from the request method ${method}.`);
    }
    if (inconsistent.length) {
      notes.push(`Headers ${inconsistent.join(', ')} look like HTTP/2 pseudo-headers but do not match the URL/method; kept as regular headers.`);
    }
  }
  if (!httpVersion) httpVersion = 'HTTP/1.1';

  // --- User-Agent given separately --------------------------------------------------------
  if (draft.userAgent && !hasHeader(headers, 'user-agent')) {
    headers.push({ name: 'User-Agent', value: String(draft.userAgent).trim() });
  }

  // --- Cookies given separately ---------------------------------------------------------
  const cookies = (draft.cookies || []).map((c) => String(c).trim()).filter(Boolean);
  if (cookies.length) {
    const joined = cookies.join('; ');
    const ci = findHeaderIndex(headers, 'cookie');
    if (ci >= 0) {
      const existing = headers[ci].value.replace(/;\s*$/, '');
      headers[ci] = { name: headers[ci].name, value: existing ? `${existing}; ${joined}` : joined };
    } else {
      const at = typeof draft.cookieIndex === 'number' ? Math.min(Math.max(draft.cookieIndex, 0), headers.length) : headers.length;
      headers.splice(at, 0, { name: 'Cookie', value: joined });
    }
  }

  // --- Content-Type given separately -------------------------------------------------------
  if (draft.contentType) {
    const ct = String(draft.contentType).trim();
    const i = findHeaderIndex(headers, 'content-type');
    if (i < 0) headers.push({ name: 'Content-Type', value: ct });
    else if (headers[i].value !== ct) {
      notes.push(`Content-Type header "${headers[i].value}" replaced by "${ct}".`);
      headers[i] = { name: headers[i].name, value: ct };
    }
  }

  // --- Host ------------------------------------------------------------------------------
  if (!hasHeader(headers, 'host')) {
    headers.unshift({ name: 'Host', value: pseudoAuthority ? pseudoAuthority.trim() : hostHeaderValue(parts) });
    synthesized.push(pseudoAuthority ? 'Host (from the authority pseudo-header)' : 'Host (from URL)');
  }

  // --- Body / Content-Length ----------------------------------------------------------
  const body = draft.body === undefined || draft.body === null ? null : String(draft.body);
  const bodyEncoding = draft.bodyEncoding === 'base64' ? 'base64' : 'text';
  const hasLength = hasHeader(headers, 'content-length');
  const hasTE = hasHeader(headers, 'transfer-encoding');
  if (!hasLength && !hasTE) {
    if (body !== null) {
      headers.push({ name: 'Content-Length', value: String(bodyByteLength(body, bodyEncoding)) });
      synthesized.push('Content-Length (computed from body)');
    } else if (LENGTH_REQUIRED.has(method)) {
      headers.push({ name: 'Content-Length', value: '0' });
      synthesized.push(`Content-Length: 0 (${method} without body)`);
    }
  } else if (hasLength && body !== null) {
    const declared = headers[findHeaderIndex(headers, 'content-length')].value;
    const actual = bodyByteLength(body, bodyEncoding);
    if (/^\d+$/.test(declared) && Number(declared) !== actual) {
      notes.push(`Content-Length header (${declared}) does not match the body length (${actual} bytes).`);
    }
  }
  if (synthesized.length) notes.push(`Added headers: ${synthesized.join(', ')}.`);

  /** @type {ParsedRequest} */
  const out = {
    method,
    url,
    httpVersion,
    headers,
    body,
    bodyEncoding,
    source: draft.source || 'unknown',
    notes: [...new Set(notes)],
  };
  if (draft.response) out.response = draft.response;
  if (typeof draft.startedAt === 'number' && Number.isFinite(draft.startedAt)) out.startedAt = draft.startedAt;
  if (draft.resourceType) out.resourceType = draft.resourceType;
  return out;
}
