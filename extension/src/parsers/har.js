/**
 * HAR (HTTP Archive 1.2) import and conversion of single HAR entries. The DevTools panel
 * calls {@link fromHarEntry} with `chrome.devtools.network.Request` objects (HAR entries
 * with extra fields such as `_resourceType`, `serverIPAddress` and a `getContent()` method).
 *
 * @module parsers/har
 */

import { normalizeRequest } from './normalize.js';
import { mapHttpVersion, hasHeader, formUrlEncode, buildMultipartBody, randomHex } from './util.js';

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParsedResponse} ParsedResponse */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

/**
 * @param {any} list
 * @returns {Header[]}
 */
function harHeaders(list) {
  if (!Array.isArray(list)) return [];
  return list
    .filter((h) => h && typeof h.name === 'string')
    .map((h) => ({ name: h.name, value: h.value === undefined || h.value === null ? '' : String(h.value) }));
}

/**
 * Encode a HAR postData param value for an urlencoded body, keeping existing %XX escapes
 * (Chrome stores the values as they appeared in the body).
 * @param {string} s
 */
function encodeParam(s) {
  return String(s).split(/(%[0-9A-Fa-f]{2})/).map((part, i) => (i % 2 ? part : formUrlEncode(part))).join('');
}

/**
 * Build the response part of a ParsedRequest from a HAR response.
 * @param {any} res
 * @param {ParseOptions} options
 * @returns {ParsedResponse|undefined}
 */
function buildResponse(res, options) {
  if (!res || typeof res !== 'object') return undefined;
  const content = res.content || {};
  return {
    status: Number(res.status) || 0,
    statusText: res.statusText ? String(res.statusText) : '',
    httpVersion: mapHttpVersion(res.httpVersion) || 'HTTP/1.1',
    headers: harHeaders(res.headers).filter((h) => options.keepPseudoHeaders || !h.name.startsWith(':')),
    mimeType: content.mimeType ? String(content.mimeType) : '',
    body: typeof content.text === 'string' ? content.text : null,
    bodyEncoding: content.encoding === 'base64' ? 'base64' : 'text',
  };
}

/**
 * Convert one HAR entry (or DevTools network request) into a ParsedRequest.
 *
 * @param {any} entry
 * @param {ParseOptions} [options]  `source` defaults to 'har' (use 'devtools' from the panel).
 * @returns {ParsedRequest|null} null for non-HTTP(S) URLs (data:, blob:, chrome-extension:, ...).
 * @throws {Error} when the entry has no request URL or the URL is invalid.
 */
export function fromHarEntry(entry, options = {}) {
  const req = entry?.request;
  if (!req || typeof req.url !== 'string' || !req.url) throw new Error('HAR entry has no request.url.');
  /** @type {string[]} */
  const notes = [];
  let url = req.url;
  if (/^wss?:\/\//i.test(url)) {
    url = url.replace(/^ws/i, 'http');
    notes.push('WebSocket handshake: ws(s):// URL evaluated as http(s)://.');
  } else if (!/^https?:\/\//i.test(url)) return null;

  const headers = harHeaders(req.headers);
  /** @type {string[]} */
  let cookies = [];
  if (!hasHeader(headers, 'cookie') && Array.isArray(req.cookies) && req.cookies.length) {
    cookies = req.cookies.filter((c) => c && c.name !== undefined).map((c) => `${c.name}=${c.value ?? ''}`);
    if (cookies.length) notes.push('Cookie header rebuilt from the HAR request.cookies list.');
  }

  /** @type {string|null} */
  let body = null;
  /** @type {'text'|'base64'} */
  let bodyEncoding = 'text';
  const pd = req.postData;
  if (pd && typeof pd === 'object') {
    if (typeof pd.text === 'string') {
      body = pd.text;
      if (pd.encoding === 'base64' || pd._encoding === 'base64') bodyEncoding = 'base64';
    } else if (Array.isArray(pd.params) && pd.params.length) {
      const mime = String(pd.mimeType || '');
      if (/multipart\/form-data/i.test(mime)) {
        const boundary = /boundary=("?)([^";]+)\1/i.exec(mime)?.[2] || options.multipartBoundary || `----WebKitFormBoundary${randomHex(8)}`;
        body = buildMultipartBody(pd.params.map((p) => ({
          name: String(p.name ?? ''), value: String(p.value ?? ''), filename: p.fileName, contentType: p.contentType,
        })), boundary);
      } else {
        body = pd.params.map((p) => `${encodeParam(p.name ?? '')}=${encodeParam(p.value ?? '')}`).join('&');
      }
      notes.push('Request body rebuilt from HAR postData.params (postData.text was missing).');
    } else body = '';
    if (pd.mimeType && !hasHeader(headers, 'content-type')) headers.push({ name: 'Content-Type', value: String(pd.mimeType) });
  }

  const started = typeof entry.startedDateTime === 'string' ? Date.parse(entry.startedDateTime) : NaN;
  const version = mapHttpVersion(req.httpVersion);
  return normalizeRequest({
    method: req.method || 'GET',
    url,
    httpVersion: version ?? undefined,
    headers,
    body,
    bodyEncoding,
    source: options.source || 'har',
    notes,
    cookies,
    response: buildResponse(entry.response, options),
    startedAt: Number.isFinite(started) ? started : undefined,
    resourceType: typeof entry._resourceType === 'string' ? entry._resourceType : undefined,
  }, options);
}

/**
 * Convert a HAR document to requests, collecting per-entry errors.
 * @param {string|object} input  HAR JSON text or parsed object (also accepts an entries array or a single entry).
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], errors: string[], skipped: number}}
 * @throws {Error} when the input is not valid JSON or not a HAR document.
 */
export function harToRequests(input, options = {}) {
  const har = typeof input === 'string' ? JSON.parse(input.replace(/^﻿/, '')) : input;
  let entries;
  if (Array.isArray(har)) entries = har;
  else if (har && Array.isArray(har.log?.entries)) entries = har.log.entries;
  else if (har && har.request) entries = [har];
  else throw new Error('Not a HAR document (missing log.entries).');
  /** @type {ParsedRequest[]} */
  const requests = [];
  /** @type {string[]} */
  const errors = [];
  let skipped = 0;
  entries.forEach((entry, i) => {
    try {
      const r = fromHarEntry(entry, options);
      if (r) requests.push(r);
      else skipped++;
    } catch (e) {
      errors.push(`HAR entry #${i + 1}: ${e.message}`);
    }
  });
  return { requests, errors, skipped };
}

/**
 * Parse a HAR document into requests. Entries with non-HTTP(S) URLs are skipped; invalid
 * entries are skipped too (use `parseInput` to get their error messages).
 *
 * @param {string|object} input  HAR JSON text or parsed object.
 * @param {ParseOptions} [options]
 * @returns {ParsedRequest[]}
 * @throws {Error} when the input is not valid JSON or not a HAR document.
 */
export function parseHar(input, options = {}) {
  return harToRequests(input, options).requests;
}
