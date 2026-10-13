/**
 * Shared type definitions for the input parsers. This module has no runtime code;
 * import it only for JSDoc (`import('./types.js').ParsedRequest`).
 *
 * @module parsers/types
 */

/** @typedef {{name: string, value: string}} Header */

/**
 * A normalized HTTP request, as consumed by the rule engine.
 *
 * @typedef {Object} ParsedRequest
 * @property {string} method        Uppercase, e.g. "GET".
 * @property {string} url           Absolute URL; the query string is kept exactly as given.
 * @property {string} httpVersion   "HTTP/1.1" | "HTTP/2.0" | "HTTP/3.0" | "HTTP/1.0"
 * @property {Header[]} headers     Wire headers in original order and casing; no HTTP/2 pseudo-headers.
 * @property {string|null} body     Request body (text, or base64 when bodyEncoding === 'base64'); null when absent.
 * @property {'text'|'base64'} bodyEncoding
 * @property {string} source        'powershell' | 'curl' | 'fetch' | 'raw' | 'har' | 'devtools'
 * @property {string[]} notes       Human readable notes/warnings about the conversion.
 * @property {ParsedResponse} [response]  Only from HAR/DevTools entries.
 * @property {number} [startedAt]         Epoch ms if known.
 * @property {string} [resourceType]      HAR `_resourceType` if present.
 */

/**
 * @typedef {Object} ParsedResponse
 * @property {number} status
 * @property {string} statusText
 * @property {string} httpVersion
 * @property {Header[]} headers
 * @property {string} mimeType
 * @property {string|null} body          Filled later by the caller (DevTools getContent) or from HAR content.text.
 * @property {'text'|'base64'} bodyEncoding
 */

/**
 * Intermediate request produced by the individual parsers and turned into a
 * {@link ParsedRequest} by `normalizeRequest()`. A `ParsedRequest` is itself a valid draft
 * (normalization is idempotent).
 *
 * @typedef {Object} RequestDraft
 * @property {string} url
 * @property {string} [method]              Defaults to GET.
 * @property {string} [httpVersion]         Known protocol version; inferred when absent.
 * @property {Header[]} [headers]
 * @property {string|null} [body]
 * @property {'text'|'base64'} [bodyEncoding]
 * @property {string} source
 * @property {string[]} [notes]
 * @property {string[]} [cookies]           Cookies given separately from the headers ("name=value" strings).
 * @property {number} [cookieIndex]         Header index at which a synthesized Cookie header is inserted (default: end).
 * @property {string} [userAgent]           User-Agent given separately (PowerShell session, curl -A).
 * @property {string} [contentType]         Content-Type given separately; replaces an existing Content-Type header.
 * @property {ParsedResponse} [response]
 * @property {number} [startedAt]
 * @property {string} [resourceType]
 */

/**
 * Options accepted by `parseInput()` and the individual parsers.
 *
 * @typedef {Object} ParseOptions
 * @property {boolean} [keepPseudoHeaders]  Do not detect/remove HTTP/2 pseudo-headers.
 * @property {string} [format]              Skip auto-detection ('powershell'|'curl'|'fetch'|'raw'|'har').
 * @property {string} [multipartBoundary]   Fixed boundary for synthesized multipart bodies (tests).
 * @property {string} [source]              Override the `source` field (fromHarEntry: 'devtools').
 */

export {};
