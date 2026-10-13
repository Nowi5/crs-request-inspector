/**
 * Input parsing entry point: converts pasted requests (Chrome DevTools "Copy as PowerShell",
 * "Copy as cURL (bash)", "Copy as cURL (cmd)", "Copy as fetch", "Copy as fetch (Node.js)",
 * the "Copy all as ..." variants, raw HTTP text) and HAR files into normalized
 * {@link ParsedRequest} objects for the rule engine.
 *
 * Plain ES2022, no dependencies, no eval; runs in the extension (browser) and in Node.
 *
 * @example
 *   import { parseInput } from './parsers/index.js';
 *   const { requests, format, errors } = parseInput(pastedText);
 *
 * @module parsers
 */

import { parsePowerShell } from './powershell.js';
import { parseCurl } from './curl.js';
import { parseFetch } from './fetch.js';
import { parseRaw, isRequestStartLine } from './raw.js';
import { parseHar, fromHarEntry, harToRequests } from './har.js';
import { normalizeRequest } from './normalize.js';

export { parseHar, fromHarEntry, normalizeRequest, parsePowerShell, parseCurl, parseFetch, parseRaw };

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParsedResponse} ParsedResponse */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

/** @typedef {'powershell'|'curl'|'fetch'|'raw'|'har'|'unknown'} InputFormat */

/**
 * @param {string} text
 * @returns {object|null} parsed JSON when it looks like a HAR document, else null
 */
function tryParseHarJson(text) {
  const t = text.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return null;
  try {
    const json = JSON.parse(t);
    if (json && Array.isArray(json.log?.entries)) return json;
    if (Array.isArray(json) && json.length && json.every((e) => e && typeof e.request === 'object')) return json;
    if (json && typeof json.request === 'object' && typeof json.request?.url === 'string') return json;
  } catch {
    /* not JSON */
  }
  return null;
}

/**
 * Classify a single (trimmed) line as the start of a known format.
 * @param {string} line
 * @returns {InputFormat|null}
 */
function classifyLine(line) {
  if (/^(?:\$\s+|sudo\s+)?curl(?:\.exe)?(?:\s|$|\^)/i.test(line)) return 'curl';
  if (/^(?:(?:const|let|var)\s+[\w$]+\s*=\s*)?(?:await\s+)?fetch\s*\(/.test(line)) return 'fetch';
  if (/^(?:\$[\w:]+\s*(?:=|\.)|\[[\w.]+\]::|(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|New-Object)\b)/i.test(line)) return 'powershell';
  if (isRequestStartLine(line)) return 'raw';
  return null;
}

/**
 * Detect the format of pasted text.
 * @param {string} text
 * @returns {InputFormat}
 */
export function detectFormat(text) {
  if (typeof text !== 'string') return 'unknown';
  const src = text.replace(/^﻿/, '');
  if (tryParseHarJson(src)) return 'har';
  // Decide by the first meaningful line.
  for (const raw of src.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//') || line === '###' || line === '---') continue;
    const f = classifyLine(line);
    if (f) return f;
    break;
  }
  // Fall back to searching anywhere.
  if (/\bInvoke-(?:WebRequest|RestMethod)\b/i.test(src)) return 'powershell';
  if (/(?:^|[\s;&|(])curl(?:\.exe)?\s+\S/im.test(src)) return 'curl';
  if (/(?<![\w$.])fetch\s*\(\s*["'`]/.test(src)) return 'fetch';
  if (src.split(/\r?\n/).some((l) => isRequestStartLine(l))) return 'raw';
  return 'unknown';
}

/**
 * Parse pasted text (or HAR JSON) into normalized requests. Never throws: problems are
 * reported in `errors`, and requests that parsed fine are still returned.
 *
 * @param {string} text
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], format: InputFormat, errors: string[]}}
 */
export function parseInput(text, options = {}) {
  /** @type {InputFormat} */
  let format = 'unknown';
  try {
    if (typeof text !== 'string') return { requests: [], format, errors: ['Input must be a string.'] };
    if (!text.trim()) return { requests: [], format, errors: ['Input is empty.'] };
    format = /** @type {InputFormat} */ (options.format || detectFormat(text));
    switch (format) {
      case 'har': {
        const { requests, errors, skipped } = harToRequests(text, options);
        if (skipped) errors.push(`${skipped} HAR entr${skipped === 1 ? 'y' : 'ies'} with non-HTTP(S) URLs skipped.`);
        return { requests, format, errors };
      }
      case 'powershell': return { format, ...parsePowerShell(text, options) };
      case 'curl': return { format, ...parseCurl(text, options) };
      case 'fetch': return { format, ...parseFetch(text, options) };
      case 'raw': return { format, ...parseRaw(text, options) };
      default:
        return {
          requests: [],
          format: 'unknown',
          errors: ['Could not detect the input format. Paste a request copied from Chrome DevTools (Copy as PowerShell / cURL / fetch), raw HTTP request text, or a HAR file.'],
        };
    }
  } catch (e) {
    return { requests: [], format, errors: [`Unexpected parser error: ${e && e.message ? e.message : String(e)}`] };
  }
}
