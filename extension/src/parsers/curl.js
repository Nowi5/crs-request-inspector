/**
 * Parser for curl command lines: Chrome DevTools "Copy as cURL (bash)" / "Copy as cURL (cmd)"
 * and "Copy all as cURL" output, plus typical hand-written commands.
 *
 * Two tokenizers are provided:
 *  - bash/POSIX: '...', $'...' (ANSI-C), "..." with backslash escapes, backslash escapes and
 *    backslash-newline continuation, comments, command separators (; & && || | newline).
 *  - Windows cmd: caret escapes (^" ^\ ^{ ^% ...), caret-newline continuation, the doubled
 *    newline Chrome uses for literal newlines, & / && / | separators, then MS C runtime
 *    argument splitting. Chrome escapes every backslash as \\ and quote as \" inside
 *    ^"...^" arguments; those two sequences are decoded exactly (this is the inverse of
 *    Chrome's escaping, which differs from msvcrt for backslashes not followed by a quote).
 *
 * @module parsers/curl
 */

import { normalizeRequest } from './normalize.js';
import {
  hasHeader, findHeaderIndex, curlEscape, appendQuery, buildMultipartBody, randomHex, guessMimeType, utf8ToBase64,
} from './util.js';

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

class CurlError extends Error {}

// --------------------------------------------------------------------------------------
// Tokenizers
// --------------------------------------------------------------------------------------

const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

/**
 * Read an ANSI-C quoted string body ($'...'), starting after the opening quote.
 * \xHH and octal escapes produce bytes which are decoded as UTF-8.
 * @param {string} src
 * @param {number} i
 * @returns {[string, number]} decoded string and index after the closing quote
 */
function readAnsiC(src, i) {
  let out = '';
  /** @type {number[]} */
  let bytes = [];
  const flush = () => {
    if (bytes.length) {
      out += utf8Decoder.decode(new Uint8Array(bytes));
      bytes = [];
    }
  };
  const simple = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
  while (i < src.length) {
    const c = src[i];
    if (c === "'") {
      flush();
      return [out, i + 1];
    }
    if (c !== '\\') {
      flush();
      out += c;
      i++;
      continue;
    }
    const n = src[i + 1];
    if (n === undefined) break;
    if (n in simple) {
      flush();
      out += simple[n];
      i += 2;
      continue;
    }
    let m;
    if ((m = /^x([0-9a-fA-F]{1,2})/.exec(src.slice(i + 1, i + 4)))) {
      bytes.push(parseInt(m[1], 16));
      i += 1 + m[0].length;
      continue;
    }
    if ((m = /^[0-7]{1,3}/.exec(src.slice(i + 1, i + 4)))) {
      bytes.push(parseInt(m[0], 8) & 0xff);
      i += 1 + m[0].length;
      continue;
    }
    if ((m = /^(u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8})/.exec(src.slice(i + 1, i + 10)))) {
      flush();
      out += String.fromCodePoint(parseInt(m[0].slice(1), 16));
      i += 1 + m[0].length;
      continue;
    }
    if (n === 'c' && src[i + 2] !== undefined) {
      flush();
      out += String.fromCharCode(src[i + 2].toUpperCase().charCodeAt(0) ^ 0x40);
      i += 3;
      continue;
    }
    flush();
    out += '\\' + n;
    i += 2;
  }
  throw new CurlError("Unterminated $'...' string");
}

/**
 * Split bash-style text into commands (arrays of words).
 * @param {string} src
 * @returns {string[][]}
 */
export function tokenizeBash(src) {
  /** @type {string[][]} */
  const commands = [];
  /** @type {string[]} */
  let words = [];
  /** @type {string|null} */
  let cur = null;
  let skipNextWord = false;
  const pushWord = () => {
    if (cur !== null) {
      if (skipNextWord) skipNextWord = false;
      else words.push(cur);
      cur = null;
    }
  };
  const endCommand = () => {
    pushWord();
    if (words.length) commands.push(words);
    words = [];
    skipNextWord = false;
  };
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') {
      const n = src[i + 1];
      if (n === '\n') {
        i += 2;
        continue;
      }
      if (n === '\r' && src[i + 2] === '\n') {
        i += 3;
        continue;
      }
      if (n !== undefined) cur = (cur ?? '') + n;
      i += 2;
      continue;
    }
    if (c === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) throw new CurlError("Unterminated '...' string");
      cur = (cur ?? '') + src.slice(i + 1, end);
      i = end + 1;
      continue;
    }
    if (c === '$' && src[i + 1] === "'") {
      const [s, next] = readAnsiC(src, i + 2);
      cur = (cur ?? '') + s;
      i = next;
      continue;
    }
    if (c === '$' && src[i + 1] === '"') {
      i++; // $"..." (locale translation) behaves like "..."
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let s = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const n = src[j + 1];
          if (n === '\n') {
            j += 2;
            continue;
          }
          if (n === '$' || n === '`' || n === '"' || n === '\\') {
            s += n;
            j += 2;
            continue;
          }
        }
        s += src[j];
        j++;
      }
      if (j >= src.length) throw new CurlError('Unterminated "..." string');
      cur = (cur ?? '') + s;
      i = j + 1;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') {
      pushWord();
      i++;
      continue;
    }
    if (c === '\n' || c === ';' || c === '&' || c === '|') {
      endCommand();
      i++;
      if ((c === '&' || c === '|' || c === ';') && src[i] === c) i++;
      continue;
    }
    if ((c === '>' || c === '<') && (cur === null || /^\d+$/.test(cur))) {
      // Redirection: drop the operator and its target word.
      cur = null;
      i++;
      while (src[i] === '>' || src[i] === '&') i++;
      skipNextWord = true;
      continue;
    }
    if (c === '#' && cur === null) {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    cur = (cur ?? '') + c;
    i++;
  }
  endCommand();
  return commands;
}

/**
 * Split one cmd.exe command line (after caret processing) into arguments.
 * @param {string} s
 * @returns {string[]}
 */
function splitWindowsArgs(s) {
  const args = [];
  /** @type {string|null} */
  let cur = null;
  let inQ = false;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\') {
      let n = 0;
      while (s[i] === '\\') {
        n++;
        i++;
      }
      if (s[i] === '"') {
        cur = (cur ?? '') + '\\'.repeat(Math.floor(n / 2));
        if (n % 2 === 1) {
          cur += '"';
          i++;
        }
      } else cur = (cur ?? '') + '\\'.repeat(Math.ceil(n / 2));
      continue;
    }
    if (c === '"') {
      if (inQ && s[i + 1] === '"') {
        cur = (cur ?? '') + '"';
        i += 2;
        continue;
      }
      inQ = !inQ;
      cur = cur ?? '';
      i++;
      continue;
    }
    if (!inQ && (c === ' ' || c === '\t' || c === '\n' || c === '\r')) {
      if (cur !== null) args.push(cur);
      cur = null;
      i++;
      continue;
    }
    cur = (cur ?? '') + c;
    i++;
  }
  if (cur !== null) args.push(cur);
  return args;
}

/**
 * Split Windows cmd.exe text into commands (arrays of arguments).
 * @param {string} src
 * @returns {string[][]}
 */
export function tokenizeCmd(src) {
  /** @type {string[]} */
  const lines = [];
  let cur = '';
  let inQ = false;
  let i = 0;
  const end = () => {
    if (cur.trim()) lines.push(cur);
    cur = '';
    inQ = false;
  };
  while (i < src.length) {
    const c = src[i];
    if (!inQ && c === '^') {
      const n = src[i + 1];
      if (n === undefined) {
        i++;
        continue;
      }
      if (n === '\r' || n === '\n') {
        // Caret at end of line: continue on the next line; its first character is escaped
        // (Chrome encodes a literal newline as "^" + newline + newline).
        i += n === '\r' && src[i + 2] === '\n' ? 3 : 2;
        if (src[i] === '\r' && src[i + 1] === '\n') {
          cur += '\n';
          i += 2;
        } else if (src[i] === '\n') {
          cur += '\n';
          i++;
        }
        continue;
      }
      cur += n;
      i += 2;
      continue;
    }
    if (c === '"') {
      inQ = !inQ;
      cur += c;
      i++;
      continue;
    }
    if (c === '\n') {
      end();
      i++;
      continue;
    }
    if (!inQ && (c === '&' || c === '|')) {
      end();
      i++;
      if (src[i] === c) i++;
      continue;
    }
    cur += c;
    i++;
  }
  end();
  return lines.map(splitWindowsArgs).filter((a) => a.length);
}

/**
 * Heuristic: does this curl text use Windows cmd escaping?
 * @param {string} text
 */
export function looksLikeCmd(text) {
  return /^\s*curl(?:\.exe)?\s+\^"/im.test(text) || /[ \t]\^\r?\n/.test(text);
}

// --------------------------------------------------------------------------------------
// curl option model
// --------------------------------------------------------------------------------------

/** Short option letter -> long option name. */
const SHORT = {
  X: 'request', H: 'header', b: 'cookie', A: 'user-agent', e: 'referer', u: 'user', d: 'data', F: 'form',
  G: 'get', I: 'head', k: 'insecure', L: 'location', s: 'silent', S: 'show-error', v: 'verbose', i: 'include',
  o: 'output', O: 'remote-name', c: 'cookie-jar', x: 'proxy', m: 'max-time', w: 'write-out', T: 'upload-file',
  r: 'range', E: 'cert', K: 'config', U: 'proxy-user', D: 'dump-header', C: 'continue-at', f: 'fail',
  g: 'globoff', 0: 'http1.0', 1: 'tlsv1', 2: 'sslv2', 3: 'sslv3', 4: 'ipv4', 6: 'ipv6', N: 'no-buffer',
  n: 'netrc', j: 'junk-session-cookies', l: 'list-only', q: 'disable', R: 'remote-time', Z: 'parallel',
  '#': 'progress-bar', a: 'append', B: 'use-ascii', M: 'manual', p: 'proxytunnel', P: 'ftp-port', Q: 'quote',
  t: 'telnet-option', V: 'version', y: 'speed-time', Y: 'speed-limit', z: 'time-cond', J: 'remote-header-name',
  h: 'help',
};

/** Long options that take an argument. */
const WITH_ARG = new Set([
  'request', 'header', 'cookie', 'user-agent', 'referer', 'user', 'data', 'data-raw', 'data-binary', 'data-ascii',
  'data-urlencode', 'json', 'form', 'form-string', 'url', 'output', 'cookie-jar', 'proxy', 'max-time', 'write-out',
  'upload-file', 'range', 'cert', 'config', 'proxy-user', 'dump-header', 'continue-at', 'ftp-port', 'quote',
  'telnet-option', 'speed-time', 'speed-limit', 'time-cond', 'connect-timeout', 'retry', 'retry-delay',
  'retry-max-time', 'max-redirs', 'resolve', 'connect-to', 'cacert', 'capath', 'key', 'key-type', 'cert-type',
  'pass', 'ciphers', 'interface', 'local-port', 'limit-rate', 'max-filesize', 'oauth2-bearer', 'url-query',
  'aws-sigv4', 'proxy-header', 'noproxy', 'unix-socket', 'abstract-unix-socket', 'output-dir', 'trace',
  'trace-ascii', 'stderr', 'dns-servers', 'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'expect100-timeout',
  'keepalive-time', 'happy-eyeballs-timeout-ms', 'pinnedpubkey', 'request-target', 'variable', 'sasl-authzid',
  'login-options', 'mail-from', 'mail-rcpt', 'mail-auth', 'hostpubmd5', 'hostpubsha256', 'pubkey', 'engine',
  'egd-file', 'random-file', 'crlfile', 'preproxy', 'proxy-cacert', 'proxy-capath', 'proxy-cert', 'proxy-cert-type',
  'proxy-key', 'proxy-key-type', 'proxy-pass', 'proxy-ciphers', 'proxy-crlfile', 'proxy-pinnedpubkey',
  'proxy-service-name', 'proxy-tls13-ciphers', 'proxy-tlsauthtype', 'proxy-tlspassword', 'proxy-tlsuser',
  'proxy1.0', 'socks4', 'socks4a', 'socks5', 'socks5-hostname', 'socks5-gssapi-service', 'service-name',
  'tls13-ciphers', 'tlsauthtype', 'tlspassword', 'tlsuser', 'tls-max', 'curves', 'delegation', 'ftp-account',
  'ftp-alternative-to-user', 'ftp-method', 'ftp-ssl-ccc-mode', 'krb', 'haproxy-clientip', 'ip-tos',
  'vlan-priority', 'ech', 'etag-compare', 'etag-save', 'create-file-mode', 'rate', 'parallel-max', 'max-time',
  'proto', 'proto-redir', 'proto-default', 'netrc-file', 'write-out', 'retry-connrefused-max', 'mptcp',
  'sigalgs', 'ssl-sessions', 'knownhosts', 'proxy-ssl-auto-client-cert', 'header-file', 'out-null',
]);
// Some of the above are actually boolean in curl; remove them so they don't eat the next word.
for (const b of ['mptcp', 'proxy-ssl-auto-client-cert', 'out-null']) WITH_ARG.delete(b);

/** Boolean options that are known and safely ignored. */
const IGNORED_FLAGS = new Set([
  'insecure', 'location', 'silent', 'show-error', 'verbose', 'include', 'remote-name', 'fail', 'fail-with-body',
  'tlsv1', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3', 'sslv2', 'sslv3', 'ipv4', 'ipv6', 'no-buffer', 'netrc',
  'netrc-optional', 'junk-session-cookies', 'list-only', 'disable', 'remote-time', 'parallel', 'progress-bar',
  'append', 'use-ascii', 'manual', 'proxytunnel', 'version', 'remote-header-name', 'help', 'location-trusted',
  'no-keepalive', 'no-sessionid', 'no-alpn', 'no-npn', 'tcp-nodelay', 'tcp-fastopen', 'path-as-is', 'raw',
  'tr-encoding', 'ssl', 'ssl-reqd', 'ssl-allow-beast', 'ssl-no-revoke', 'ssl-revoke-best-effort', 'ssl-auto-client-cert',
  'ca-native', 'proxy-ca-native', 'proxy-insecure', 'basic', 'digest', 'ntlm', 'ntlm-wb', 'negotiate', 'anyauth',
  'retry-all-errors', 'retry-connrefused', 'remote-name-all', 'create-dirs', 'styled-output', 'xattr', 'no-progress-meter',
  'post301', 'post302', 'post303', 'suppress-connect-headers', 'cert-status', 'false-start', 'sasl-ir', 'disallow-username-in-url',
  'http0.9', 'parallel-immediate', 'skip-existing', 'remove-on-error', 'clobber', 'no-clobber', 'compressed-ssh',
  'mptcp', 'proxy-ssl-auto-client-cert', 'out-null', 'ignore-content-length', 'crlf', 'doh-insecure', 'doh-cert-status',
  'ftp-create-dirs', 'ftp-pasv', 'ftp-skip-pasv-ip', 'ftp-pret', 'ftp-ssl-control', 'globoff', 'trace-time', 'trace-ids',
  'proxy-basic', 'proxy-digest', 'proxy-ntlm', 'proxy-negotiate', 'proxy-anyauth', 'socks5-basic', 'socks5-gssapi',
  'socks5-gssapi-nec', 'haproxy-protocol', 'alt-svc', 'hsts', 'metalink', 'libcurl',
]);

/**
 * Turn one tokenized curl command into a request draft.
 * @param {string[]} words  words[0] is the curl executable.
 * @param {ParseOptions} options
 * @returns {ParsedRequest}
 */
function curlWordsToRequest(words, options) {
  /** @type {string[]} */
  const notes = [];
  /** @type {Header[]} */
  const headers = [];
  /** @type {string[]} */
  const urls = [];
  /** @type {string[]} */
  const cookies = [];
  let cookieIndex;
  /** @type {string[]} */
  const data = [];
  /** @type {Array<{name: string, value: string, filename?: string, contentType?: string}>} */
  const forms = [];
  /** @type {string[]} */
  const urlQueries = [];
  const removed = new Set();
  let method;
  let head = false;
  let get = false;
  let json = false;
  let compressed = false;
  let globoff = false;
  let userAgent;
  let referer;
  let user;
  let uploadFile;
  let httpVersion;
  const unknown = [];

  const addHeader = (raw) => {
    if (raw.startsWith('@')) {
      notes.push(`Headers from file ${raw.slice(1)} are not available; ignored.`);
      return;
    }
    const colon = raw.indexOf(':');
    if (colon < 0) {
      const t = raw.trim();
      if (t.endsWith(';')) headers.push({ name: t.slice(0, -1).trim(), value: '' });
      else notes.push(`Ignored malformed header "${raw}".`);
      return;
    }
    const name = raw.slice(0, colon).trim();
    const value = raw.slice(colon + 1).trim();
    if (!value) {
      // "Name:" removes an internal curl header.
      removed.add(name.toLowerCase());
      notes.push(`-H "${name}:" removes the header in curl; not sent.`);
      return;
    }
    headers.push({ name, value });
  };

  const readData = (val, kind) => {
    if (kind !== 'raw' && val.startsWith('@')) {
      notes.push(`Request body from file ${val.slice(1)} is not available; used an empty body.`);
      return '';
    }
    return val;
  };

  const dataUrlencode = (val) => {
    const m = /[=@]/.exec(val);
    if (!m) return curlEscape(val);
    const name = val.slice(0, m.index);
    if (m[0] === '@') {
      notes.push(`--data-urlencode file ${val.slice(m.index + 1)} is not available; used an empty value.`);
      return name ? `${name}=` : '';
    }
    const content = curlEscape(val.slice(m.index + 1));
    return name ? `${name}=${content}` : content;
  };

  const parseForm = (val, literal) => {
    const eq = val.indexOf('=');
    if (eq < 0) {
      notes.push(`Ignored malformed -F argument "${val}".`);
      return;
    }
    const name = val.slice(0, eq);
    let rest = val.slice(eq + 1);
    if (literal) {
      forms.push({ name, value: rest });
      return;
    }
    let isFile = false;
    let isContentFile = false;
    if (rest.startsWith('@')) {
      isFile = true;
      rest = rest.slice(1);
    } else if (rest.startsWith('<')) {
      isContentFile = true;
      rest = rest.slice(1);
    }
    // Split off ;type= / ;filename= / ;headers= parameters (value may be double-quoted).
    let value = rest;
    let params = '';
    if (rest.startsWith('"')) {
      let j = 1;
      let v = '';
      while (j < rest.length && rest[j] !== '"') {
        if (rest[j] === '\\' && j + 1 < rest.length) j++;
        v += rest[j++];
      }
      value = v;
      params = rest.slice(j + 1);
    } else {
      const m = /;(type|filename|headers|encoder)=/i.exec(rest);
      if (m) {
        value = rest.slice(0, m.index);
        params = rest.slice(m.index);
      }
    }
    const type = /;type=([^;]*)/i.exec(params)?.[1];
    const fname = /;filename=("?)([^;"]*)\1/i.exec(params)?.[2];
    if (isFile) {
      const base = value.split(/[\\/]/).pop() || value;
      notes.push(`Contents of file ${value} for form field "${name}" are not available; the part body is empty.`);
      forms.push({ name, value: '', filename: fname ?? base, contentType: type || guessMimeType(fname ?? base) });
    } else if (isContentFile) {
      notes.push(`Contents of file ${value} for form field "${name}" are not available; the part body is empty.`);
      forms.push({ name, value: '', contentType: type });
    } else forms.push({ name, value, filename: fname, contentType: type });
  };

  /**
   * @param {string} name  long option name
   * @param {string|true} val
   */
  const apply = (name, val) => {
    const v = /** @type {string} */ (val);
    switch (name) {
      case 'url': urls.push(v); break;
      case 'request': method = v; break;
      case 'header': addHeader(v); break;
      case 'cookie':
        if (v.includes('=')) {
          if (cookieIndex === undefined) cookieIndex = headers.length;
          cookies.push(v.trim().replace(/;\s*$/, ''));
        } else notes.push(`Cookie file ${v} is not available; ignored.`);
        break;
      case 'user-agent': userAgent = v; break;
      case 'referer': referer = v.replace(/;auto$/, ''); break;
      case 'user': user = v; break;
      case 'data': case 'data-ascii': data.push(readData(v, 'ascii')); break;
      case 'data-binary': data.push(readData(v, 'binary')); break;
      case 'data-raw': data.push(v); break;
      case 'data-urlencode': data.push(dataUrlencode(v)); break;
      case 'json': json = true; data.push(readData(v, 'json')); break;
      case 'form': parseForm(v, false); break;
      case 'form-string': parseForm(v, true); break;
      case 'get': get = true; break;
      case 'head': head = true; break;
      case 'compressed': compressed = true; break;
      case 'globoff': globoff = true; break;
      case 'http1.0': httpVersion = 'HTTP/1.0'; break;
      case 'http1.1': httpVersion = 'HTTP/1.1'; break;
      case 'http2': case 'http2-prior-knowledge': httpVersion = 'HTTP/2.0'; break;
      case 'http3': case 'http3-only': httpVersion = 'HTTP/3.0'; break;
      case 'upload-file': uploadFile = v; break;
      case 'range': headers.push({ name: 'Range', value: `bytes=${v}` }); break;
      case 'oauth2-bearer': headers.push({ name: 'Authorization', value: `Bearer ${v}` }); break;
      case 'url-query': urlQueries.push(v.startsWith('+') ? v.slice(1) : dataUrlencode(v)); break;
      case 'config': notes.push(`curl config file ${v} is not available; ignored.`); break;
      case 'request-target': notes.push(`--request-target ${v} is not represented; the URL path is used.`); break;
      default:
        if (!WITH_ARG.has(name) && !IGNORED_FLAGS.has(name) && !name.startsWith('no-')) unknown.push(`--${name}`);
    }
  };

  let endOfOptions = false;
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (w === '&' || w === '&&' || w === ';') continue;
    if (endOfOptions || !w.startsWith('-') || w === '-') {
      urls.push(w);
      continue;
    }
    if (w === '--') {
      endOfOptions = true;
      continue;
    }
    if (w.startsWith('--')) {
      const name = w.slice(2).toLowerCase();
      if (WITH_ARG.has(name)) {
        if (i + 1 >= words.length) throw new CurlError(`Option ${w} needs an argument`);
        apply(name, words[++i]);
      } else apply(name, true);
      continue;
    }
    for (let k = 1; k < w.length; k++) {
      const long = SHORT[w[k]];
      if (!long) {
        unknown.push(`-${w[k]}`);
        continue;
      }
      if (WITH_ARG.has(long)) {
        let val = w.slice(k + 1);
        if (!val) {
          if (i + 1 >= words.length) throw new CurlError(`Option -${w[k]} needs an argument`);
          val = words[++i];
        }
        apply(long, val);
        break;
      }
      apply(long, true);
    }
  }
  if (unknown.length) notes.push(`Ignored unknown curl option(s): ${unknown.join(', ')}.`);

  if (!urls.length) throw new CurlError('No URL found in curl command');
  if (urls.length > 1) notes.push(`curl command has ${urls.length} URLs; only the first (${urls[0]}) is used.`);
  let url = urls[0];
  if (!globoff) url = url.replace(/\\([[\]{}])/g, '$1');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
    url = 'http://' + url;
    notes.push('URL without scheme; curl assumes http://.');
  }
  for (const q of urlQueries) url = appendQuery(url, q);

  if (data.length && forms.length) notes.push('Both -d and -F were given (curl refuses this); the -d data is used.');

  // Body
  /** @type {string|null} */
  let body = null;
  let contentType;
  if (data.length) {
    const joined = data.join(json ? '' : '&');
    if (get) url = appendQuery(url, joined);
    else {
      body = joined;
      if (!hasHeader(headers, 'content-type') && !removed.has('content-type')) {
        contentType = json ? 'application/json' : 'application/x-www-form-urlencoded';
        notes.push(`No Content-Type header given; curl sends ${contentType} for ${json ? '--json' : '-d/--data'}.`);
      }
      if (json && !hasHeader(headers, 'accept') && !removed.has('accept')) headers.push({ name: 'Accept', value: 'application/json' });
    }
  } else if (forms.length) {
    const boundary = options.multipartBoundary || `------------------------${randomHex(8)}`;
    body = buildMultipartBody(forms, boundary);
    const ci = findHeaderIndex(headers, 'content-type');
    if (ci < 0) contentType = `multipart/form-data; boundary=${boundary}`;
    else if (!/boundary=/i.test(headers[ci].value)) headers[ci] = { name: headers[ci].name, value: `${headers[ci].value}; boundary=${boundary}` };
    notes.push('-F form fields were encoded as multipart/form-data with a generated boundary.');
  }

  // Method
  let finalMethod = method;
  if (!finalMethod) {
    if (head) finalMethod = 'HEAD';
    else if (uploadFile !== undefined) finalMethod = 'PUT';
    else if (get) finalMethod = 'GET';
    else if (data.length || forms.length) finalMethod = 'POST';
    else finalMethod = 'GET';
  }
  if (uploadFile !== undefined) {
    notes.push(`-T ${uploadFile}: file contents are not available; body left empty.`);
    if (body === null) body = '';
  }

  // Extra headers curl derives from options
  if (user !== undefined && !hasHeader(headers, 'authorization')) {
    const creds = user.includes(':') ? user : `${user}:`;
    if (!user.includes(':')) notes.push('-u without password: curl would prompt for it; an empty password was used.');
    headers.unshift({ name: 'Authorization', value: `Basic ${utf8ToBase64(creds)}` });
  }
  if (referer && !hasHeader(headers, 'referer')) headers.push({ name: 'Referer', value: referer });
  if (compressed && !hasHeader(headers, 'accept-encoding') && !removed.has('accept-encoding')) {
    headers.push({ name: 'Accept-Encoding', value: 'deflate, gzip, br, zstd' });
    notes.push('--compressed: added the Accept-Encoding header curl sends.');
  }
  if (!hasHeader(headers, 'user-agent') && !userAgent && !removed.has('user-agent')) {
    notes.push("No User-Agent given; real curl would send its default 'User-Agent: curl/<version>' (not added).");
  }

  return normalizeRequest({
    method: finalMethod,
    url,
    httpVersion,
    headers,
    body,
    bodyEncoding: 'text',
    source: 'curl',
    notes,
    cookies,
    cookieIndex,
    userAgent,
    contentType,
  }, options);
}

/**
 * Parse one or more curl commands (bash or Windows cmd syntax; auto-detected).
 * Commands that are not curl (e.g. `| jq`) are ignored.
 *
 * @param {string} text
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], errors: string[]}}
 */
export function parseCurl(text, options = {}) {
  const src = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  /** @type {ParsedRequest[]} */
  const requests = [];
  /** @type {string[]} */
  const errors = [];
  let commands;
  try {
    commands = looksLikeCmd(src) ? tokenizeCmd(src) : tokenizeBash(src);
  } catch (e) {
    return { requests, errors: [`curl: ${e.message}`] };
  }
  let n = 0;
  for (const words of commands) {
    // Allow a leading shell prompt ("$ curl ...") and "sudo".
    while (words.length && (words[0] === '$' || words[0] === '>' || words[0] === 'sudo')) words.shift();
    if (!words.length || !/(^|[\\/])curl(\.exe)?$/i.test(words[0])) continue;
    n++;
    try {
      requests.push(curlWordsToRequest(words, options));
    } catch (e) {
      errors.push(`curl command #${n}: ${e.message}`);
    }
  }
  if (!n) errors.push('curl: no curl command found.');
  return { requests, errors };
}
