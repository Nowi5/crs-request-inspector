// Builds the ModSecurity variable collections for one HTTP transaction and implements
// the request body processors (URLENCODED, MULTIPART, JSON, XML).
//
// All values are byte strings (see bytes.js). Collections are arrays of
// { name, value } entries; scalar variables have name ''.

import { utf8ToBinary, binaryToUtf8, base64ToBinary, asciiLower, isValidUtf8 } from './bytes.js';
import { TRANSFORMS } from './transforms.js';

/** Normalise "http/2.0", "h2", "h3" ... to ModSecurity's REQUEST_PROTOCOL format. */
export function normalizeProtocol(v) {
  const raw = String(v || '').trim();
  const s = raw.toLowerCase();
  if (!s) return 'HTTP/1.1';
  // Keep well-formed or unusual protocol strings exactly as sent (e.g. "HTTP/1.1", "HTTP/3.0", "HTTP/1.2").
  if (/^HTTP\/\S*$/.test(raw) && !/^http\/2(\.0)?$/i.test(raw) && !/^http\/3(\.0)?$/i.test(raw)) return raw;
  if (!/^(h2|h2c|h3|h3-.*|http\/.*)$/.test(s)) return raw;
  if (s === 'h2' || s === 'h2c' || s.startsWith('http/2')) return 'HTTP/2.0';
  if (s === 'h3' || s.startsWith('h3-') || s.startsWith('http/3')) return 'HTTP/3.0';
  if (s.startsWith('http/1.0')) return 'HTTP/1.0';
  if (s.startsWith('http/0.9')) return 'HTTP/0.9';
  return 'HTTP/1.1';
}

/** Split an absolute or origin-form URL without normalising it. */
export function splitUrl(url) {
  let rest = String(url);
  let scheme = '', authority = '';
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)/.exec(rest);
  if (m) {
    scheme = m[1].toLowerCase();
    authority = m[2];
    rest = rest.slice(m[0].length);
  }
  const hash = rest.indexOf('#');
  if (hash >= 0) rest = rest.slice(0, hash);
  if (!rest.startsWith('/') && !rest.startsWith('*')) rest = '/' + rest;
  const q = rest.indexOf('?');
  const path = q >= 0 ? rest.slice(0, q) : rest;
  const query = q >= 0 ? rest.slice(q + 1) : null;
  const at = authority.lastIndexOf('@');
  const hostport = at >= 0 ? authority.slice(at + 1) : authority;
  let host = hostport, port = scheme === 'https' ? '443' : '80';
  const pm = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(hostport);
  if (pm) {
    host = pm[1];
    if (pm[2]) port = pm[2];
  }
  return { scheme, authority, host, port, path, query, uri: path + (query !== null ? '?' + query : '') };
}

/** Parse `a=1&b=2` (ModSecurity's parse_arguments): names and values are URL-decoded. */
export function parseUrlencoded(s, separator = '&') {
  const out = [];
  if (!s) return out;
  for (const part of s.split(separator)) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const name = eq >= 0 ? part.slice(0, eq) : part;
    const value = eq >= 0 ? part.slice(eq + 1) : '';
    out.push({ name: TRANSFORMS.urldecode(name), value: TRANSFORMS.urldecode(value) });
  }
  return out;
}

/** Parse the Cookie header(s) (version 0 cookies, like SecCookieFormat 0). */
export function parseCookies(headerValue) {
  const out = [];
  for (const part of headerValue.split(';')) {
    const p = part.replace(/^[ \t]+/, '');
    if (!p) continue;
    const eq = p.indexOf('=');
    const name = eq >= 0 ? p.slice(0, eq) : p;
    const value = eq >= 0 ? p.slice(eq + 1) : '';
    if (!name.trim() && !value) continue;
    out.push({ name: name.replace(/[ \t]+$/, ''), value });
  }
  return out;
}

/**
 * Minimal JSON parser that keeps number lexemes and duplicate keys and emits
 * ModSecurity-style arguments: {"a":{"b":[1,"x"]}} -> json.a.b.0=1, json.a.b.1=x
 * Works on a unicode string; names/values are converted to byte strings.
 */
export function parseJsonArgs(text, { depthLimit = 512, prefix = 'json' } = {}) {
  const args = [];
  let i = 0;
  const n = text.length;
  const ws = () => {
    while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const err = (m) => {
    throw new Error(`JSON parsing error at offset ${i}: ${m}`);
  };
  const str = () => {
    if (text[i] !== '"') err('expected string');
    i++;
    let s = '';
    while (i < n) {
      const c = text[i];
      if (c === '"') {
        i++;
        return s;
      }
      if (c === '\\') {
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': s += '"'; break;
          case '\\': s += '\\'; break;
          case '/': s += '/'; break;
          case 'b': s += '\b'; break;
          case 'f': s += '\f'; break;
          case 'n': s += '\n'; break;
          case 'r': s += '\r'; break;
          case 't': s += '\t'; break;
          case 'u': {
            const h = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) err('bad \\u escape');
            s += String.fromCharCode(parseInt(h, 16));
            i += 4;
            break;
          }
          default:
            err('bad escape');
        }
        continue;
      }
      if (c < ' ') err('control character in string');
      s += c;
      i++;
    }
    err('unterminated string');
  };
  const add = (name, value) => args.push({ name: utf8ToBinary(name), value: utf8ToBinary(value) });
  const value = (path, depth) => {
    if (depth > depthLimit) err('maximum nesting depth exceeded');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      if (text[i] === '}') {
        i++;
        return;
      }
      for (;;) {
        ws();
        const k = str();
        ws();
        if (text[i] !== ':') err("expected ':'");
        i++;
        value(`${path}.${k}`, depth + 1);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return;
        }
        err("expected ',' or '}'");
      }
    } else if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') {
        i++;
        return;
      }
      let idx = 0;
      for (;;) {
        value(`${path}.${idx++}`, depth + 1);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return;
        }
        err("expected ',' or ']'");
      }
    } else if (c === '"') {
      add(path, str());
    } else {
      const m = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 400));
      if (!m) err('unexpected token');
      i += m[0].length;
      add(path, m[0] === 'null' ? '' : m[0]);
    }
  };
  value(prefix, 0);
  ws();
  if (i < n) err('trailing data');
  return args;
}

/** Text content of an XML document (XML:/*) and attribute values (XML://@*). */
export function parseXml(bin) {
  const text = binaryToUtf8(bin);
  const attrs = [];
  let error = null;
  if (!/<[A-Za-z_]/.test(text)) error = 'XML parsing error: no root element';
  const decode = (s) =>
    s.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (m, e) => {
      if (e[0] === '#') {
        const cp = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try {
          return String.fromCodePoint(cp);
        } catch {
          return m;
        }
      }
      return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e];
    });
  let content = '';
  // Linear scanner (indexOf + a sticky tag regex whose parts never cross '<'), so hostile
  // bodies such as '<a<a<a…' or many unterminated '<!--' cannot cause quadratic work.
  const tagRe = /<(\/?)([A-Za-z_][\w.:-]*)((?:[^<>"']|"[^"<]*"|'[^'<]*')*)>/y;
  const n = text.length;
  let depth = 0;
  let seenRoot = false;
  let truncated = false;
  let i = 0;
  const skipTo = (start, close) => {
    const end = text.indexOf(close, start);
    if (end < 0) {
      truncated = true;
      return -1;
    }
    return end;
  };
  while (i < n) {
    const lt = text.indexOf('<', i);
    if (lt < 0) {
      if (depth > 0) content += decode(text.slice(i));
      break;
    }
    if (lt > i && depth > 0) content += decode(text.slice(i, lt));
    if (text.startsWith('<![CDATA[', lt)) {
      const end = skipTo(lt + 9, ']]>');
      if (end < 0) break;
      if (depth > 0) content += text.slice(lt + 9, end);
      i = end + 3;
    } else if (text.startsWith('<!--', lt)) {
      const end = skipTo(lt + 4, '-->');
      if (end < 0) break;
      i = end + 3;
    } else if (text.startsWith('<?', lt)) {
      const end = skipTo(lt + 2, '?>');
      if (end < 0) break;
      i = end + 2;
    } else if (text.startsWith('<!DOCTYPE', lt)) {
      let j = lt + 9;
      while (j < n && text[j] !== '[' && text[j] !== '>') j++;
      if (text[j] === '[') {
        j = skipTo(j + 1, ']');
        if (j < 0) break;
      }
      const end = skipTo(j, '>');
      if (end < 0) break;
      i = end + 1;
    } else {
      tagRe.lastIndex = lt;
      const m = tagRe.exec(text);
      if (!m) {
        i = lt + 1; // stray '<' (ignored, as before)
        continue;
      }
      i = tagRe.lastIndex;
      if (!m[1]) {
        seenRoot = true;
        const attrRe = /([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
        let a;
        while ((a = attrRe.exec(m[3]))) attrs.push({ name: '//@*', value: utf8ToBinary(decode(a[3] ?? a[4])) });
        if (!/\/\s*$/.test(m[3])) depth++;
      } else {
        depth--;
      }
    }
  }
  if (!error && (truncated || !seenRoot || depth !== 0)) error = 'XML parsing error: document is not well-formed';
  return { text: utf8ToBinary(content), attrs, error };
}

/** Multipart/form-data parser loosely following ModSecurity v2's msc_multipart.c checks. */
export function parseMultipart(bin, contentType) {
  const res = {
    args: [], files: [], partHeaders: [], error: null,
    flags: { BOUNDARY_QUOTED: 0, BOUNDARY_WHITESPACE: 0, DATA_BEFORE: 0, DATA_AFTER: 0, HEADER_FOLDING: 0, LF_LINE: 0, CRLF_LF_LINES: 0, MISSING_SEMICOLON: 0, INVALID_QUOTING: 0, INVALID_PART: 0, INVALID_HEADER_FOLDING: 0, FILE_LIMIT_EXCEEDED: 0, UNMATCHED_BOUNDARY: 0, DUPLICATE_PART_HEADER: 0 },
    filesCombinedSize: 0,
  };
  const bm = /boundary\s*=\s*("([^"]*)"|[^;,\s]+)/i.exec(contentType);
  if (!bm) {
    res.error = 'Multipart: Boundary not found in C-T.';
    return res;
  }
  if (bm[2] !== undefined) res.flags.BOUNDARY_QUOTED = 1;
  if (/boundary\s+=|=\s+/i.test(contentType)) res.flags.BOUNDARY_WHITESPACE = 1;
  const boundary = bm[2] ?? bm[1];
  const delim = '--' + boundary;
  // Like msc_multipart.c, a boundary is only recognised at the start of a line (start of the
  // body or right after LF); "--boundary" inside part content is data.
  const segs = [];
  let from = 0;
  for (let p = bin.indexOf(delim); p >= 0; p = bin.indexOf(delim, p + 1)) {
    if (p !== 0 && bin[p - 1] !== '\n') continue;
    segs.push(bin.slice(from, p));
    from = p + delim.length;
  }
  segs.push(bin.slice(from));
  if (segs.length < 2) {
    res.error = 'Multipart: Final boundary missing.';
    return res;
  }
  if (segs[0].replace(/^\r?\n/, '').length && segs[0] !== '') res.flags.DATA_BEFORE = 1;
  let finished = false;
  let sawCrlf = false, sawLf = false;
  for (let k = 1; k < segs.length; k++) {
    let seg = segs[k];
    if (finished) {
      res.flags.DATA_AFTER = 1;
      continue;
    }
    if (seg.startsWith('--')) {
      finished = true;
      if (seg.slice(2).replace(/^\r?\n/, '').trim().length) res.flags.DATA_AFTER = 1;
      continue;
    }
    if (seg.startsWith('\r\n')) { seg = seg.slice(2); sawCrlf = true; }
    else if (seg.startsWith('\n')) { seg = seg.slice(1); sawLf = true; }
    else { res.flags.INVALID_PART = 1; }
    // strip the line break that precedes the next delimiter
    if (seg.endsWith('\r\n')) seg = seg.slice(0, -2);
    else if (seg.endsWith('\n')) { seg = seg.slice(0, -1); sawLf = true; }
    let sep = seg.indexOf('\r\n\r\n');
    let sepLen = 4;
    const lfSep = seg.indexOf('\n\n');
    if (sep < 0 || (lfSep >= 0 && lfSep < sep)) {
      if (lfSep >= 0) { sep = lfSep; sepLen = 2; sawLf = true; }
    }
    if (sep < 0) {
      res.flags.INVALID_PART = 1;
      continue;
    }
    const headerText = seg.slice(0, sep);
    const content = seg.slice(sep + sepLen);
    const lines = headerText.split(/\r?\n/);
    const headers = [];
    for (const line of lines) {
      if (/^[ \t]/.test(line) && headers.length) {
        res.flags.HEADER_FOLDING = 1;
        headers[headers.length - 1] += ' ' + line.trim();
      } else headers.push(line);
    }
    let name = null, filename;
    const seen = new Set();
    for (const h of headers) {
      const hm = /^([^:]+):\s*(.*)$/.exec(h);
      if (!hm) { res.flags.INVALID_PART = 1; continue; }
      const hname = asciiLower(hm[1].trim());
      if (seen.has(hname)) res.flags.DUPLICATE_PART_HEADER = 1;
      seen.add(hname);
      if (hname === 'content-disposition') {
        const v = hm[2];
        if (!/^form-data\s*;/i.test(v)) res.flags.INVALID_PART = 1;
        const nm = /;\s*name\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/i.exec(v);
        if (nm) name = nm[1] ?? nm[2];
        const fm = /;\s*filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/i.exec(v);
        if (fm) filename = fm[1] ?? fm[2];
        if (/name\s*=\s*'/.test(v)) res.flags.INVALID_QUOTING = 1;
        if (/"\s*[a-z]+\s*=/i.test(v.replace(/;\s*/g, ';'))) res.flags.MISSING_SEMICOLON = 1;
      }
    }
    if (name === null) {
      res.flags.INVALID_PART = 1;
      continue;
    }
    for (const h of headers) res.partHeaders.push({ name, value: h });
    if (filename !== undefined) {
      res.files.push({ name, filename, size: content.length, content });
      res.filesCombinedSize += content.length;
    } else {
      res.args.push({ name, value: content });
    }
  }
  if (sawCrlf && sawLf) res.flags.CRLF_LF_LINES = 1;
  if (sawLf) res.flags.LF_LINE = 1;
  if (!finished) res.error = 'Multipart: Final boundary missing.';
  return res;
}

let uniqueCounter = 0;

/**
 * Holds all variables of one transaction.
 */
export class Transaction {
  /**
   * @param {object} req  ParsedRequest (see parsers) — unicode strings
   * @param {object} config engine config (limits, remoteAddr, ...)
   */
  constructor(req, config = {}) {
    this.config = config;
    this.c = new Map(); // collection name -> [{name, value}]
    this.txVars = new Map(); // lowercase -> {name, value}
    this.otherCollections = { IP: new Map(), GLOBAL: new Map(), SESSION: new Map(), USER: new Map(), RESOURCE: new Map() };
    this.matchedVars = [];
    this.matchedVar = null;
    this.reqbodyProcessor = '';
    this.forceRequestBodyVariable = false;
    this.requestBodyAccess = config.requestBodyAccess !== false;
    this.bodyNotes = [];
    this.startTime = Date.now();
    this.currentRule = null;
    this.setRequest(req);
  }

  set(name, values) {
    // ARGS entries remember their source (query string / body) for source-scoped exclusions.
    if (name === 'ARGS_GET') for (const e of values) e.src = 'get';
    else if (name === 'ARGS_POST') for (const e of values) e.src = 'post';
    this.c.set(name, values);
  }

  scalar(name, value) {
    this.c.set(name, [{ name: '', value: value == null ? '' : String(value) }]);
  }

  setRequest(req) {
    const method = String(req.method || 'GET').toUpperCase();
    const protocol = normalizeProtocol(req.httpVersion);
    const u = splitUrl(req.url || '/');
    let uri = utf8ToBinary(u.uri);
    let uriRaw = uri;
    let path = utf8ToBinary(u.path);
    let query = u.query !== null ? utf8ToBinary(u.query) : '';
    if (req.requestTarget != null) {
      // Exact request-target from the request line (raw HTTP input).
      uriRaw = utf8ToBinary(req.requestTarget);
      const rt = splitUrl(req.requestTarget);
      uri = utf8ToBinary(rt.uri);
      path = utf8ToBinary(rt.path);
      query = rt.query !== null ? utf8ToBinary(rt.query) : '';
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(req.requestTarget)) uri = uriRaw;
    }
    this.url = u;
    this.scalar('REQUEST_METHOD', method);
    this.scalar('REQUEST_PROTOCOL', protocol);
    this.scalar('REQUEST_URI', uri);
    this.scalar('REQUEST_URI_RAW', uriRaw);
    this.scalar('REQUEST_LINE', `${method} ${uriRaw} ${protocol}`);
    // REQUEST_FILENAME is the percent-decoded path (no '+' -> space decoding).
    const filename = path.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    this.scalar('REQUEST_FILENAME', filename);
    this.scalar('PATH_INFO', '');
    const slash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
    this.scalar('REQUEST_BASENAME', filename.slice(slash + 1));
    this.scalar('QUERY_STRING', query);

    const sep = this.config.argumentSeparator || '&';
    const argsGet = parseUrlencoded(query, sep);
    this.set('ARGS_GET', argsGet);
    this.set('ARGS_POST', []);

    const headers = (req.headers || []).map((h) => ({ name: utf8ToBinary(h.name), value: utf8ToBinary(h.value) }));
    this.set('REQUEST_HEADERS', headers);
    const cookies = [];
    for (const h of headers) if (asciiLower(h.name) === 'cookie') cookies.push(...parseCookies(h.value));
    this.set('REQUEST_COOKIES', cookies);

    const hostHeader = headers.find((h) => asciiLower(h.name) === 'host');
    this.scalar('SERVER_NAME', hostHeader ? hostHeader.value.replace(/:\d+$/, '') : u.host);
    this.scalar('SERVER_PORT', u.port);
    this.scalar('SERVER_ADDR', this.config.serverAddr || '192.0.2.10');
    this.scalar('REMOTE_ADDR', this.config.remoteAddr || '203.0.113.10');
    this.scalar('REMOTE_HOST', this.config.remoteAddr || '203.0.113.10');
    this.scalar('REMOTE_PORT', '51234');
    this.scalar('REMOTE_USER', '');
    this.scalar('AUTH_TYPE', '');
    this.scalar('UNIQUE_ID', `${Date.now().toString(36)}${(uniqueCounter++).toString(36)}${Math.random().toString(36).slice(2, 10)}`);
    this.scalar('REQBODY_ERROR', '0');
    this.scalar('REQBODY_ERROR_MSG', '');
    this.scalar('REQBODY_PROCESSOR_ERROR', '0');
    this.scalar('REQBODY_PROCESSOR_ERROR_MSG', '');
    this.scalar('URLENCODED_ERROR', '0');
    this.scalar('INBOUND_DATA_ERROR', '0');
    this.scalar('OUTBOUND_DATA_ERROR', '0');
    this.scalar('HIGHEST_SEVERITY', '255');
    this.scalar('WEBAPPID', 'default');
    this.scalar('SESSIONID', '');
    this.scalar('USERID', '');
    for (const f of ['FILES', 'FILES_NAMES', 'FILES_SIZES', 'FILES_TMPNAMES', 'FILES_TMP_CONTENT', 'MULTIPART_PART_HEADERS', 'MULTIPART_FILENAME', 'MULTIPART_NAME', 'XML', 'ENV', 'GEO', 'RESPONSE_HEADERS']) this.set(f, []);
    this.scalar('FILES_COMBINED_SIZE', '0');
    for (const f of ['BOUNDARY_QUOTED', 'BOUNDARY_WHITESPACE', 'DATA_AFTER', 'DATA_BEFORE', 'HEADER_FOLDING', 'LF_LINE', 'CRLF_LF_LINES', 'MISSING_SEMICOLON', 'INVALID_QUOTING', 'INVALID_PART', 'INVALID_HEADER_FOLDING', 'FILE_LIMIT_EXCEEDED', 'STRICT_ERROR', 'UNMATCHED_BOUNDARY', 'DUPLICATE_PART_HEADER']) this.scalar('MULTIPART_' + f, '0');

    // Body
    let body = '';
    if (req.body != null) body = req.bodyEncoding === 'base64' ? base64ToBinary(req.body) : utf8ToBinary(req.body);
    this.body = body;
    this.scalar('REQUEST_BODY_LENGTH', String(body.length));
    this.set('REQUEST_BODY', []);

    const ct = headers.find((h) => asciiLower(h.name) === 'content-type');
    this.contentType = ct ? ct.value : '';
    const ctl = asciiLower(this.contentType);
    if (ctl.startsWith('application/x-www-form-urlencoded')) this.reqbodyProcessor = 'URLENCODED';
    else if (ctl.startsWith('multipart/form-data')) this.reqbodyProcessor = 'MULTIPART';

    const headerLines = headers.map((h) => `${h.name}: ${h.value}`).join('\r\n');
    const full = `${method} ${uri} ${protocol}\r\n${headerLines}\r\n\r\n${body}`;
    this.scalar('FULL_REQUEST', full);
    this.scalar('FULL_REQUEST_LENGTH', String(full.length));

    // Response (phases 3/4)
    this.response = req.response || null;
  }

  /** Request body processing (run before phase 2). */
  processRequestBody() {
    const body = this.body;
    const proc = this.reqbodyProcessor;
    this.bodyProcessed = true;
    if (!this.requestBodyAccess) {
      this.bodyNotes.push('Request body access is disabled (ctl:requestBodyAccess=Off).');
      return;
    }
    const setError = (msg) => {
      this.scalar('REQBODY_ERROR', '1');
      this.scalar('REQBODY_ERROR_MSG', msg);
      this.scalar('REQBODY_PROCESSOR_ERROR', '1');
      this.scalar('REQBODY_PROCESSOR_ERROR_MSG', msg);
      this.bodyNotes.push(msg);
    };
    if (body.length) {
      if (proc === 'URLENCODED') {
        this.set('ARGS_POST', parseUrlencoded(body, this.config.argumentSeparator || '&'));
        this.set('REQUEST_BODY', [{ name: '', value: body }]);
      } else if (proc === 'JSON') {
        const text = binaryToUtf8(body);
        if (!isValidUtf8(body)) this.bodyNotes.push('JSON body is not valid UTF-8.');
        // REQUEST_BODY is also available for JSON bodies (libmodsecurity v3 / Coraza behaviour;
        // the CRS regression tests rely on it, e.g. 934210).
        this.set('REQUEST_BODY', [{ name: '', value: body }]);
        try {
          this.set('ARGS_POST', parseJsonArgs(text, { depthLimit: this.config.jsonDepthLimit || 512 }));
        } catch (e) {
          setError(e.message);
        }
      } else if (proc === 'MULTIPART') {
        const mp = parseMultipart(body, this.contentType);
        this.set('ARGS_POST', mp.args);
        this.set('FILES', mp.files.map((f) => ({ name: f.name, value: f.filename })));
        this.set('FILES_NAMES', mp.files.map((f) => ({ name: f.name, value: f.name })));
        this.set('FILES_SIZES', mp.files.map((f) => ({ name: f.name, value: String(f.size) })));
        this.set('FILES_TMP_CONTENT', mp.files.map((f) => ({ name: f.name, value: f.content })));
        this.set('MULTIPART_FILENAME', mp.files.map((f) => ({ name: f.name, value: f.filename })));
        this.set('MULTIPART_NAME', [...mp.args.map((a) => ({ name: a.name, value: a.name })), ...mp.files.map((f) => ({ name: f.name, value: f.name }))]);
        this.set('MULTIPART_PART_HEADERS', mp.partHeaders);
        this.scalar('FILES_COMBINED_SIZE', String(mp.filesCombinedSize));
        let strict = 0;
        for (const [k, v] of Object.entries(mp.flags)) {
          this.scalar('MULTIPART_' + k, String(v));
          if (v && k !== 'UNMATCHED_BOUNDARY' && k !== 'FILE_LIMIT_EXCEEDED') strict = 1;
        }
        if (mp.error) {
          setError(mp.error);
          strict = 1;
        }
        this.scalar('MULTIPART_STRICT_ERROR', String(strict));
        this.multipartFilesSize = mp.filesCombinedSize;
      } else if (proc === 'XML') {
        const x = parseXml(body);
        this.set('XML', [{ name: '/*', value: x.text }, ...x.attrs]);
        if (x.error) setError(x.error);
      }
      if (!proc && this.forceRequestBodyVariable) this.set('REQUEST_BODY', [{ name: '', value: body }]);
    }
  }

  setResponse() {
    const r = this.response;
    if (!r) return false;
    const headers = (r.headers || []).map((h) => ({ name: utf8ToBinary(h.name), value: utf8ToBinary(h.value) }));
    this.set('RESPONSE_HEADERS', headers);
    this.scalar('RESPONSE_STATUS', String(r.status ?? ''));
    this.scalar('RESPONSE_PROTOCOL', normalizeProtocol(r.httpVersion));
    this.scalar('STATUS_LINE', `${normalizeProtocol(r.httpVersion)} ${r.status} ${r.statusText || ''}`.trim());
    const ct = headers.find((h) => asciiLower(h.name) === 'content-type');
    this.scalar('RESPONSE_CONTENT_TYPE', ct ? ct.value : r.mimeType || '');
    const cl = headers.find((h) => asciiLower(h.name) === 'content-length');
    let body = '';
    if (r.body != null) body = r.bodyEncoding === 'base64' ? base64ToBinary(r.body) : utf8ToBinary(r.body);
    this.scalar('RESPONSE_CONTENT_LENGTH', cl ? cl.value : String(body.length));
    const mime = asciiLower((ct ? ct.value : r.mimeType || '').split(';')[0].trim());
    const allowed = this.config.responseBodyMimeTypes || ['text/plain', 'text/html', 'text/xml'];
    if (body && allowed.includes(mime)) {
      const limit = this.config.responseBodyLimit || 524288;
      this.set('RESPONSE_BODY', [{ name: '', value: body.slice(0, limit) }]);
      this.responseBodyInspected = true;
    } else {
      this.set('RESPONSE_BODY', []);
      this.responseBodyInspected = false;
      this.responseBodySkipReason = !body ? 'no response body available' : `response MIME type "${mime}" is not in SecResponseBodyMimeType`;
    }
    return true;
  }

  // ---- TX / macros ---------------------------------------------------------

  getTx(name) {
    return this.txVars.get(asciiLower(name))?.value;
  }

  setTx(name, value) {
    this.txVars.set(asciiLower(name), { name, value: String(value) });
  }

  delTx(name) {
    this.txVars.delete(asciiLower(name));
  }

  /** Return the entries of a collection (unfiltered). */
  collection(name) {
    switch (name) {
      case 'TX':
        return [...this.txVars.values()];
      case 'ARGS':
        return [...this.c.get('ARGS_GET'), ...this.c.get('ARGS_POST')];
      case 'ARGS_NAMES':
        return this.collection('ARGS').map((a) => ({ name: a.name, value: a.name, src: a.src }));
      case 'ARGS_GET_NAMES':
        return this.c.get('ARGS_GET').map((a) => ({ name: a.name, value: a.name, src: 'get' }));
      case 'ARGS_POST_NAMES':
        return this.c.get('ARGS_POST').map((a) => ({ name: a.name, value: a.name, src: 'post' }));
      case 'ARGS_COMBINED_SIZE': {
        let n = 0;
        for (const a of this.collection('ARGS')) n += a.name.length + a.value.length;
        return [{ name: '', value: String(n) }];
      }
      case 'REQUEST_HEADERS_NAMES':
        return this.c.get('REQUEST_HEADERS').map((h) => ({ name: h.name, value: h.name }));
      case 'RESPONSE_HEADERS_NAMES':
        return (this.c.get('RESPONSE_HEADERS') || []).map((h) => ({ name: h.name, value: h.name }));
      case 'REQUEST_COOKIES_NAMES':
        return this.c.get('REQUEST_COOKIES').map((h) => ({ name: h.name, value: h.name }));
      case 'MATCHED_VAR':
        return this.matchedVar ? [{ name: '', value: this.matchedVar.value }] : [];
      case 'MATCHED_VAR_NAME':
        return this.matchedVar ? [{ name: '', value: this.matchedVar.name }] : [];
      case 'MATCHED_VARS':
        return this.matchedVars.map((m) => ({ name: m.name, value: m.value }));
      case 'MATCHED_VARS_NAMES':
        return this.matchedVars.map((m) => ({ name: m.name, value: m.name }));
      case 'REQBODY_PROCESSOR':
        return [{ name: '', value: this.reqbodyProcessor }];
      case 'DURATION':
        return [{ name: '', value: String((Date.now() - this.startTime) * 1000) }];
      case 'TIME':
      case 'TIME_EPOCH':
      case 'TIME_YEAR':
      case 'TIME_MON':
      case 'TIME_DAY':
      case 'TIME_HOUR':
      case 'TIME_MIN':
      case 'TIME_SEC':
      case 'TIME_WDAY': {
        const d = new Date();
        const map = {
          TIME: d.toTimeString().slice(0, 8),
          TIME_EPOCH: String(Math.floor(d.getTime() / 1000)),
          TIME_YEAR: String(d.getFullYear()),
          TIME_MON: String(d.getMonth() + 1),
          TIME_DAY: String(d.getDate()),
          TIME_HOUR: String(d.getHours()),
          TIME_MIN: String(d.getMinutes()),
          TIME_SEC: String(d.getSeconds()),
          TIME_WDAY: String(d.getDay()),
        };
        return [{ name: '', value: map[name] }];
      }
      case 'RULE': {
        const r = this.currentRule;
        if (!r) return [];
        return [
          { name: 'id', value: String(r.id ?? '') },
          { name: 'msg', value: r.msg ?? '' },
          { name: 'severity', value: r.severity != null ? String(r.severity) : '' },
          { name: 'ver', value: r.ver ?? '' },
          { name: 'rev', value: r.rev ?? '' },
          { name: 'logdata', value: r.logdata ?? '' },
          { name: 'phase', value: String(r.phase) },
        ];
      }
      case 'IP':
      case 'GLOBAL':
      case 'SESSION':
      case 'USER':
      case 'RESOURCE':
        return [...this.otherCollections[name].values()];
      default:
        return this.c.get(name);
    }
  }

  /** Expand %{collection.key} macros. */
  expand(str) {
    if (str == null || str.indexOf('%{') < 0) return str;
    return str.replace(/%\{([^}]+)\}/g, (m, ref) => {
      const sepIdx = ref.search(/[.:]/);
      const coll = (sepIdx >= 0 ? ref.slice(0, sepIdx) : ref).toUpperCase();
      const key = sepIdx >= 0 ? ref.slice(sepIdx + 1) : null;
      if (coll === 'TX' && key !== null) return this.getTx(key) ?? '';
      const entries = this.collection(coll);
      if (!entries) return '';
      if (key === null) return entries[0]?.value ?? '';
      const lk = asciiLower(key);
      const e = entries.find((x) => asciiLower(x.name) === lk);
      return e ? e.value : '';
    });
  }
}
