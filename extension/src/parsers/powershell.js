/**
 * Parser for PowerShell `Invoke-WebRequest` / `Invoke-RestMethod` commands, including
 * Chrome DevTools "Copy as PowerShell" and "Copy all as PowerShell" output.
 *
 * This is a small interpreter for the subset of PowerShell those exports (and typical
 * hand-written commands) use: statements separated by newlines/`;`, backtick line
 * continuation, comments, variables and member assignment, expandable/verbatim strings and
 * here-strings, hashtables, arrays, `$(...)` subexpressions, casts such as `[char]252`,
 * static calls such as `[System.Text.Encoding]::UTF8.GetBytes(...)`, `New-Object` for
 * `WebRequestSession` and `System.Net.Cookie`, `ConvertTo-Json`, and the web cmdlets.
 * Nothing is executed for real; unknown constructs produce notes or errors.
 *
 * @module parsers/powershell
 */

import { normalizeRequest } from './normalize.js';
import {
  splitUrl, domainMatches, pathMatches, appendQuery, formUrlEncode, mapHttpVersion,
  findHeaderIndex, hasHeader, utf8ToBase64, utf16leToBase64, buildMultipartBody, randomHex, ellipsis,
} from './util.js';

/** @typedef {import('./types.js').ParsedRequest} ParsedRequest */
/** @typedef {import('./types.js').ParseOptions} ParseOptions */
/** @typedef {import('./types.js').Header} Header */

// PowerShell accepts typographic quotes and dashes as well (text pasted from Word/Teams).
const DQ = new Set(['"', '“', '”', '„']);
const SQ = new Set(["'", '‘', '’', '‚', '‛']);
const DASH = new Set(['-', '–', '—', '―']);

const isLetter = (c) => c !== undefined && /[A-Za-z_]/.test(c);
const isDigit = (c) => c !== undefined && c >= '0' && c <= '9';
const isIdentChar = (c) => c !== undefined && /[A-Za-z0-9_]/.test(c);
const isBlank = (c) => c === ' ' || c === '\t' || c === '\f' || c === '\v' || c === ' ';

class PsError extends Error {}

/** Parameters of Invoke-WebRequest / Invoke-RestMethod (Windows PowerShell 5.1 + pwsh 7). */
const WEB_PARAMS = [
  'Uri', 'Method', 'Headers', 'Body', 'ContentType', 'UserAgent', 'WebSession', 'SessionVariable',
  'UseBasicParsing', 'InFile', 'OutFile', 'Credential', 'UseDefaultCredentials', 'CertificateThumbprint',
  'Certificate', 'DisableKeepAlive', 'TimeoutSec', 'MaximumRedirection', 'Proxy', 'ProxyCredential',
  'ProxyUseDefaultCredentials', 'TransferEncoding', 'PassThru', 'SkipCertificateCheck', 'SkipHeaderValidation',
  'Authentication', 'Token', 'Form', 'HttpVersion', 'SslProtocol', 'NoProxy', 'PreserveAuthorizationOnRedirect',
  'Resume', 'CustomMethod', 'FollowRelLink', 'MaximumFollowRelLink', 'ResponseHeadersVariable',
  'StatusCodeVariable', 'SkipHttpErrorCheck', 'AllowUnencryptedAuthentication', 'RetryIntervalSec',
  'MaximumRetryCount', 'ConnectionTimeoutSeconds', 'OperationTimeoutSeconds', 'AllowInsecureRedirect',
  'PreserveHttpMethodOnRedirect', 'UnixSocket', 'ErrorAction', 'ErrorVariable', 'WarningAction',
  'InformationAction', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction', 'Verbose', 'Debug',
];
const WEB_SWITCHES = new Set([
  'UseBasicParsing', 'UseDefaultCredentials', 'DisableKeepAlive', 'ProxyUseDefaultCredentials', 'PassThru',
  'SkipCertificateCheck', 'SkipHeaderValidation', 'NoProxy', 'PreserveAuthorizationOnRedirect', 'Resume',
  'FollowRelLink', 'SkipHttpErrorCheck', 'AllowUnencryptedAuthentication', 'AllowInsecureRedirect',
  'PreserveHttpMethodOnRedirect', 'Verbose', 'Debug',
]);
/** Preferred resolution for ambiguous abbreviations such as `-M` or `-H`. */
const WEB_PRIORITY = ['Uri', 'Method', 'Headers', 'Body', 'ContentType', 'UserAgent', 'WebSession'];

const NEW_OBJECT_PARAMS = ['TypeName', 'ArgumentList', 'Property', 'ComObject', 'Strict'];

const WEB_CMDLETS = new Set([
  'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm',
  'microsoft.powershell.utility\\invoke-webrequest', 'microsoft.powershell.utility\\invoke-restmethod',
]);
const SILENT_CMDLETS = new Set([
  'out-null', 'write-host', 'write-output', 'select-object', 'format-list', 'format-table', 'out-file',
  'out-string', 'set-content', 'add-content', 'tee-object', 'select', 'ft', 'fl', 'echo', 'write-verbose',
  'convertfrom-json', 'out-host', 'clear-host', 'cls', 'start-sleep', 'sleep', 'foreach-object', 'where-object',
  'set-strictmode', 'import-module', 'add-type',
]);

// --------------------------------------------------------------------------------------
// Runtime values
// --------------------------------------------------------------------------------------

/** Ordered, case-insensitive-lookup hashtable. */
class PsHashtable {
  constructor() {
    /** @type {Array<[string, any]>} */
    this.entries = [];
  }
  get(key) {
    const lk = String(key).toLowerCase();
    for (let i = this.entries.length - 1; i >= 0; i--) if (this.entries[i][0].toLowerCase() === lk) return this.entries[i][1];
    return undefined;
  }
  set(key, value) {
    const lk = String(key).toLowerCase();
    const e = this.entries.find(([k]) => k.toLowerCase() === lk);
    if (e) e[1] = value;
    else this.entries.push([String(key), value]);
  }
}

class PsSession {
  constructor() {
    /** @type {string|null} */
    this.userAgent = null;
    /** @type {PsCookie[]} */
    this.cookies = [];
    /** @type {Array<[string,string]>} */
    this.headers = [];
  }
}

class PsCookie {
  constructor(name = '', value = '', path = '/', domain = '') {
    this.name = name;
    this.value = value;
    this.path = path;
    this.domain = domain;
  }
}

/** Encoded byte array produced by `[Text.Encoding]::X.GetBytes(...)` or `[Convert]::FromBase64String(...)`. */
class PsBytes {
  /**
   * @param {string} data
   * @param {'text'|'base64'} encoding
   */
  constructor(data, encoding) {
    this.data = data;
    this.encoding = encoding;
  }
}

class PsEncoding {
  constructor(name) {
    this.name = name;
  }
}

/** Member access proxies (`$session.Cookies`, `$session.Headers`). */
class PsMemberRef {
  constructor(kind, owner) {
    this.kind = kind;
    this.owner = owner;
  }
}

class PsTypeRef {
  constructor(name) {
    this.name = name;
  }
}

/** Placeholder for things we cannot evaluate (e.g. a web response). */
class PsOpaque {
  constructor(desc) {
    this.desc = desc;
  }
}

/**
 * Convert a runtime value to a string the way PowerShell would (roughly).
 * @param {any} v
 * @returns {string}
 */
function toStr(v) {
  if (v === undefined || v === null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  if (typeof v === 'boolean') return v ? 'True' : 'False';
  if (Array.isArray(v)) return v.map(toStr).join(' ');
  if (v instanceof PsBytes) return v.encoding === 'text' ? v.data : atob(v.data);
  if (v instanceof PsHashtable) return 'System.Collections.Hashtable';
  if (v instanceof PsCookie) return `${v.name}=${v.value}`;
  if (v instanceof PsTypeRef) return v.name;
  if (v instanceof PsOpaque) return '';
  return String(v);
}

const normTypeName = (t) => t.replace(/\s+/g, '').toLowerCase().replace(/^system\./, '');

// --------------------------------------------------------------------------------------
// Interpreter
// --------------------------------------------------------------------------------------

class PsInterpreter {
  /**
   * @param {string} src
   * @param {ParseOptions} options
   */
  constructor(src, options) {
    this.src = src;
    this.pos = 0;
    this.options = options;
    /** @type {Map<string, any>} */
    this.vars = new Map();
    /** @type {ParsedRequest[]} */
    this.requests = [];
    /** @type {string[]} */
    this.errors = [];
    /** Notes collected while evaluating; attached to the next request. */
    this.pendingNotes = [];
    this.webCallCount = 0;
  }

  // ---- low level scanning -------------------------------------------------------

  peek(o = 0) {
    return this.src[this.pos + o];
  }
  eof() {
    return this.pos >= this.src.length;
  }
  snippet(from) {
    return ellipsis(this.src.slice(from, from + 50), 50);
  }
  note(msg) {
    if (!this.pendingNotes.includes(msg)) this.pendingNotes.push(msg);
  }
  expect(ch) {
    if (this.peek() !== ch) throw new PsError(`Expected '${ch}' but found ${this.eof() ? 'end of input' : `'${this.peek()}'`}`);
    this.pos++;
  }

  /** True when a backtick at pos starts a line continuation (backtick, optional blanks, newline). */
  isContinuation(at = this.pos) {
    if (this.src[at] !== '`') return false;
    let j = at + 1;
    while (isBlank(this.src[j])) j++;
    return this.src[j] === '\n' || j >= this.src.length;
  }

  /**
   * Skip blanks, comments and line continuations; with `newlines`, newlines too.
   * @param {boolean} newlines
   */
  skipWs(newlines) {
    for (;;) {
      const c = this.peek();
      if (isBlank(c) || c === '\r') this.pos++;
      else if (c === '\n' && newlines) this.pos++;
      else if (c === '`' && this.isContinuation()) {
        this.pos++;
        while (isBlank(this.peek())) this.pos++;
        if (this.peek() === '\n') this.pos++;
      } else if (c === '<' && this.peek(1) === '#') {
        const end = this.src.indexOf('#>', this.pos + 2);
        this.pos = end < 0 ? this.src.length : end + 2;
      } else if (c === '#') {
        while (!this.eof() && this.peek() !== '\n') this.pos++;
      } else break;
    }
  }

  /** Skip to the end of the current statement (error recovery). */
  skipStatement() {
    let depth = 0;
    while (!this.eof()) {
      const c = this.peek();
      if (c === '`') {
        this.pos += 2;
        continue;
      }
      if (DQ.has(c) || SQ.has(c)) {
        const closers = DQ.has(c) ? DQ : SQ;
        this.pos++;
        while (!this.eof() && !closers.has(this.peek())) this.pos += this.peek() === '`' && DQ.has(c) ? 2 : 1;
        this.pos++;
        continue;
      }
      if (c === '{' || c === '(') depth++;
      else if (c === '}' || c === ')') depth = Math.max(0, depth - 1);
      else if ((c === '\n' || c === ';') && depth === 0) return;
      this.pos++;
    }
  }

  readIdent() {
    const start = this.pos;
    while (isIdentChar(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  // ---- script / statements --------------------------------------------------------

  run() {
    for (;;) {
      this.skipWs(true);
      while (this.peek() === ';') {
        this.pos++;
        this.skipWs(true);
      }
      if (this.eof()) break;
      const start = this.pos;
      try {
        this.parseStatement();
      } catch (e) {
        if (!(e instanceof PsError) && !(e instanceof Error)) throw e;
        this.errors.push(`PowerShell: ${e.message} (near "${this.snippet(start)}")`);
        this.skipStatement();
      }
      if (this.pos === start) this.pos++;
    }
  }

  /**
   * Parse and evaluate one statement; returns its value.
   * @returns {any}
   */
  parseStatement() {
    if (this.peek() === '$') {
      const save = this.pos;
      const target = this.tryAssignmentTarget();
      if (target) {
        this.pos++; // '='
        this.skipWs(true);
        const value = this.parsePipeline();
        this.assign(target, value);
        return undefined;
      }
      this.pos = save;
    }
    return this.parsePipeline();
  }

  /**
   * If the input at pos is `$name(.Prop)* =` (not `==`), return the target, else null.
   * @returns {{name: string, props: string[]}|null}
   */
  tryAssignmentTarget() {
    this.pos++; // '$'
    let name;
    if (this.peek() === '{') {
      const end = this.src.indexOf('}', this.pos);
      if (end < 0) return null;
      name = this.src.slice(this.pos + 1, end);
      this.pos = end + 1;
    } else {
      name = this.readVarName();
      if (!name) return null;
    }
    const props = [];
    while (this.peek() === '.' && isLetter(this.peek(1))) {
      this.pos++;
      props.push(this.readIdent());
    }
    this.skipWs(false);
    if (this.peek() === '=' && this.peek(1) !== '=') return { name, props };
    // Compound assignment such as += is handled leniently as concatenation.
    if (this.peek() === '+' && this.peek(1) === '=') {
      this.pos++;
      return { name, props, append: true };
    }
    return null;
  }

  readVarName() {
    let name = this.readIdent();
    if (this.peek() === ':' && isLetter(this.peek(1)) && /^(env|global|script|local|private|variable|using)$/i.test(name)) {
      this.pos++;
      name += ':' + this.readIdent();
    }
    return name;
  }

  /**
   * @param {{name: string, props: string[], append?: boolean}} target
   * @param {any} value
   */
  assign(target, value) {
    const varName = target.name.replace(/^(global|script|local|private|variable|using):/i, '').toLowerCase();
    if (!target.props.length) {
      if (target.append) value = this.add(this.vars.get(varName), value);
      this.vars.set(varName, value);
      return;
    }
    let obj = this.lookupVar(target.name);
    for (const p of target.props.slice(0, -1)) obj = this.getMember(obj, p);
    const last = target.props[target.props.length - 1];
    if (target.append) value = this.add(this.getMember(obj, last), value);
    this.setMember(obj, last, value);
  }

  /**
   * pipeline := (command | expression) ('|' command)*
   * @returns {any}
   */
  parsePipeline() {
    this.skipWs(false);
    let value;
    const c = this.peek();
    if (isLetter(c) || ((c === '&' || c === '.') && isBlank(this.peek(1)))) value = this.parseCommand(undefined);
    else value = this.parseExpression();
    for (;;) {
      this.skipWs(false);
      if (this.peek() === '|' && this.peek(1) !== '|') {
        this.pos++;
        this.skipWs(true);
        value = this.parseCommand(value);
      } else if ((this.peek() === '&' && this.peek(1) === '&') || (this.peek() === '|' && this.peek(1) === '|')) {
        // pwsh 7 pipeline chain operators: treat the right side as another statement.
        this.pos += 2;
        this.skipWs(true);
        value = this.parsePipeline();
      } else break;
    }
    return value;
  }

  // ---- expressions --------------------------------------------------------------

  /** expression := binary (',' binary)* */
  parseExpression() {
    const first = this.parseBinary();
    this.skipWs(false);
    if (this.peek() !== ',') return first;
    const items = [first];
    while (this.peek() === ',') {
      this.pos++;
      this.skipWs(true);
      items.push(this.parseBinary());
      this.skipWs(false);
    }
    return items;
  }

  /** binary := unary (('+' unary) | ('-f' expression) | ('-join' unary))* */
  parseBinary() {
    let left = this.parseUnary();
    for (;;) {
      const save = this.pos;
      this.skipWs(false);
      const c = this.peek();
      if (c === '+' && this.peek(1) !== '=') {
        this.pos++;
        this.skipWs(true);
        left = this.add(left, this.parseUnary());
        continue;
      }
      if (DASH.has(c)) {
        const m = /^-(f|join|replace)(?![A-Za-z0-9_])/i.exec(this.src.slice(this.pos, this.pos + 10));
        if (m) {
          this.pos += m[0].length;
          this.skipWs(true);
          const op = m[1].toLowerCase();
          if (op === 'f') {
            const args = this.parseUnary();
            const rest = [args];
            this.skipWs(false);
            while (this.peek() === ',') {
              this.pos++;
              this.skipWs(true);
              rest.push(this.parseUnary());
              this.skipWs(false);
            }
            const list = rest.length === 1 && Array.isArray(args) ? args : rest;
            left = toStr(left).replace(/\{(\d+)(?:[,:][^}]*)?\}/g, (_, i) => toStr(list[Number(i)]));
          } else if (op === 'join') {
            const sep = toStr(this.parseUnary());
            left = (Array.isArray(left) ? left : [left]).map(toStr).join(sep);
          } else {
            const args = this.parseExpression();
            const [pat, rep] = Array.isArray(args) ? args : [args, ''];
            try {
              left = toStr(left).replace(new RegExp(toStr(pat), 'gi'), toStr(rep).replace(/\$(\d)/g, '$$$1'));
            } catch {
              this.note('Could not evaluate a -replace expression.');
            }
          }
          continue;
        }
      }
      this.pos = save;
      return left;
    }
  }

  add(a, b) {
    if (a === undefined || a === null) return b;
    if (typeof a === 'number' && typeof b === 'number') return a + b;
    if (Array.isArray(a)) return a.concat(Array.isArray(b) ? b : [b]);
    if (a instanceof PsHashtable && b instanceof PsHashtable) {
      const h = new PsHashtable();
      for (const [k, v] of a.entries) h.set(k, v);
      for (const [k, v] of b.entries) h.set(k, v);
      return h;
    }
    return toStr(a) + toStr(b);
  }

  parseUnary() {
    this.skipWs(false);
    const c = this.peek();
    if (c === '[') return this.parseTypeExpression();
    if (DASH.has(c) && (isDigit(this.peek(1)) || this.peek(1) === '.')) {
      this.pos++;
      return -Number(this.parseNumber());
    }
    if (c === '!') {
      this.pos++;
      return !this.parseUnary();
    }
    return this.parsePostfix(this.parsePrimary());
  }

  parsePrimary() {
    const c = this.peek();
    const n = this.peek(1);
    if (DQ.has(c)) return this.parseDQString();
    if (SQ.has(c)) return this.parseSQString();
    if (c === '@') {
      if (DQ.has(n) || SQ.has(n)) return this.parseHereString();
      if (n === '{') return this.parseHashtable();
      if (n === '(') {
        this.pos += 2;
        const v = this.parseStatementList(')');
        return v === undefined || v === null ? [] : Array.isArray(v) ? v : [v];
      }
    }
    if (c === '$') {
      if (n === '(') {
        this.pos += 2;
        return this.parseStatementList(')');
      }
      return this.parseVariable();
    }
    if (c === '(') {
      this.pos++;
      this.skipWs(true);
      const v = this.parseStatement();
      this.skipWs(true);
      this.expect(')');
      return v;
    }
    if (isDigit(c) || (c === '.' && isDigit(n))) return this.parseNumber();
    if (isLetter(c)) return this.parseCommand(undefined);
    if (c === '{') {
      // Script block: not evaluated.
      const start = this.pos;
      this.skipBalanced('{', '}');
      return new PsOpaque(`script block ${this.snippet(start)}`);
    }
    throw new PsError(this.eof() ? 'Unexpected end of input' : `Unexpected character '${c}'`);
  }

  skipBalanced(open, close) {
    let depth = 0;
    while (!this.eof()) {
      const c = this.peek();
      if (DQ.has(c)) {
        this.parseDQString();
        continue;
      }
      if (SQ.has(c)) {
        this.parseSQString();
        continue;
      }
      this.pos++;
      if (c === open) depth++;
      else if (c === close && --depth === 0) return;
    }
  }

  /**
   * Parse statements until `close`; returns the last value (or array of non-null values).
   * @param {string} close
   */
  parseStatementList(close) {
    const values = [];
    for (;;) {
      this.skipWs(true);
      while (this.peek() === ';') {
        this.pos++;
        this.skipWs(true);
      }
      if (this.peek() === close) {
        this.pos++;
        break;
      }
      if (this.eof()) throw new PsError(`Missing closing '${close}'`);
      const start = this.pos;
      const v = this.parseStatement();
      if (v !== undefined && v !== null) values.push(v);
      if (this.pos === start) throw new PsError(`Unexpected character '${this.peek()}'`);
    }
    if (values.length === 0) return null;
    return values.length === 1 ? values[0] : values;
  }

  parseNumber() {
    const m = /^(0x[0-9a-fA-F]+|\d*\.?\d+(?:e[+-]?\d+)?)(kb|mb|gb|tb|pb|[lLdD])?/.exec(this.src.slice(this.pos, this.pos + 40));
    if (!m) throw new PsError('Invalid number');
    this.pos += m[0].length;
    let v = m[1].toLowerCase().startsWith('0x') ? parseInt(m[1], 16) : Number(m[1]);
    const mult = { kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4, pb: 1024 ** 5 }[m[2]?.toLowerCase()];
    if (mult) v *= mult;
    return v;
  }

  parseVariable() {
    this.pos++; // '$'
    let name;
    if (this.peek() === '{') {
      const end = this.src.indexOf('}', this.pos);
      if (end < 0) throw new PsError('Unterminated ${...} variable');
      name = this.src.slice(this.pos + 1, end);
      this.pos = end + 1;
    } else {
      name = this.readVarName();
      if (!name) {
        const special = this.peek();
        if (special === '_' || special === '?' || special === '$' || special === '^') {
          this.pos++;
          return null;
        }
        return '$';
      }
    }
    return this.lookupVar(name);
  }

  lookupVar(name) {
    const lower = name.replace(/^(global|script|local|private|variable|using):/i, '').toLowerCase();
    if (lower === 'true') return true;
    if (lower === 'false') return false;
    if (lower === 'null') return null;
    if (lower.startsWith('env:')) {
      this.note(`Environment variable $${name} is not available; treated as empty.`);
      return '';
    }
    if (this.vars.has(lower)) return this.vars.get(lower);
    if (lower === 'psversiontable' || lower === 'pwd' || lower === 'home') return '';
    this.note(`Variable $${name} is not defined in the pasted script; treated as empty.`);
    return null;
  }

  /**
   * Member access, method calls and indexing directly following a value.
   * @param {any} value
   */
  parsePostfix(value) {
    for (;;) {
      const c = this.peek();
      if (c === '.' && isLetter(this.peek(1))) {
        this.pos++;
        const name = this.readIdent();
        if (this.peek() === '(') value = this.callMethod(value, name, this.parseCallArgs());
        else value = this.getMember(value, name);
        continue;
      }
      if (c === ':' && this.peek(1) === ':' && isLetter(this.peek(2))) {
        this.pos += 2;
        const name = this.readIdent();
        const type = value instanceof PsTypeRef ? value.name : '';
        if (this.peek() === '(') value = this.callStatic(type, name, this.parseCallArgs());
        else value = this.getStatic(type, name);
        continue;
      }
      if (c === '[' && value !== undefined) {
        this.pos++;
        this.skipWs(true);
        const idx = this.parseExpression();
        this.skipWs(true);
        this.expect(']');
        if (Array.isArray(value)) value = value[Number(idx) < 0 ? value.length + Number(idx) : Number(idx)];
        else if (value instanceof PsHashtable) value = value.get(toStr(idx));
        else if (typeof value === 'string') value = value[Number(idx)];
        else value = null;
        continue;
      }
      return value;
    }
  }

  parseCallArgs() {
    this.expect('(');
    const args = [];
    this.skipWs(true);
    if (this.peek() === ')') {
      this.pos++;
      return args;
    }
    for (;;) {
      this.skipWs(true);
      args.push(this.parseBinary());
      this.skipWs(true);
      if (this.peek() === ',') {
        this.pos++;
        continue;
      }
      this.expect(')');
      return args;
    }
  }

  /** `[Type]::Member...`, `[Type]` literal, or a cast `[type]operand`. */
  parseTypeExpression() {
    const start = this.pos;
    let depth = 0;
    do {
      const c = this.peek();
      if (c === undefined) throw new PsError('Unterminated type literal');
      if (c === '[') depth++;
      else if (c === ']') depth--;
      this.pos++;
    } while (depth > 0);
    const type = this.src.slice(start + 1, this.pos - 1).trim();
    if (this.peek() === ':' && this.peek(1) === ':') return this.parsePostfix(new PsTypeRef(type));
    const save = this.pos;
    this.skipWs(false);
    const c = this.peek();
    const startsOperand = c !== undefined && !/[\s\n;,)}\]|=+]/.test(c) && !(DASH.has(c) && isLetter(this.peek(1)));
    if (!startsOperand) {
      this.pos = save;
      return new PsTypeRef(type);
    }
    return this.cast(type, this.parseUnary());
  }

  cast(type, v) {
    switch (normTypeName(type)) {
      case 'char': {
        if (typeof v === 'number') return String.fromCharCode(v);
        const s = toStr(v);
        if (/^\d+$/.test(s)) return String.fromCharCode(Number(s));
        return s.slice(0, 1);
      }
      case 'string':
        return toStr(v);
      case 'int': case 'int32': case 'int64': case 'long': case 'double': case 'decimal': case 'float': case 'single':
        return Number(toStr(v));
      case 'bool': case 'boolean':
        return Boolean(v);
      case 'void':
        return undefined;
      case 'ordered': case 'hashtable': case 'collections.hashtable':
        return v;
      case 'byte[]':
        if (Array.isArray(v)) return new PsBytes(btoa(String.fromCharCode(...v.map((x) => Number(x) & 0xff))), 'base64');
        return v;
      default:
        return v;
    }
  }

  getStatic(type, name) {
    const t = normTypeName(type);
    const n = name.toLowerCase();
    if (t === 'text.encoding') return new PsEncoding(n);
    if (t === 'net.securityprotocoltype' || t === 'net.servicepointmanager') return new PsOpaque(`${type}::${name}`);
    this.note(`Static member [${type}]::${name} is not supported; treated as empty.`);
    return null;
  }

  callStatic(type, name, args) {
    const t = normTypeName(type);
    const n = name.toLowerCase();
    if (t === 'convert' && n === 'frombase64string') return new PsBytes(toStr(args[0]).replace(/\s+/g, ''), 'base64');
    if (t === 'convert' && n === 'tobase64string') {
      const b = args[0];
      if (b instanceof PsBytes) return b.encoding === 'base64' ? b.data : utf8ToBase64(b.data);
      return utf8ToBase64(toStr(b));
    }
    if (t === 'char' && n === 'convertfromutf32') return String.fromCodePoint(Number(toStr(args[0])));
    if ((t === 'uri' || t === 'net.webutility' || t === 'web.httputility') && /^(escapedatastring|escapeuristring|urlencode)$/.test(n)) {
      const s = toStr(args[0]);
      if (n === 'urlencode') return formUrlEncode(s);
      return n === 'escapeuristring' ? encodeURI(s) : encodeURIComponent(s).replace(/[!'()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
    }
    if (t === 'text.encoding' && n === 'getencoding') return new PsEncoding(toStr(args[0]).toLowerCase().replace(/-/g, ''));
    if (t === 'string' && n === 'join') return (Array.isArray(args[1]) ? args[1] : args.slice(1)).map(toStr).join(toStr(args[0]));
    if (t === 'io.file' && /^readall(text|bytes)$/.test(n)) {
      this.note(`File contents of ${toStr(args[0])} are not available; treated as empty.`);
      return '';
    }
    this.note(`Static method [${type}]::${name}() is not supported; treated as empty.`);
    return null;
  }

  getMember(obj, name) {
    const n = name.toLowerCase();
    if (obj instanceof PsSession) {
      if (n === 'cookies') return new PsMemberRef('cookies', obj);
      if (n === 'headers') return new PsMemberRef('headers', obj);
      if (n === 'useragent') return obj.userAgent;
      return null;
    }
    if (obj instanceof PsCookie) {
      if (['name', 'value', 'path', 'domain'].includes(n)) return obj[n];
      return null;
    }
    if (obj instanceof PsHashtable) {
      if (n === 'count') return obj.entries.length;
      if (n === 'keys') return obj.entries.map(([k]) => k);
      return obj.get(name);
    }
    if (obj instanceof PsEncoding) return obj;
    if (typeof obj === 'string' && n === 'length') return obj.length;
    if (Array.isArray(obj) && (n === 'count' || n === 'length')) return obj.length;
    if (obj instanceof PsOpaque || obj === null || obj === undefined) return null;
    return null;
  }

  setMember(obj, name, value) {
    const n = name.toLowerCase();
    if (obj instanceof PsSession) {
      if (n === 'useragent') obj.userAgent = toStr(value);
      else if (n === 'headers' && value instanceof PsHashtable) obj.headers = value.entries.map(([k, v]) => [k, toStr(v)]);
      else this.note(`Setting WebRequestSession.${name} is not supported; ignored.`);
      return;
    }
    if (obj instanceof PsCookie) {
      if (['name', 'value', 'path', 'domain'].includes(n)) obj[n] = toStr(value);
      return;
    }
    if (obj instanceof PsHashtable) {
      obj.set(name, value);
      return;
    }
    this.note(`Assignment to .${name} on an unsupported object ignored.`);
  }

  callMethod(obj, name, args) {
    const n = name.toLowerCase();
    if (obj instanceof PsMemberRef && obj.kind === 'cookies' && n === 'add') {
      for (const arg of args) {
        const list = Array.isArray(arg) ? arg : [arg];
        for (const c of list) {
          if (c instanceof PsCookie) obj.owner.cookies.push(new PsCookie(c.name, c.value, c.path, c.domain));
        }
      }
      // Add(Uri, Cookie): the cookie domain defaults to the URI host.
      if (args.length === 2 && args[1] instanceof PsCookie && !args[1].domain) {
        const parts = splitUrl(toStr(args[0]));
        if (parts) obj.owner.cookies[obj.owner.cookies.length - 1].domain = parts.host;
      }
      return undefined;
    }
    if (obj instanceof PsMemberRef && obj.kind === 'headers' && n === 'add') {
      obj.owner.headers.push([toStr(args[0]), toStr(args[1])]);
      return undefined;
    }
    if (obj instanceof PsEncoding && n === 'getbytes') return this.encodeBytes(obj.name, toStr(args[0]));
    if (obj instanceof PsEncoding && n === 'getstring') {
      const b = args[0];
      return b instanceof PsBytes ? (b.encoding === 'text' ? b.data : atob(b.data)) : toStr(b);
    }
    if (obj instanceof PsHashtable && n === 'add') {
      obj.entries.push([toStr(args[0]), args[1]]);
      return undefined;
    }
    if (typeof obj === 'string') {
      switch (n) {
        case 'trim': return obj.trim();
        case 'trimend': return obj.trimEnd();
        case 'trimstart': return obj.trimStart();
        case 'tolower': case 'tolowerinvariant': return obj.toLowerCase();
        case 'toupper': case 'toupperinvariant': return obj.toUpperCase();
        case 'replace': return obj.split(toStr(args[0])).join(toStr(args[1]));
        case 'tostring': return obj;
        case 'substring': return obj.substr(Number(args[0]), args[1] === undefined ? undefined : Number(args[1]));
        default: break;
      }
    }
    if (n === 'tostring') return toStr(obj);
    this.note(`Method .${name}() is not supported; result treated as empty.`);
    return null;
  }

  /**
   * @param {string} encName  Lowercased .NET encoding property/name.
   * @param {string} text
   */
  encodeBytes(encName, text) {
    switch (encName) {
      case 'utf8': case 'default': case 'utf-8':
        return new PsBytes(text, 'text');
      case 'ascii': case 'usascii':
        if (/[^\x00-\x7F]/.test(text)) this.note('Non-ASCII characters replaced by "?" ([Text.Encoding]::ASCII).');
        return new PsBytes(text.replace(/[^\x00-\x7F]/g, '?'), 'text');
      case 'unicode': case 'utf16': case 'utf16le':
        return new PsBytes(utf16leToBase64(text), 'base64');
      default:
        this.note(`Encoding ${encName} treated as UTF-8.`);
        return new PsBytes(text, 'text');
    }
  }

  // ---- strings ------------------------------------------------------------------

  /** Backtick escape at pos inside an expandable string. */
  readBacktickEscape() {
    const n = this.peek(1);
    if (n === undefined) {
      this.pos++;
      return '`';
    }
    this.pos += 2;
    switch (n) {
      case '0': return '\0';
      case 'a': return '\x07';
      case 'b': return '\b';
      case 'e': return '\x1b';
      case 'f': return '\f';
      case 'n': return '\n';
      case 'r': return '\r';
      case 't': return '\t';
      case 'v': return '\v';
      case 'u': {
        const m = /^\{([0-9a-fA-F]{1,6})\}/.exec(this.src.slice(this.pos, this.pos + 9));
        if (m) {
          this.pos += m[0].length;
          return String.fromCodePoint(parseInt(m[1], 16));
        }
        return 'u';
      }
      default:
        return n;
    }
  }

  /** `$...` inside an expandable string. */
  expandDollar() {
    const n = this.peek(1);
    if (n === '(') {
      this.pos += 2;
      return toStr(this.parseStatementList(')'));
    }
    if (n === '{') {
      const end = this.src.indexOf('}', this.pos);
      if (end > 0) {
        const name = this.src.slice(this.pos + 2, end);
        this.pos = end + 1;
        return toStr(this.lookupVar(name));
      }
    }
    if (isIdentChar(n)) {
      this.pos++;
      return toStr(this.lookupVar(this.readVarName()));
    }
    this.pos++;
    return '$';
  }

  parseDQString() {
    this.pos++;
    let out = '';
    for (;;) {
      if (this.eof()) throw new PsError('Unterminated double-quoted string');
      const c = this.peek();
      if (DQ.has(c)) {
        if (DQ.has(this.peek(1))) {
          out += c === '"' ? '"' : c;
          this.pos += 2;
          continue;
        }
        this.pos++;
        return out;
      }
      if (c === '`') out += this.readBacktickEscape();
      else if (c === '$') out += this.expandDollar();
      else {
        out += c;
        this.pos++;
      }
    }
  }

  parseSQString() {
    this.pos++;
    let out = '';
    for (;;) {
      if (this.eof()) throw new PsError('Unterminated single-quoted string');
      const c = this.peek();
      if (SQ.has(c)) {
        if (SQ.has(this.peek(1))) {
          out += c === "'" ? "'" : c;
          this.pos += 2;
          continue;
        }
        this.pos++;
        return out;
      }
      out += c;
      this.pos++;
    }
  }

  /** `@" ... "@` (expandable) or `@' ... '@` (verbatim). */
  parseHereString() {
    const expandable = DQ.has(this.peek(1));
    this.pos += 2;
    while (isBlank(this.peek()) || this.peek() === '\r') this.pos++;
    if (this.peek() !== '\n') throw new PsError('Here-string header must be followed by a newline');
    this.pos++;
    const closeRe = expandable ? /\n["“”„]@/g : /\n['‘’‚‛]@/g;
    // The closing delimiter may also be directly after the opening line (empty here-string).
    let end;
    let contentStart = this.pos;
    if ((expandable ? DQ : SQ).has(this.peek()) && this.peek(1) === '@') end = this.pos - 1;
    else {
      closeRe.lastIndex = this.pos - 1;
      const m = closeRe.exec(this.src);
      if (!m) throw new PsError('Unterminated here-string');
      end = m.index;
    }
    let out = '';
    if (!expandable) out = end >= contentStart ? this.src.slice(contentStart, end) : '';
    else {
      while (this.pos < end) {
        const c = this.peek();
        if (c === '`') out += this.readBacktickEscape();
        else if (c === '$') out += this.expandDollar();
        else {
          out += c;
          this.pos++;
        }
      }
    }
    this.pos = Math.max(end, contentStart - 1) + 3;
    return out;
  }

  parseHashtable() {
    this.pos += 2; // '@{'
    const h = new PsHashtable();
    for (;;) {
      this.skipWs(true);
      while (this.peek() === ';') {
        this.pos++;
        this.skipWs(true);
      }
      if (this.peek() === '}') {
        this.pos++;
        return h;
      }
      if (this.eof()) throw new PsError('Unterminated hashtable @{...}');
      let key;
      const c = this.peek();
      if (DQ.has(c)) key = this.parseDQString();
      else if (SQ.has(c)) key = this.parseSQString();
      else if (c === '(' || c === '$') key = toStr(this.parsePostfix(this.parsePrimary()));
      else {
        const start = this.pos;
        while (!this.eof() && !/[\s=;}]/.test(this.peek())) this.pos++;
        key = this.src.slice(start, this.pos);
        if (!key) throw new PsError(`Unexpected character '${c}' in hashtable`);
      }
      this.skipWs(false);
      this.expect('=');
      this.skipWs(true);
      const value = this.parseStatement();
      h.entries.push([key, value]);
    }
  }

  // ---- commands -----------------------------------------------------------------

  /** Bareword in argument mode (stops at whitespace and `;|)}(,`); quotes concatenate. */
  readArgBareword() {
    let out = '';
    for (;;) {
      const c = this.peek();
      if (c === undefined || /[\s;|)}(,]/.test(c)) break;
      if (c === '{' && out) break;
      if (c === '`') {
        if (this.isContinuation()) break;
        out += this.readBacktickEscape();
      } else if (DQ.has(c)) out += this.parseDQString();
      else if (SQ.has(c)) out += this.parseSQString();
      else if (c === '$' && isIdentChar(this.peek(1))) out += toStr(this.parseVariable());
      else {
        out += c;
        this.pos++;
      }
    }
    return out;
  }

  /** A single argument value in argument mode. */
  parseArgValue() {
    const c = this.peek();
    const n = this.peek(1);
    if (DQ.has(c) || SQ.has(c) || c === '(' || c === '[' || (c === '@' && (n === '{' || n === '(' || DQ.has(n) || SQ.has(n)))) {
      if (c === '[') return this.parseTypeExpression();
      return this.parsePostfix(this.parsePrimary());
    }
    if (c === '$') return this.parsePostfix(this.parsePrimary());
    return this.readArgBareword();
  }

  parseArgWithCommas() {
    const first = this.parseArgValue();
    this.skipWs(false);
    if (this.peek() !== ',') return first;
    const items = [first];
    while (this.peek() === ',') {
      this.pos++;
      this.skipWs(true);
      items.push(this.parseArgValue());
      this.skipWs(false);
    }
    return items;
  }

  /**
   * Parse a command invocation in argument mode and evaluate it.
   * @param {any} input  Pipeline input value.
   */
  parseCommand(input) {
    let name;
    if ((this.peek() === '&' || this.peek() === '.') && isBlank(this.peek(1))) {
      this.pos++;
      this.skipWs(false);
      name = toStr(this.parseArgValue());
    } else name = this.readArgBareword();
    /** @type {Array<{kind: 'param', name: string, value?: any, hasValue: boolean} | {kind: 'pos', value: any}>} */
    const args = [];
    for (;;) {
      this.skipWs(false);
      const c = this.peek();
      if (c === undefined || c === '\n' || c === ';' || c === ')' || c === '}' || c === '|') break;
      if (c === '&' && this.peek(1) === '&') break;
      if (DASH.has(c) && isLetter(this.peek(1))) {
        this.pos++;
        const pname = this.readIdent();
        if (this.peek() === ':' && this.peek(1) !== ':') {
          this.pos++;
          this.skipWs(false);
          args.push({ kind: 'param', name: pname, value: this.parseArgWithCommas(), hasValue: true });
        } else args.push({ kind: 'param', name: pname, hasValue: false });
        continue;
      }
      if (c === '-' && this.peek(1) === '-' && /\s/.test(this.peek(2) ?? ' ')) {
        this.pos += 2;
        continue;
      }
      const before = this.pos;
      args.push({ kind: 'pos', value: this.parseArgWithCommas() });
      if (this.pos === before) throw new PsError(`Unexpected character '${c}'`);
    }
    return this.invokeCommand(name, args, input);
  }

  /**
   * Bind raw command arguments to named parameters.
   * @param {Array<any>} args
   * @param {string[]} known      Known parameter names.
   * @param {Set<string>} switches
   * @param {string[]} positional Positional parameter names in order.
   * @param {string[]} [priority] Preferred names for ambiguous prefixes.
   * @returns {{bound: Record<string, any>, unknown: string[]}}
   */
  bindParameters(args, known, switches, positional, priority = []) {
    const bound = {};
    const unknown = [];
    const resolve = (raw) => {
      const lower = raw.toLowerCase();
      const exact = known.find((k) => k.toLowerCase() === lower);
      if (exact) return exact;
      const matches = known.filter((k) => k.toLowerCase().startsWith(lower));
      if (matches.length === 1) return matches[0];
      return priority.find((p) => matches.includes(p)) || null;
    };
    const posValues = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.kind === 'pos') {
        posValues.push(a.value);
        continue;
      }
      const name = resolve(a.name);
      if (a.hasValue) {
        if (name) bound[name] = a.value;
        else unknown.push(a.name);
        continue;
      }
      const next = args[i + 1];
      if (name && switches.has(name)) {
        bound[name] = true;
        continue;
      }
      if (!name) {
        unknown.push(a.name);
        // Unknown parameter: assume it takes a value unless that value looks like the URI.
        const looksLikeUri = next?.kind === 'pos' && /^[a-z][a-z0-9+.-]*:\/\//i.test(toStr(next.value)) && !bound.Uri;
        if (next?.kind === 'pos' && !looksLikeUri) i++;
        continue;
      }
      if (next?.kind === 'pos') {
        bound[name] = next.value;
        i++;
      } else bound[name] = true;
    }
    for (const v of posValues) {
      const p = positional.find((n) => !(n in bound));
      if (p) bound[p] = v;
    }
    return { bound, unknown };
  }

  invokeCommand(name, args, input) {
    const lower = name.toLowerCase();
    if (WEB_CMDLETS.has(lower)) return this.invokeWeb(name, args);
    if (lower === 'new-object') return this.newObject(args);
    if (lower === 'convertto-json') return this.convertToJson(args, input);
    if (lower === 'get-content') {
      this.note(`File contents read with Get-Content are not available; treated as empty.`);
      return '';
    }
    if (lower === 'convertto-securestring') return args.find((a) => a.kind === 'pos')?.value ?? '';
    if (SILENT_CMDLETS.has(lower)) return input;
    this.note(`Command "${name}" is not supported and was ignored.`);
    return new PsOpaque(name);
  }

  newObject(args) {
    const { bound } = this.bindParameters(args, NEW_OBJECT_PARAMS, new Set(['Strict']), ['TypeName', 'ArgumentList']);
    const type = normTypeName(toStr(bound.TypeName));
    const list = bound.ArgumentList === undefined ? [] : Array.isArray(bound.ArgumentList) ? bound.ArgumentList : [bound.ArgumentList];
    if (type === 'microsoft.powershell.commands.webrequestsession') return new PsSession();
    if (type === 'net.cookie') {
      const c = new PsCookie(toStr(list[0]), toStr(list[1]), list[2] === undefined ? '/' : toStr(list[2]), toStr(list[3]));
      if (bound.Property instanceof PsHashtable) for (const [k, v] of bound.Property.entries) this.setMember(c, k, v);
      return c;
    }
    if (type === 'uri') return toStr(list[0]);
    if (type === 'collections.hashtable' || type === 'collections.specialized.ordereddictionary') return new PsHashtable();
    if (type === 'net.cookiecontainer') return new PsOpaque('CookieContainer');
    this.note(`New-Object ${toStr(bound.TypeName)} is not supported.`);
    return new PsOpaque(toStr(bound.TypeName));
  }

  convertToJson(args, input) {
    const { bound } = this.bindParameters(args, ['InputObject', 'Depth', 'Compress', 'EnumsAsStrings', 'AsArray', 'EscapeHandling'],
      new Set(['Compress', 'EnumsAsStrings', 'AsArray']), ['InputObject']);
    const value = bound.InputObject !== undefined ? bound.InputObject : input;
    const toJs = (v) => {
      if (v instanceof PsHashtable) return Object.fromEntries(v.entries.map(([k, x]) => [k, toJs(x)]));
      if (Array.isArray(v)) return v.map(toJs);
      if (v instanceof PsBytes || v instanceof PsCookie || v instanceof PsTypeRef) return toStr(v);
      if (v instanceof PsOpaque || v === undefined) return null;
      return v;
    };
    const json = JSON.stringify(toJs(value), null, bound.Compress ? undefined : 2);
    return json === undefined ? 'null' : json;
  }

  /**
   * Evaluate Invoke-WebRequest / Invoke-RestMethod: build and record a request.
   * @param {string} cmdName
   * @param {Array<any>} args
   */
  invokeWeb(cmdName, args) {
    this.webCallCount++;
    const { bound, unknown } = this.bindParameters(args, WEB_PARAMS, WEB_SWITCHES, ['Uri'], WEB_PRIORITY);
    const notes = this.pendingNotes;
    this.pendingNotes = [];
    try {
      this.requests.push(this.buildRequest(cmdName, bound, unknown, notes));
    } catch (e) {
      this.errors.push(`PowerShell ${cmdName} #${this.webCallCount}: ${e.message}`);
    }
    return new PsOpaque('web response');
  }

  /**
   * @param {string} cmdName
   * @param {Record<string, any>} bound
   * @param {string[]} unknown
   * @param {string[]} notes
   * @returns {ParsedRequest}
   */
  buildRequest(cmdName, bound, unknown, notes) {
    let url = toStr(bound.Uri).trim();
    if (!url) throw new Error(`${cmdName} has no -Uri.`);
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      url = 'http://' + url;
      notes.push('URI without scheme; assumed http:// (as PowerShell does).');
    }
    let method = toStr(bound.CustomMethod ?? bound.Method ?? 'GET').trim() || 'GET';
    if (unknown.length) notes.push(`Ignored unknown parameter(s): ${unknown.map((u) => '-' + u).join(', ')}.`);

    /** @type {Header[]} */
    const headers = [];
    /** @type {PsSession|null} */
    let session = null;
    if (bound.WebSession !== undefined) {
      if (bound.WebSession instanceof PsSession) session = bound.WebSession;
      else notes.push('-WebSession does not refer to a WebRequestSession defined in the pasted script; ignored.');
    }
    /** @type {Header[]} */
    const explicit = [];
    if (bound.Headers !== undefined && bound.Headers !== null) {
      if (bound.Headers instanceof PsHashtable) {
        for (const [k, v] of bound.Headers.entries) {
          explicit.push({ name: k, value: Array.isArray(v) ? v.map(toStr).join(', ') : toStr(v) });
        }
      } else notes.push('-Headers is not a hashtable; ignored.');
    }
    // Session headers first; -Headers values override session headers with the same name.
    if (session) {
      for (const [k, v] of session.headers) {
        if (findHeaderIndex(explicit, k) < 0) headers.push({ name: k, value: v });
      }
    }
    headers.push(...explicit);

    // Cookies from the session, filtered like a browser would (domain + path match).
    const cookies = [];
    const parts = splitUrl(url);
    if (session && session.cookies.length && parts) {
      const skipped = [];
      for (const c of session.cookies) {
        if (domainMatches(parts.host, c.domain) && pathMatches(parts.path, c.path || '/')) cookies.push(`${c.name}=${c.value}`);
        else skipped.push(`${c.name} (domain ${c.domain || '-'}, path ${c.path || '/'})`);
      }
      if (skipped.length) notes.push(`Skipped session cookies not matching ${parts.host}${parts.path}: ${skipped.join(', ')}.`);
    }

    const userAgent = bound.UserAgent !== undefined ? toStr(bound.UserAgent) : session?.userAgent ?? undefined;
    let contentType = bound.ContentType !== undefined ? toStr(bound.ContentType) : undefined;

    // Body
    /** @type {string|null} */
    let body = null;
    /** @type {'text'|'base64'} */
    let bodyEncoding = 'text';
    const rawBody = bound.Body;
    if (rawBody !== undefined && rawBody !== null && !(rawBody instanceof PsOpaque)) {
      if (rawBody instanceof PsBytes) {
        body = rawBody.data;
        bodyEncoding = rawBody.encoding;
      } else if (rawBody instanceof PsHashtable) {
        const encoded = rawBody.entries.map(([k, v]) => `${formUrlEncode(k)}=${formUrlEncode(toStr(v))}`).join('&');
        if (method.toUpperCase() === 'GET') {
          url = appendQuery(url, encoded);
          notes.push('-Body hashtable with GET was appended to the URL query string (as PowerShell does).');
        } else {
          body = encoded;
          if (!contentType && !hasHeader(headers, 'content-type')) contentType = 'application/x-www-form-urlencoded';
          notes.push('-Body hashtable was form-urlencoded (as PowerShell does).');
        }
      } else if (Array.isArray(rawBody) && rawBody.every((x) => typeof x === 'number')) {
        body = btoa(String.fromCharCode(...rawBody.map((x) => x & 0xff)));
        bodyEncoding = 'base64';
      } else body = toStr(rawBody);
    }
    if (bound.Form instanceof PsHashtable) {
      const boundary = this.options.multipartBoundary || `${randomHex(4)}-${randomHex(2)}-${randomHex(2)}-${randomHex(2)}-${randomHex(6)}`;
      body = buildMultipartBody(bound.Form.entries.map(([k, v]) => ({ name: k, value: toStr(v) })), boundary);
      contentType = `multipart/form-data; boundary="${boundary}"`;
      notes.push('-Form fields were encoded as multipart/form-data (file fields are not supported).');
    }
    if (bound.InFile !== undefined) notes.push(`-InFile ${toStr(bound.InFile)}: file contents are not available; body left empty.`);
    if (body !== null && bodyEncoding === 'text' && method.toUpperCase() === 'POST' && !contentType && !hasHeader(headers, 'content-type')) {
      contentType = 'application/x-www-form-urlencoded';
      notes.push('No -ContentType given for a POST body; PowerShell sends application/x-www-form-urlencoded.');
    }
    if (bound.Credential !== undefined || bound.UseDefaultCredentials) notes.push('Credentials (-Credential/-UseDefaultCredentials) are not represented in the headers.');
    if (bound.Authentication !== undefined || bound.Token !== undefined) {
      const auth = toStr(bound.Authentication).toLowerCase();
      if (auth === 'bearer' && typeof bound.Token === 'string' && findHeaderIndex(headers, 'authorization') < 0) {
        headers.push({ name: 'Authorization', value: `Bearer ${bound.Token}` });
      } else notes.push('-Authentication/-Token are not represented in the headers.');
    }

    return normalizeRequest({
      method,
      url,
      httpVersion: bound.HttpVersion !== undefined ? mapHttpVersion(toStr(bound.HttpVersion)) ?? undefined : undefined,
      headers,
      body,
      bodyEncoding,
      source: 'powershell',
      notes,
      cookies,
      userAgent,
      contentType,
    }, this.options);
  }
}

/**
 * Parse PowerShell `Invoke-WebRequest` / `Invoke-RestMethod` commands. Every web cmdlet
 * invocation becomes one request, using the variable/session state defined before it.
 *
 * @param {string} text
 * @param {ParseOptions} [options]
 * @returns {{requests: ParsedRequest[], errors: string[]}}
 */
export function parsePowerShell(text, options = {}) {
  const interp = new PsInterpreter(text.replace(/^﻿/, '').replace(/\r\n?/g, '\n'), options);
  interp.run();
  if (!interp.requests.length && !interp.errors.length) interp.errors.push('PowerShell: no Invoke-WebRequest / Invoke-RestMethod command found.');
  return { requests: interp.requests, errors: interp.errors };
}
