// Evaluates Azure WAF custom rules (Front Door / Application Gateway) against a request.
//
// Semantics (Microsoft Learn, "WAF custom rules for Azure Front Door"):
//  - rules are evaluated by ascending priority; evaluation stops on any action except Log
//  - all match conditions of a rule must match (AND); any of a condition's values may match (OR)
//  - LessThan/GreaterThan/... are size constraints: the byte length of the variable is compared
//  - transforms are applied before matching; negateCondition inverts the condition result
//  - Allow exits the WAF: managed rules are not evaluated for that request

import { parseMultipart } from '../engine/transaction.js';
import { compilePcre } from '../engine/pcre.js';
import { utf8ToBinary, binaryToUtf8 } from '../engine/bytes.js';

const TERMINAL = new Set(['allow', 'block', 'redirect', 'jschallenge', 'captcha']);
const enc = new TextEncoder();
const byteLength = (s) => enc.encode(String(s)).length;

function pctDecode(s, plus) {
  let t = String(s);
  if (plus) t = t.replace(/\+/g, ' ');
  return t.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
function utf8Fix(s) {
  try {
    return decodeURIComponent(escape(s));
  } catch {
    return s;
  }
}

const TRANSFORMS = {
  lowercase: (s) => s.toLowerCase(),
  uppercase: (s) => s.toUpperCase(),
  trim: (s) => s.trim(),
  removenulls: (s) => s.replace(/\0/g, ''),
  urldecode: (s) => utf8Fix(pctDecode(s, true)),
  urlencode: (s) => encodeURIComponent(s),
  htmlentitydecode: (s) => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (m, e) => {
    const map = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
    if (map[e.toLowerCase()]) return map[e.toLowerCase()];
    const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    try {
      return String.fromCodePoint(cp);
    } catch {
      return m;
    }
  }),
};

function parseIpv4(s) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!v4 || v4.slice(1).some((o) => +o > 255)) return null;
  return BigInt(((+v4[1] << 24) >>> 0) + (+v4[2] << 16) + (+v4[3] << 8) + +v4[4]);
}
/** Parse an IPv4 / IPv6 address (incl. IPv4-mapped ::ffff:a.b.c.d); null when malformed. */
export function parseIp(ip) {
  const s = String(ip || '').trim();
  const n4 = parseIpv4(s);
  if (n4 !== null) return { v: 4, n: n4, bits: 32 };
  if (!s.includes(':')) return null;
  let str = s.replace(/%[0-9A-Za-z._~-]+$/, ''); // zone id
  // Trailing embedded IPv4 (e.g. ::ffff:10.1.2.3) -> two hex groups.
  const emb = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(str);
  if (emb) {
    const v = parseIpv4(emb[2]);
    if (v === null) return null;
    str = emb[1] + (v >> 16n).toString(16) + ':' + (v & 0xffffn).toString(16);
  }
  const parts = str.split('::');
  if (parts.length > 2) return null;
  const h = parts[0] ? parts[0].split(':') : [];
  const t = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  let groups;
  if (parts.length === 2) {
    const fill = 8 - h.length - t.length;
    if (fill < 1) return null;
    groups = [...h, ...Array(fill).fill('0'), ...t];
  } else groups = h;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v: 6, n: groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n), bits: 128 };
}
const V4_MAPPED = 0xffffn << 32n;
export function ipInCidr(ip, cidr) {
  const [addr, len, extra] = String(cidr).trim().split('/');
  if (extra !== undefined) return false;
  let a = parseIp(ip);
  const b = parseIp(addr);
  if (!a || !b) return false;
  // Compare IPv4 clients with IPv4-mapped IPv6 ranges and vice versa.
  if (a.v === 4 && b.v === 6) a = { v: 6, n: V4_MAPPED | a.n, bits: 128 };
  else if (a.v === 6 && b.v === 4 && a.n >> 32n === 0xffffn) a = { v: 4, n: a.n & 0xffffffffn, bits: 32 };
  if (a.v !== b.v) return false;
  let bits = b.bits;
  if (len !== undefined) {
    if (!/^\d{1,3}$/.test(len) || Number(len) > b.bits) return false;
    bits = Number(len);
  }
  const shift = BigInt(b.bits - bits);
  return a.n >> shift === b.n >> shift;
}

/** Derive Azure match variables from a ParsedRequest. */
export function requestFacts(req, ctx = {}) {
  const url = String(req.url || '/');
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(url);
  let rest = m ? url.slice(m[0].length) : url;
  rest = rest.split('#')[0] || '/';
  if (!rest.startsWith('/')) rest = '/' + rest;
  const q = rest.indexOf('?');
  const query = q >= 0 ? rest.slice(q + 1) : '';
  const headers = req.headers || [];
  const header = (name) => headers.filter((h) => h.name.toLowerCase() === String(name).toLowerCase()).map((h) => h.value);
  const cookies = [];
  for (const v of header('cookie')) {
    for (const part of v.split(';')) {
      const p = part.trim();
      if (!p) continue;
      const eq = p.indexOf('=');
      cookies.push({ name: eq >= 0 ? p.slice(0, eq) : p, value: eq >= 0 ? p.slice(eq + 1) : '' });
    }
  }
  let body = '';
  if (req.body != null) {
    if (req.bodyEncoding === 'base64') {
      try {
        body = utf8Fix(atob(req.body));
      } catch {
        body = '';
      }
    } else body = String(req.body);
  }
  const ct = (header('content-type')[0] || '').toLowerCase();
  const postArgs = [];
  if (ct.startsWith('application/x-www-form-urlencoded')) {
    for (const part of body.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      postArgs.push({ name: utf8Fix(pctDecode(eq >= 0 ? part.slice(0, eq) : part, true)), value: utf8Fix(pctDecode(eq >= 0 ? part.slice(eq + 1) : '', true)) });
    }
  } else if (ct.startsWith('multipart/form-data')) {
    // Same multipart parser as the managed-rule engine (byte strings in, converted back to text).
    // PostArgs are the form fields; file parts are included too (name = form field name,
    // value = file content, flagged `file`) because Microsoft does not document whether Azure
    // inspects uploads as PostArgs – a match on a file part is reported with a note.
    const mp = parseMultipart(utf8ToBinary(body), utf8ToBinary(header('content-type')[0] || ''));
    for (const a of mp.args) postArgs.push({ name: binaryToUtf8(a.name), value: binaryToUtf8(a.value) });
    for (const f of mp.files) postArgs.push({ name: binaryToUtf8(f.name), value: binaryToUtf8(f.content), file: true, filename: binaryToUtf8(f.filename) });
  }
  const queryArgs = query
    ? query.split('&').filter(Boolean).map((p) => {
        const eq = p.indexOf('=');
        return { name: utf8Fix(pctDecode(eq >= 0 ? p.slice(0, eq) : p, true)), value: utf8Fix(pctDecode(eq >= 0 ? p.slice(eq + 1) : '', true)) };
      })
    : [];
  return { method: String(req.method || 'GET').toUpperCase(), uri: rest, query, queryArgs, header, headers, cookies, body, postArgs, clientIp: ctx.clientIp || '', country: (ctx.country || '').toUpperCase() };
}

/** Values of a match variable (array; empty = variable absent). */
function variableValues(facts, variable, selector) {
  const v = String(variable).toLowerCase();
  const sel = selector == null || selector === '' ? null : String(selector);
  switch (v) {
    case 'remoteaddr':
    case 'socketaddr':
      return facts.clientIp ? [facts.clientIp] : [];
    case 'requestmethod':
      return [facts.method];
    case 'querystring':
      if (sel) return facts.queryArgs.filter((a) => a.name.toLowerCase() === sel.toLowerCase()).map((a) => a.value);
      return [facts.query];
    case 'postargs':
      if (sel) return facts.postArgs.filter((a) => a.name.toLowerCase() === sel.toLowerCase()).map((a) => a.value);
      return facts.postArgs.map((a) => a.value);
    case 'requesturi':
      return [facts.uri];
    case 'requestheader':
    case 'requestheaders':
      if (sel) return facts.header(sel);
      return facts.headers.map((h) => h.value);
    case 'requestbody':
      return facts.body ? [facts.body] : [];
    case 'cookies':
    case 'requestcookies':
      if (sel) return facts.cookies.filter((c) => c.name === sel || c.name.toLowerCase() === sel.toLowerCase()).map((c) => c.value);
      return facts.cookies.map((c) => c.value);
    default:
      return null; // unsupported variable
  }
}

/**
 * Compile an Azure custom-rule regex (RE2-like syntax: inline flags anywhere, \z, \A, POSIX
 * classes, \Q…\E, no DOTALL by default, '$' = end of text) via the PCRE translator. Custom rules
 * match normal (UTF-16) strings, so the translator runs in unicode-subject mode.
 */
function compileRegex(p) {
  const r = compilePcre(String(p), { baseFlags: '', unicode: true });
  return r.re;
}

/** Evaluate one condition. */
export function evalCondition(cond, facts) {
  const op = String(cond.operator).toLowerCase();
  const out = { ...cond, expected: cond.values, matched: false, status: 'ok', values: [], note: null, matchedValue: null };
  if (op === 'any') {
    out.matched = !cond.negate;
    out.note = 'Any: matches every request';
    return out;
  }
  if (op === 'geomatch') {
    if (!facts.country) {
      out.status = 'unknown';
      out.note = 'Client country unknown – set it in the settings to simulate GeoMatch.';
      return out;
    }
    const hit = cond.values.some((c) => c.toUpperCase() === facts.country);
    out.matched = cond.negate ? !hit : hit;
    out.values = [facts.country];
    return out;
  }
  let values = variableValues(facts, cond.variable, cond.selector);
  if (values === null) {
    out.status = 'unsupported';
    out.note = `Match variable ${cond.variable} cannot be simulated.`;
    return out;
  }
  for (const extra of cond.extraVariables || []) {
    const more = variableValues(facts, extra.variable, extra.selector);
    if (more) values = values.concat(more);
  }
  if (op === 'ipmatch' && !facts.clientIp) {
    out.status = 'unknown';
    out.note = 'Client IP unknown – set “Remote address” in the settings.';
    return out;
  }
  const tvals = values.map((v) => {
    let s = String(v);
    for (const t of cond.transforms || []) {
      const fn = TRANSFORMS[String(t).toLowerCase()];
      if (fn) s = fn(s);
    }
    return s;
  });
  out.values = tvals.map((v) => (v.length > 300 ? v.slice(0, 300) + '…' : v));
  let regexes = null;
  if (op === 'regex') {
    regexes = cond.values.map(compileRegex);
    if (regexes.some((r) => !r)) out.note = 'One regex could not be compiled in JavaScript.';
  }
  const test = (v, caseFold) => {
    const vv = caseFold ? v.toLowerCase() : v;
    const mv = (x) => (caseFold ? String(x).toLowerCase() : String(x));
    switch (op) {
      case 'ipmatch':
        return cond.values.flatMap((x) => String(x).split(',')).some((cidr) => ipInCidr(v, cidr));
      case 'equal':
        return cond.values.some((x) => vv === mv(x));
      case 'contains':
        return cond.values.some((x) => vv.includes(mv(x)));
      case 'beginswith':
        return cond.values.some((x) => vv.startsWith(mv(x)));
      case 'endswith':
        return cond.values.some((x) => vv.endsWith(mv(x)));
      case 'regex':
        return regexes.some((r) => r && r.test(v));
      case 'lessthan':
        return cond.values.some((x) => byteLength(v) < Number(x));
      case 'greaterthan':
        return cond.values.some((x) => byteLength(v) > Number(x));
      case 'lessthanorequal':
        return cond.values.some((x) => byteLength(v) <= Number(x));
      case 'greaterthanorequal':
        return cond.values.some((x) => byteLength(v) >= Number(x));
      default:
        return undefined;
    }
  };
  let hit = false;
  let fileHit = false;
  for (const [idx, v] of tvals.entries()) {
    const r = test(v, false);
    if (r === undefined) {
      out.status = 'unsupported';
      out.note = `Operator ${cond.operator} is not supported by the simulator.`;
      return out;
    }
    if (r) {
      hit = true;
      out.matchedValue = v.length > 300 ? v.slice(0, 300) + '…' : v;
      fileHit = /^postargs$/i.test(cond.variable) && facts.postArgs.some((a) => a.file && a.value === values[idx]);
      break;
    }
  }
  if (!values.length) out.note = cond.selector ? `${cond.variable} “${cond.selector}” is not present in the request.` : `${cond.variable} is empty / not present.`;
  else if (!hit && ['equal', 'contains', 'beginswith', 'endswith'].includes(op) && tvals.some((v) => test(v, true))) {
    out.note = 'Would match if compared case-insensitively – add a Lowercase transform (and lower-case match values) if that is intended.';
  }
  if (fileHit) out.note = (out.note ? out.note + ' ' : '') + 'The match is in the content of an uploaded file part – Azure may not treat file uploads as PostArgs.';
  if (/lessthan|greaterthan/.test(op)) out.note = (out.note ? out.note + ' ' : '') + `Size constraint: compares the byte length (${values.map((v) => byteLength(v)).join(', ') || 0}).`;
  out.matched = cond.negate ? !hit : hit;
  return out;
}

/**
 * Evaluate all custom rules of a policy.
 * @returns {{ rules: Array, decision: {name, priority, action}|null, logged: string[] }}
 */
export function evaluateCustomRules(policy, req, ctx = {}) {
  const facts = requestFacts(req, ctx);
  const rules = [];
  let decision = null;
  const logged = [];
  for (const rule of policy?.customRules || []) {
    const res = { name: rule.name, priority: rule.priority, action: rule.action, ruleType: rule.ruleType, enabled: rule.enabled, evaluated: false, matched: false, uncertain: false, conditions: [] };
    rules.push(res);
    if (!rule.enabled || decision) continue;
    res.evaluated = true;
    let all = true;
    for (const c of rule.conditions) {
      const cr = evalCondition(c, facts);
      res.conditions.push(cr);
      if (cr.status !== 'ok') res.uncertain = true;
      if (!cr.matched) all = false;
    }
    res.matched = all && rule.conditions.length > 0;
    if (!res.matched) continue;
    if (/ratelimit/i.test(rule.ruleType)) {
      res.rateLimited = true;
      res.note = `Rate-limit rule: this request counts towards the limit (${rule.rateLimitThreshold ?? '?'} requests / ${rule.rateLimitDurationInMinutes ?? '?'} min). The action applies only once the limit is exceeded.`;
      continue;
    }
    const a = String(rule.action).toLowerCase();
    if (a === 'log') logged.push(rule.name);
    else if (TERMINAL.has(a)) decision = { name: rule.name, priority: rule.priority, action: rule.action };
  }
  return { rules, decision, logged };
}
