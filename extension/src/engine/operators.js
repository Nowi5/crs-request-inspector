// ModSecurity operators (@rx, @pm, @detectSQLi, ...).
//
// Each operator factory receives the (macro-unexpanded) parameter plus a context and
// returns `{ exec(input, tx) -> result|null, dynamic, warning? }`. A non-null result
// means "operator matched" and carries details for the report:
//   { matched: string, index: number, captures?: string[] }

import { compilePcre } from './pcre.js';
import { asciiLower, atoi, isHex, isValidUtf8 } from './bytes.js';
import { AhoCorasick } from './ahocorasick.js';
import { detectSQLi, detectXSS } from './libinjection.js';

const hasMacro = (s) => s.includes('%{');

/** Split @pm parameters: whitespace separated, double quotes group phrases. */
function splitPhrases(param) {
  const out = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m;
  while ((m = re.exec(param))) out.push(m[1] ?? m[2]);
  return out.filter((p) => p.length);
}

function parseByteRanges(param) {
  const allowed = new Uint8Array(256);
  for (const part of param.split(',')) {
    const p = part.trim();
    if (!p) continue;
    const m = /^(\d+)(?:-(\d+))?$/.exec(p);
    if (!m) continue;
    const a = Math.max(0, Math.min(255, +m[1]));
    const b = m[2] !== undefined ? Math.max(0, Math.min(255, +m[2])) : a;
    for (let k = a; k <= b; k++) allowed[k] = 1;
  }
  return allowed;
}

function parseIpv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function expandIpv6(s) {
  if (!s.includes(':')) return null;
  let [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  if (tail === undefined && h.length !== 8) return null;
  const fill = tail !== undefined ? 8 - h.length - t.length : 0;
  const all = [...h, ...Array(Math.max(0, fill)).fill('0'), ...t];
  if (all.length !== 8 || all.some((x) => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
  return all.map((x) => parseInt(x, 16));
}

function ipMatcher(list) {
  const nets = [];
  for (const raw of list) {
    const e = raw.trim();
    if (!e) continue;
    const [addr, bitsStr] = e.split('/');
    const v4 = parseIpv4(addr);
    if (v4 !== null) {
      const bits = bitsStr !== undefined ? +bitsStr : 32;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      nets.push({ v: 4, net: (v4 & mask) >>> 0, mask });
      continue;
    }
    const v6 = expandIpv6(addr);
    if (v6) nets.push({ v: 6, addr: v6, bits: bitsStr !== undefined ? +bitsStr : 128 });
  }
  return (ip) => {
    const v4 = parseIpv4(ip);
    const v6 = v4 === null ? expandIpv6(ip) : null;
    for (const n of nets) {
      if (n.v === 4 && v4 !== null && ((v4 & n.mask) >>> 0) === n.net) return true;
      if (n.v === 6 && v6) {
        let bits = n.bits, ok = true;
        for (let k = 0; k < 8 && bits > 0; k++, bits -= 16) {
          const m = bits >= 16 ? 0xffff : (0xffff << (16 - bits)) & 0xffff;
          if ((v6[k] & m) !== (n.addr[k] & m)) { ok = false; break; }
        }
        if (ok) return true;
      }
    }
    return false;
  };
}

function validateUrlEncoding(s) {
  // returns index of the first invalid encoding, or -1
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) !== 37) continue;
    if (i + 2 >= s.length) return i; // not enough characters
    if (!isHex(s.charCodeAt(i + 1)) || !isHex(s.charCodeAt(i + 2))) return i;
    i += 2;
  }
  return -1;
}

function firstInvalidUtf8(s) {
  const n = s.length;
  for (let i = 0; i < n; ) {
    const c = s.charCodeAt(i);
    if (c < 0x80) { i++; continue; }
    let len, min;
    if ((c & 0xe0) === 0xc0) { len = 2; min = 0x80; }
    else if ((c & 0xf0) === 0xe0) { len = 3; min = 0x800; }
    else if ((c & 0xf8) === 0xf0) { len = 4; min = 0x10000; }
    else return i;
    if (i + len > n) return i;
    let cp = c & (0xff >> (len + 1));
    for (let k = 1; k < len; k++) {
      const cc = s.charCodeAt(i + k);
      if ((cc & 0xc0) !== 0x80) return i;
      cp = (cp << 6) | (cc & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return i;
    i += len;
  }
  return -1;
}

const numeric = (cmp) => (param, ctx) => {
  const dynamic = hasMacro(param);
  const fixed = dynamic ? 0 : atoi(param);
  return {
    dynamic,
    exec(input, tx) {
      const p = dynamic ? atoi(tx.expand(param)) : fixed;
      return cmp(atoi(input), p) ? { matched: input, index: 0 } : null;
    },
  };
};

// fn returns the match index or -1; wholeInput: report the full input as the matched text.
const stringOp = (fn, wholeInput = false) => (param) => {
  const dynamic = hasMacro(param);
  return {
    dynamic,
    exec(input, tx) {
      const p = dynamic ? tx.expand(param) : param;
      const idx = fn(input, p);
      if (idx < 0) return null;
      return { matched: wholeInput ? input : input.slice(idx, idx + p.length), index: wholeInput ? 0 : idx };
    },
  };
};

function pmOperator(phrases) {
  const ac = new AhoCorasick(phrases.map(asciiLower));
  return {
    exec(input) {
      const hit = ac.search(asciiLower(input));
      if (!hit) return null;
      const matched = input.slice(hit.start, hit.end);
      return { matched, index: hit.start, captures: [matched], phrase: hit.phrase };
    },
  };
}

/** Operator factories. `ctx` = { dataFiles: Map<name, string>, warn(msg) } */
export const OPERATORS = {
  rx(param, ctx) {
    const dynamic = hasMacro(param);
    const compile = (p) => {
      const r = compilePcre(p);
      if (!r.re) throw new Error(`regex not supported: ${r.error}`);
      for (const w of r.warnings) ctx.warn?.(w);
      return r.re;
    };
    const fixed = dynamic ? null : compile(param);
    const cache = new Map();
    return {
      dynamic,
      regex: fixed,
      exec(input, tx) {
        let re = fixed;
        if (dynamic) {
          const p = tx.expand(param);
          re = cache.get(p);
          if (!re) {
            re = compile(p);
            cache.set(p, re);
          }
        }
        const m = re.exec(input);
        if (!m) return null;
        return { matched: m[0], index: m.index, captures: Array.from(m).slice(0, 10).map((x) => x ?? '') };
      },
    };
  },
  pm(param) {
    return pmOperator(splitPhrases(param));
  },
  pmfromfile(param, ctx) {
    const phrases = [];
    for (const file of param.split(/\s+/).filter(Boolean)) {
      const name = file.split('/').pop();
      const text = ctx.dataFiles?.get(name);
      if (text == null) throw new Error(`data file ${name} not available`);
      for (const line of text.split(/\r?\n/)) {
        const l = line.replace(/[\s]+$/, '').replace(/^\s+/, '');
        if (!l || l.startsWith('#')) continue;
        phrases.push(l);
      }
    }
    return pmOperator(phrases);
  },
  streq: stringOp((i, p) => (i === p ? 0 : -1), true),
  contains: stringOp((i, p) => i.indexOf(p)),
  containsword: stringOp((i, p) => {
    if (!p.length) return 0;
    let from = 0;
    for (;;) {
      const idx = i.indexOf(p, from);
      if (idx < 0) return -1;
      const before = idx === 0 ? '' : i[idx - 1];
      const after = i[idx + p.length] ?? '';
      if (!/\w/.test(before) && !/\w/.test(after)) return idx;
      from = idx + 1;
    }
  }),
  beginswith: stringOp((i, p) => (i.startsWith(p) ? 0 : -1)),
  endswith: stringOp((i, p) => (i.endsWith(p) ? Math.max(0, i.length - p.length) : -1)),
  within: stringOp((i, p) => (p.indexOf(i) >= 0 ? 0 : -1), true),
  strmatch: stringOp((i, p) => i.indexOf(p)),
  eq: numeric((a, b) => a === b),
  ge: numeric((a, b) => a >= b),
  gt: numeric((a, b) => a > b),
  le: numeric((a, b) => a <= b),
  lt: numeric((a, b) => a < b),
  validatebyterange(param) {
    const allowed = parseByteRanges(param);
    return {
      exec(input) {
        for (let i = 0; i < input.length; i++) {
          const c = input.charCodeAt(i) & 0xff;
          if (!allowed[c]) return { matched: input[i], index: i, detail: `byte 0x${c.toString(16).padStart(2, '0')} (${c}) outside allowed range ${param}` };
        }
        return null;
      },
    };
  },
  validateurlencoding() {
    return {
      exec(input) {
        const idx = validateUrlEncoding(input);
        return idx >= 0 ? { matched: input.slice(idx, idx + 3), index: idx, detail: 'invalid URL encoding' } : null;
      },
    };
  },
  validateutf8encoding() {
    return {
      exec(input) {
        if (isValidUtf8(input)) return null;
        const idx = firstInvalidUtf8(input);
        return { matched: input.slice(Math.max(0, idx), Math.max(0, idx) + 4), index: Math.max(0, idx), detail: 'invalid UTF-8 byte sequence' };
      },
    };
  },
  detectsqli() {
    return {
      exec(input) {
        const r = detectSQLi(input);
        return r.isSqli ? { matched: input, index: 0, captures: [r.fingerprint], detail: `libinjection SQLi fingerprint: ${r.fingerprint}` } : null;
      },
    };
  },
  detectxss() {
    return {
      exec(input) {
        return detectXSS(input) ? { matched: input, index: 0, detail: 'libinjection detected XSS' } : null;
      },
    };
  },
  ipmatch(param) {
    const match = ipMatcher(param.split(/[,\s]+/));
    return { exec: (input) => (match(input) ? { matched: input, index: 0 } : null) };
  },
  ipmatchfromfile(param, ctx) {
    const name = param.trim().split('/').pop();
    const text = ctx.dataFiles?.get(name);
    if (text == null) throw new Error(`data file ${name} not available`);
    const match = ipMatcher(text.split(/\r?\n/).filter((l) => l && !l.startsWith('#')));
    return { exec: (input) => (match(input) ? { matched: input, index: 0 } : null) };
  },
  unconditionalmatch() {
    return { exec: (input) => ({ matched: input, index: 0 }) };
  },
  nomatch() {
    return { exec: () => null };
  },
};
OPERATORS.pmf = OPERATORS.pmfromfile;
OPERATORS.ipmatchf = OPERATORS.ipmatchfromfile;

/** Operators that need external services; they never match here. */
export const UNSUPPORTED_OPERATORS = new Set(['rbl', 'geolookup', 'inspectfile', 'fuzzyhash', 'gsblookup', 'verifycc', 'verifycpf', 'verifyssn', 'rsub']);

/**
 * Build an operator instance.
 * @returns {{exec: Function, dynamic?: boolean, unsupported?: string}}
 */
export function createOperator(name, param, ctx) {
  const key = name.toLowerCase();
  if (UNSUPPORTED_OPERATORS.has(key)) {
    return { unsupported: `@${name} needs external data/services and is never evaluated here`, exec: () => null };
  }
  const factory = OPERATORS[key];
  if (!factory) return { unsupported: `@${name} is not implemented`, exec: () => null };
  return factory(param, ctx);
}
