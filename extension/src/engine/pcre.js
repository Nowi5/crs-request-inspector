// PCRE -> JavaScript RegExp translator.
//
// ModSecurity v2 compiles @rx patterns with PCRE (non-UTF mode) using
// PCRE_DOTALL | PCRE_DOLLAR_ENDONLY. The engine matches against byte strings
// (see bytes.js), so a JS RegExp without the `u` flag and with the `s` flag behaves
// almost identically once PCRE-only syntax is rewritten:
//   - inline flags `(?i)` anywhere (JS only has scoped `(?i:...)` modifiers)
//   - possessive quantifiers / atomic groups (approximated by their greedy forms)
//   - \A \z \Z \h \H \v \V \R \e \a \x{...} \Q...\E \N, POSIX classes [[:alpha:]]
//   - \s / \S restricted to the PCRE (non-UCP) whitespace set
//   - (?P<name> (?P=name) (?'name' \k{name} \g{n}, (?# comments), extended mode (x)
//   - (?m) ^/$ and non-DOTALL '.' with LF as the only line terminator (JS also uses \r, U+2028/9)
//   - (?i) on literal Latin-1 letters (PCRE byte mode folds ASCII only; JS folds 0xC0-0xFE)
//   - negated POSIX classes inside a class ([[:^digit:]])
// opts.unicode translates for normal UTF-16 subjects (Azure custom rules, RE2-like syntax).
// Constructs JS cannot express (recursion, conditionals, \G, \K, callouts) throw.

const PCRE_SPACE_CLASS = '\\t\\n\\x0B\\f\\r ';
const PCRE_NONSPACE_RANGES = '\\x00-\\x08\\x0E-\\x1F!-\\uFFFF';
const H_SPACE = '\\t \\xA0';
const H_NONSPACE_RANGES = '\\x00-\\x08\\x0A-\\x1F!-\\x9F\\xA1-\\uFFFF';
const V_SPACE = '\\n\\x0B\\f\\r\\x85';
const V_NONSPACE_RANGES = '\\x00-\\t\\x0E-\\x84\\x86-\\uFFFF';

const POSIX = {
  alpha: 'a-zA-Z',
  digit: '0-9',
  alnum: 'a-zA-Z0-9',
  upper: 'A-Z',
  lower: 'a-z',
  space: PCRE_SPACE_CLASS,
  blank: ' \\t',
  punct: '!-\\/:-@\\[-`{-~',
  xdigit: '0-9A-Fa-f',
  word: '\\w',
  cntrl: '\\x00-\\x1F\\x7F',
  print: ' -~',
  graph: '!-~',
  ascii: '\\x00-\\x7F',
};

// Code point ranges of the POSIX classes (ASCII, as PCRE without UCP), used to build the
// complement of a negated class such as [[:^digit:]] inside a bracket expression.
const POSIX_RANGES = {
  alpha: [[0x41, 0x5a], [0x61, 0x7a]],
  digit: [[0x30, 0x39]],
  alnum: [[0x30, 0x39], [0x41, 0x5a], [0x61, 0x7a]],
  upper: [[0x41, 0x5a]],
  lower: [[0x61, 0x7a]],
  space: [[0x09, 0x0d], [0x20, 0x20]],
  blank: [[0x09, 0x09], [0x20, 0x20]],
  punct: [[0x21, 0x2f], [0x3a, 0x40], [0x5b, 0x60], [0x7b, 0x7e]],
  xdigit: [[0x30, 0x39], [0x41, 0x46], [0x61, 0x66]],
  word: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]],
  cntrl: [[0x00, 0x1f], [0x7f, 0x7f]],
  print: [[0x20, 0x7e]],
  graph: [[0x21, 0x7e]],
  ascii: [[0x00, 0x7f]],
};
const hex4 = (c) => '\\u' + c.toString(16).padStart(4, '0');
function posixComplement(name) {
  let s = '';
  let next = 0;
  for (const [a, b] of POSIX_RANGES[name]) {
    if (a > next) s += a - 1 > next ? `${hex4(next)}-${hex4(a - 1)}` : hex4(next);
    next = b + 1;
  }
  if (next <= 0xffff) s += next < 0xffff ? `${hex4(next)}-\\uffff` : '\\uffff';
  return s;
}
// Latin-1 letters that JS (non-unicode `i`) folds to each other but PCRE in byte mode does not.
const isLatin1Letter = (c) => c >= 0xc0 && c <= 0xfe && c !== 0xd7 && c !== 0xf7;

const META = new Set(['\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}', '/']);
const escapeLiteral = (ch) => (META.has(ch) ? '\\' + ch : ch === '\n' ? '\\n' : ch === '\r' ? '\\r' : ch);

export class PcreTranslationError extends Error {}

/**
 * Translate a PCRE pattern to a JS RegExp source + flags.
 * @param {string} pattern
 * @param {{ baseFlags?: string }} [opts]  default 's' (PCRE_DOTALL, as ModSecurity uses)
 * @returns {{ source: string, flags: string, warnings: string[] }}
 */
export function translatePcre(pattern, opts = {}) {
  const warnings = [];
  // opts.unicode: the subject is a normal (UTF-16) JS string, not a byte string (Azure custom rules).
  const unicode = !!opts.unicode;
  const base = new Set((opts.baseFlags ?? 's').split('').filter(Boolean));
  // JS flags: only i and s are ever emitted. Multiline (m) and non-DOTALL '.' are emulated with
  // LF-only assertions/classes, because JS also treats \r, U+2028 and U+2029 as line terminators
  // while PCRE (default NEWLINE=LF) and RE2 only use \n.
  const globalFlags = new Set([...base].filter((f) => f === 'i' || f === 's'));
  const n = pattern.length;
  let i = 0;
  let out = '';
  let emittedSomething = false;

  // Group stack: each entry tracks inline-flag wrappers opened inside it and the effective flags.
  const stack = [{ wraps: [], ext: false, flags: { i: base.has('i'), m: base.has('m'), s: base.has('s') } }];
  const top = () => stack[stack.length - 1];
  const childFlags = (flags, on = '', off = '') => {
    const f = { ...flags };
    for (const k of 'ims') {
      if (on.includes(k)) f[k] = true;
      if (off.includes(k)) f[k] = false;
    }
    return f;
  };

  const fail = (msg) => {
    throw new PcreTranslationError(`${msg} at offset ${i}`);
  };
  const warn = (msg) => {
    if (!warnings.includes(msg)) warnings.push(msg);
  };

  const emit = (s) => {
    out += s;
    emittedSomething = true;
  };

  // After an atom/quantifier, check for a possessive '+' and drop it.
  const afterQuantifier = () => {
    if (pattern[i] === '+') {
      warn('possessive quantifier approximated as greedy');
      i++;
    } else if (pattern[i] === '?') {
      out += '?';
      i++;
    }
  };

  const readHexBrace = () => {
    // at '{' after \x or \o
    const end = pattern.indexOf('}', i);
    if (end < 0) fail('unterminated \\x{');
    const body = pattern.slice(i + 1, end);
    i = end + 1;
    return body;
  };

  const codeToEscape = (code, inClass) => {
    if (code > 0xffff) {
      if (unicode) {
        if (inClass) fail('code point above U+FFFF inside a character class is not supported');
        const s = String.fromCodePoint(code);
        return `(?:${hex4(s.charCodeAt(0))}${hex4(s.charCodeAt(1))})`;
      }
      warn('code point above U+FFFF can never match in byte mode');
      return '(?!)';
    }
    if (code > 0xff && !unicode) warn('\\x{...} above 0xFF can never match in byte mode');
    return hex4(code);
  };

  /** Parse an escape at pattern[i] === '\\'. Returns the JS replacement. */
  const parseEscape = (inClass) => {
    i++; // skip backslash
    if (i >= n) fail('trailing backslash');
    const c = pattern[i++];
    switch (c) {
      case 's':
        return inClass ? PCRE_SPACE_CLASS : `[${PCRE_SPACE_CLASS}]`;
      case 'S':
        return inClass ? PCRE_NONSPACE_RANGES : `[^${PCRE_SPACE_CLASS}]`;
      case 'h':
        return inClass ? H_SPACE : `[${H_SPACE}]`;
      case 'H':
        return inClass ? H_NONSPACE_RANGES : `[^${H_SPACE}]`;
      case 'v':
        return inClass ? V_SPACE : `[${V_SPACE}]`;
      case 'V':
        return inClass ? V_NONSPACE_RANGES : `[^${V_SPACE}]`;
      case 'R':
        if (inClass) fail('\\R in character class');
        return `(?:\\r\\n|[${V_SPACE}])`;
      case 'N':
        if (inClass) fail('\\N in character class');
        return '[^\\n]';
      case 'A':
        if (inClass) fail('\\A in character class');
        return '(?<![\\s\\S])';
      case 'z':
        if (inClass) fail('\\z in character class');
        return '(?![\\s\\S])';
      case 'Z':
        if (inClass) fail('\\Z in character class');
        return '(?=\\n?(?![\\s\\S]))';
      case 'G':
        fail('\\G is not supported');
        break;
      case 'K':
        fail('\\K is not supported');
        break;
      case 'X':
        fail('\\X is not supported');
        break;
      case 'C':
        fail('\\C is not supported');
        break;
      case 'e':
        return '\\x1B';
      case 'a':
        return '\\x07';
      case 'Q': {
        const end = pattern.indexOf('\\E', i);
        const lit = end < 0 ? pattern.slice(i) : pattern.slice(i, end);
        i = end < 0 ? n : end + 2;
        return [...lit].map((ch) => (inClass ? (ch === ']' || ch === '\\' || ch === '^' || ch === '-' ? '\\' + ch : ch) : escapeLiteral(ch))).join('');
      }
      case 'E':
        return '';
      case 'x': {
        if (pattern[i] === '{') {
          const body = readHexBrace();
          return codeToEscape(parseInt(body || '0', 16), inClass);
        }
        let hex = '';
        while (hex.length < 2 && i < n && /[0-9a-fA-F]/.test(pattern[i])) hex += pattern[i++];
        return '\\x' + hex.padStart(2, '0');
      }
      case 'o': {
        if (pattern[i] !== '{') fail('bad \\o');
        const body = readHexBrace();
        return codeToEscape(parseInt(body, 8), inClass);
      }
      case 'c':
        if (i >= n) fail('bad \\c');
        return '\\c' + pattern[i++].toUpperCase();
      case 'p':
      case 'P':
        fail('Unicode property escapes are not supported in byte mode');
        break;
      case 'g': {
        // \g{n} \g{-n} \g{name} \gn \g<name> (subroutine -> unsupported)
        if (pattern[i] === '<' || pattern[i] === "'") fail('subroutine calls are not supported');
        let ref;
        if (pattern[i] === '{') {
          const end = pattern.indexOf('}', i);
          ref = pattern.slice(i + 1, end);
          i = end + 1;
        } else {
          const m = /^-?\d+/.exec(pattern.slice(i));
          if (!m) fail('bad \\g');
          ref = m[0];
          i += ref.length;
        }
        if (/^\d+$/.test(ref)) return '\\' + ref;
        if (/^-\d+$/.test(ref)) fail('relative back references are not supported');
        return `\\k<${ref}>`;
      }
      case 'k': {
        const open = pattern[i];
        const close = open === '{' ? '}' : open === '<' ? '>' : open === "'" ? "'" : null;
        if (!close) fail('bad \\k');
        const end = pattern.indexOf(close, i + 1);
        const name = pattern.slice(i + 1, end);
        i = end + 1;
        return `\\k<${name}>`;
      }
      default:
        if (/[0-9]/.test(c)) {
          // Back reference or octal escape; JS (non-unicode mode) follows the same legacy rules closely.
          let digits = c;
          while (i < n && /[0-9]/.test(pattern[i]) && digits.length < 3) digits += pattern[i++];
          return '\\' + digits;
        }
        // \d \D \w \W \b \B \n \r \t \f \0 and identity escapes are identical in JS non-unicode mode.
        return '\\' + c;
    }
    return '';
  };

  const parseClass = () => {
    // pattern[i] === '['
    i++;
    let s = '[';
    if (pattern[i] === '^') {
      s += '^';
      i++;
    }
    if (pattern[i] === ']') {
      s += '\\]';
      i++;
    }
    while (i < n && pattern[i] !== ']') {
      const ch = pattern[i];
      if (ch === '[' && pattern[i + 1] === ':') {
        const end = pattern.indexOf(':]', i + 2);
        if (end > 0) {
          let name = pattern.slice(i + 2, end);
          let neg = false;
          if (name[0] === '^') {
            neg = true;
            name = name.slice(1);
          }
          const exp = POSIX[name];
          if (!exp) fail(`unknown POSIX class [:${name}:]`);
          s += neg ? posixComplement(name) : exp;
          i = end + 2;
          continue;
        }
      }
      if (ch === '[' && (pattern.startsWith('[:<:]]', i) || pattern.startsWith('[:>:]]', i))) fail('[[:<:]] is not supported');
      if (ch === '\\') {
        s += parseEscape(true);
        continue;
      }
      if (ch === '[') {
        s += '\\[';
        i++;
        continue;
      }
      s += ch;
      i++;
    }
    if (pattern[i] !== ']') fail('unterminated character class');
    i++;
    return s + ']';
  };

  const parseFlagSpec = (spec) => {
    const [on, off = ''] = spec.split('-');
    return { on, off };
  };

  const applyInlineFlags = (spec) => {
    const { on, off } = parseFlagSpec(spec);
    for (const f of on + off) {
      if (!'imsxUJn'.includes(f)) fail(`unknown inline flag ${f}`);
    }
    // extended mode is handled by the translator itself
    const t = top();
    if (on.includes('x')) t.ext = true;
    if (off.includes('x')) t.ext = false;
    if (/[UJn]/.test(on + off)) warn(`inline flag(s) ${spec} ignored`);
    const next = childFlags(t.flags, on, off);
    // At the very beginning of the pattern -> global JS flags.
    if (!emittedSomething && stack.length === 1) {
      for (const f of 'is') {
        if (next[f]) globalFlags.add(f);
        else globalFlags.delete(f);
      }
      t.flags = next;
      return;
    }
    // m and s are emulated per atom; only i needs a scoped JS modifier group. The change applies
    // to the rest of the enclosing group, including later alternatives (re-opened after '|').
    if (next.i !== t.flags.i) {
      const opener = next.i ? '(?i:' : '(?-i:';
      t.wraps.push(opener);
      emit(opener);
    }
    t.flags = next;
  };

  // A literal Latin-1 letter under (?i): PCRE in byte mode folds ASCII only, JS folds 0xC0-0xFE
  // too -> match the literal case-sensitively (not for unicode subjects, where RE2 folds Unicode).
  const emitChar = (atom, code) => {
    if (!unicode && top().flags.i && isLatin1Letter(code)) emit(`(?-i:${atom})`);
    else emit(atom);
  };
  // Character classes cannot be rewritten that simply: warn when folding changes the class.
  const checkClassFolding = (cls) => {
    if (!/[^\x00-\x7f]|\\x[89a-fA-F]|\\u00[89a-fA-F]|\\[0-7]{3}/.test(cls)) return;
    try {
      const plain = new RegExp(cls);
      const folded = new RegExp(cls, 'i');
      for (let c = 0xc0; c <= 0xfe; c++) {
        const s = String.fromCharCode(c);
        if (plain.test(s) !== folded.test(s)) {
          warn('case-insensitive character class with Latin-1 letters: JS folds them, PCRE in byte mode does not');
          return;
        }
      }
    } catch {
      /* ignore */
    }
  };

  const closeWraps = (t) => {
    if (t.wraps.length) out += ')'.repeat(t.wraps.length);
  };

  while (i < n) {
    const ch = pattern[i];
    const t = top();

    if (t.ext) {
      if (/\s/.test(ch)) {
        i++;
        continue;
      }
      if (ch === '#') {
        while (i < n && pattern[i] !== '\n') i++;
        continue;
      }
    }

    switch (ch) {
      case '\\': {
        const rep = parseEscape(false);
        const hx = /^\\x([0-9a-fA-F]{2})$/.exec(rep);
        if (hx) emitChar(rep, parseInt(hx[1], 16));
        else emit(rep);
        // escapes that are atoms can be followed by quantifiers; handled when we see them
        break;
      }
      case '[': {
        const cls = parseClass();
        if (t.flags.i && !unicode) checkClassFolding(cls);
        emit(cls);
        break;
      }
      case '.':
        // PCRE/RE2 '.' without DOTALL excludes only LF (JS also excludes \r, U+2028, U+2029).
        emit(t.flags.s ? (globalFlags.has('s') ? '.' : '[\\s\\S]') : '[^\\n]');
        i++;
        break;
      case '^':
        emit(t.flags.m ? '(?<![^\\n])' : '^');
        i++;
        break;
      case '$':
        // Without (?m): end of subject only (PCRE_DOLLAR_ENDONLY as used by ModSecurity; RE2 alike).
        emit(t.flags.m ? '(?![^\\n])' : '$');
        i++;
        break;
      case '(': {
        if (pattern[i + 1] !== '?' && pattern[i + 1] !== '*') {
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit('(');
          i++;
          break;
        }
        if (pattern[i + 1] === '*') fail('PCRE verbs (*...) are not supported');
        // (?...
        const rest = pattern.slice(i + 2);
        let m;
        if (rest[0] === '#') {
          const end = pattern.indexOf(')', i);
          if (end < 0) fail('unterminated comment');
          i = end + 1;
          break;
        }
        if (rest[0] === ':' || rest[0] === '=' || rest[0] === '!') {
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit('(?' + rest[0]);
          i += 3;
          break;
        }
        if (rest.startsWith('<=') || rest.startsWith('<!')) {
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit('(?' + rest.slice(0, 2));
          i += 4;
          break;
        }
        if (rest[0] === '>') {
          warn('atomic group approximated as non-capturing group');
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit('(?:');
          i += 3;
          break;
        }
        if (rest[0] === '|') {
          warn('branch reset group approximated as non-capturing group');
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit('(?:');
          i += 3;
          break;
        }
        if ((m = /^P?<([A-Za-z_]\w*)>/.exec(rest)) || (m = /^'([A-Za-z_]\w*)'/.exec(rest))) {
          stack.push({ wraps: [], ext: t.ext, flags: { ...t.flags } });
          emit(`(?<${m[1]}>`);
          i += 2 + m[0].length;
          break;
        }
        if ((m = /^P=([A-Za-z_]\w*)\)/.exec(rest))) {
          emit(`\\k<${m[1]}>`);
          i += 2 + m[0].length;
          break;
        }
        if ((m = /^([imsxUJn]*(?:-[imsxUJn]*)?)\)/.exec(rest)) && m[1].length) {
          i += 2 + m[0].length;
          applyInlineFlags(m[1]);
          break;
        }
        if ((m = /^([imsxUJn]*(?:-[imsxUJn]*)?):/.exec(rest)) && m[1].length) {
          const { on, off } = parseFlagSpec(m[1]);
          for (const f of on + off) if (!'imsxUJn'.includes(f)) fail(`unknown inline flag ${f}`);
          const ext = on.includes('x') ? true : off.includes('x') ? false : t.ext;
          const flags = childFlags(t.flags, on, off);
          stack.push({ wraps: [], ext, flags });
          emit(flags.i !== t.flags.i ? (flags.i ? '(?i:' : '(?-i:') : '(?:');
          i += 2 + m[0].length;
          break;
        }
        if (/^(?:R|[+-]?\d|&|P>|\(|C)/.test(rest)) fail('recursion, conditionals and callouts are not supported');
        fail('unsupported group syntax');
        break;
      }
      case ')': {
        if (stack.length === 1) fail('unbalanced )');
        closeWraps(t);
        stack.pop();
        out += ')';
        i++;
        afterQuantifierOrNothing();
        break;
      }
      case '|': {
        closeWraps(t);
        out += '|';
        i++;
        for (const w of t.wraps) out += w;
        break;
      }
      case '*':
      case '+':
      case '?':
        out += ch;
        i++;
        afterQuantifier();
        break;
      case '{': {
        const m = /^\{(\d+)(,(\d*))?\}/.exec(pattern.slice(i));
        if (m) {
          out += m[0];
          i += m[0].length;
          afterQuantifier();
        } else {
          emit('\\{');
          i++;
        }
        break;
      }
      case '}':
        emit('\\}');
        i++;
        break;
      case '/':
        emit('\\/');
        i++;
        break;
      case '\n':
        emit('\\n');
        i++;
        break;
      case '\r':
        emit('\\r');
        i++;
        break;
      default:
        emitChar(ch, ch.charCodeAt(0));
        i++;
    }
  }
  if (stack.length !== 1) fail('missing )');
  closeWraps(top());

  function afterQuantifierOrNothing() {
    /* quantifiers after ')' are handled by the main loop */
  }

  // Order flags canonically.
  const flags = [...globalFlags].filter((f) => 'ims'.includes(f)).sort().join('');
  return { source: out, flags, warnings };
}

/**
 * Compile a PCRE pattern into a JS RegExp.
 * @returns {{ re: RegExp|null, error?: string, warnings: string[], source?: string }}
 */
export function compilePcre(pattern, opts) {
  try {
    const { source, flags, warnings } = translatePcre(pattern, opts);
    return { re: new RegExp(source, flags), warnings, source };
  } catch (e) {
    return { re: null, error: e.message, warnings: [] };
  }
}
