// libinjection (SQLi + XSS detection) ported to JavaScript.
//
// This is a line-by-line port of libinjection 4.0.0
// (https://github.com/libinjection/libinjection, tag v4.0.0,
// commit 211782219663f889f471650150df12b623c5766e):
// src/libinjection_sqli.c, src/libinjection_html5.c and src/libinjection_xss.c.
// Keyword / fingerprint tables are generated from src/libinjection_sqli_data.h and
// src/libinjection_xss.c by scripts/gen-libinjection-data.mjs.
//
// libinjection is Copyright (c) 2012-2016 Nick Galbreath and Copyright (c) 2017-2024
// the libinjection contributors, licensed under the BSD 3-Clause license; see
// LICENSE.libinjection next to this file. This port is distributed under the same
// license.
//
// Input convention: every function takes a "byte string", a JS string whose char
// codes are 0..255 and stand for one byte each (exactly like `unsigned char` in
// C). The code works on explicit lengths (embedded NUL bytes are data, as in C)
// and only ever folds ASCII a-z / A-Z case. Where the C code relies on `char`
// being signed (x86 / x86_64, the platforms ModSecurity normally runs on) the
// signed behaviour is reproduced; those places are marked "signed char".

import {
  LIBINJECTION_VERSION,
  CHAR_PARSERS,
  CHAR_PARSE_MAP,
  SQL_KEYWORDS,
  XSS_BLACK_ATTR_EVENTS,
  XSS_BLACK_ATTRS,
  XSS_BLACK_TAGS,
} from './libinjection-data.js';

export { LIBINJECTION_VERSION };

/* ========================================================================== */
/* Shared helpers                                                             */
/* ========================================================================== */

/** ASCII-only upper-casing (a-z -> A-Z); all other chars are left untouched. */
function asciiUpper(s) {
  return /[a-z]/.test(s) ? s.replace(/[a-z]+/g, (m) => m.toUpperCase()) : s;
}

/** C-string view of a token value (printf("%s") / strcmp / strchr stop at NUL). */
function cstr(v) {
  const i = v.indexOf('\0');
  return i === -1 ? v : v.slice(0, i);
}

/**
 * Lookup table for `strchr(set, ch) != NULL`. strchr() always finds the
 * terminating NUL, so byte 0 is always a member.
 * @param {string} chars
 */
function charSet(chars) {
  const t = new Uint8Array(256);
  t[0] = 1;
  for (let i = 0; i < chars.length; i++) t[chars.charCodeAt(i)] = 1;
  return t;
}

/* ========================================================================== */
/* SQLi                                                                       */
/* ========================================================================== */

export const FLAG_NONE = 0;
export const FLAG_QUOTE_NONE = 1;
export const FLAG_QUOTE_SINGLE = 2;
export const FLAG_QUOTE_DOUBLE = 4;
export const FLAG_SQL_ANSI = 8;
export const FLAG_SQL_MYSQL = 16;

const LOOKUP_WORD = 1;
// const LOOKUP_TYPE = 2;
const LOOKUP_OPERATOR = 3;
const LOOKUP_FINGERPRINT = 4;

const TOKEN_SIZE = 32; // sizeof(stoken_t.val), values hold at most 31 bytes
const MAX_TOKENS = 5;

const CHAR_NULL = '\0';
const CHAR_SINGLE = "'";
const CHAR_DOUBLE = '"';
const CHAR_TICK = '`';

const TYPE_NONE = '\0';
const TYPE_KEYWORD = 'k';
const TYPE_UNION = 'U';
const TYPE_GROUP = 'B';
const TYPE_EXPRESSION = 'E';
const TYPE_SQLTYPE = 't';
const TYPE_FUNCTION = 'f';
const TYPE_BAREWORD = 'n';
const TYPE_NUMBER = '1';
const TYPE_VARIABLE = 'v';
const TYPE_STRING = 's';
const TYPE_OPERATOR = 'o';
const TYPE_LOGIC_OPERATOR = '&';
const TYPE_COMMENT = 'c';
const TYPE_COLLATE = 'A';
const TYPE_LEFTPARENS = '(';
const TYPE_RIGHTPARENS = ')';
const TYPE_LEFTBRACE = '{';
const TYPE_RIGHTBRACE = '}';
const TYPE_DOT = '.';
const TYPE_COMMA = ',';
const TYPE_COLON = ':';
const TYPE_SEMICOLON = ';';
const TYPE_TSQL = 'T';
const TYPE_UNKNOWN = '?';
const TYPE_EVIL = 'X';
const TYPE_FINGERPRINT = 'F';
const TYPE_BACKSLASH = '\\';

/** Keyword table: ASCII-upper-case word -> token type (see the generator for why a Map is equivalent). */
const KEYWORDS = new Map();
let KEYWORD_MAX_LEN = 0;
for (const [type, prefix, sep, words] of SQL_KEYWORDS) {
  for (const w of words.split(sep)) {
    const word = prefix + w;
    KEYWORDS.set(word, type);
    if (word.length > KEYWORD_MAX_LEN) KEYWORD_MAX_LEN = word.length;
  }
}

/**
 * bsearch_keyword_type() / is_keyword(): case-insensitive (ASCII) exact lookup.
 * @param {string} key
 * @returns {string} token type or CHAR_NULL
 */
function isKeyword(key) {
  if (key.length === 0 || key.length > KEYWORD_MAX_LEN) return CHAR_NULL;
  return KEYWORDS.get(asciiUpper(key)) || CHAR_NULL;
}

/** `cstrcasecmp(upper, s, n) == 0` where s = val.slice(0, n) (upper has no NUL). */
function cstrcaseeq(upper, s) {
  return s.length === upper.length && asciiUpper(s) === upper;
}

/* char_is_white(): " \t\n\v\f\r\240\000" */
function charIsWhite(c) {
  return c === 0x20 || (c >= 0x09 && c <= 0x0d) || c === 0xa0 || c === 0x00;
}

// strlenspn() accepts NUL (strchr finds the terminator); strlencspn() stops at NUL.
const SET_BINARY = charSet('01');
const SET_HEX = charSet('0123456789ABCDEFabcdef');
const SET_MONEY = charSet('0123456789.,');
const SET_LETTERS = charSet('abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
const SET_WORD_DELIMS = charSet(" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\xa0\x00");
const SET_VAR_DELIMS = charSet(" <>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r'`\"");

/** strlenspn(s + start, len, accept) */
function strlenspn(s, start, len, set) {
  for (let i = 0; i < len; i++) {
    if (!set[s.charCodeAt(start + i)]) return i;
  }
  return len;
}

/** strlencspn(s + start, len, reject) */
function strlencspn(s, start, len, set) {
  for (let i = 0; i < len; i++) {
    if (set[s.charCodeAt(start + i)]) return i;
  }
  return len;
}

/** memchr2(): index of the 2-char sequence c0 c1 in s[start, start+len), or -1. */
function memchr2(s, start, len, c0, c1) {
  if (len < 2) return -1;
  const last = start + len - 1;
  for (let cur = start; cur < last; cur++) {
    if (s[cur] === c0 && s[cur + 1] === c1) return cur;
  }
  return -1;
}

/** memchr(): index of ch in s[start, start+len), or -1. */
function memchr(s, start, len, ch) {
  if (len <= 0) return -1;
  const i = s.indexOf(ch, start);
  return i !== -1 && i < start + len ? i : -1;
}

/** my_memmem(): index of needle in s[start, start+hlen), or -1. */
function myMemmem(s, start, hlen, needle) {
  if (hlen < needle.length) return -1;
  const i = s.indexOf(needle, start);
  return i !== -1 && i + needle.length <= start + hlen ? i : -1;
}

/**
 * A SQL token (struct libinjection_sqli_token).
 * `type`, `strOpen`, `strClose` are 1-char strings, '\0' for "none".
 * `val` holds at most 31 bytes (the C buffer is char[32]); `len` = val.length
 * except after the evil-fingerprint reset (as in C).
 */
export class SqliToken {
  constructor() {
    this.pos = 0;
    this.len = 0;
    this.count = 0;
    this.type = CHAR_NULL;
    this.strOpen = CHAR_NULL;
    this.strClose = CHAR_NULL;
    this.val = '';
  }
}

function stClear(st) {
  st.pos = 0;
  st.len = 0;
  st.count = 0;
  st.type = CHAR_NULL;
  st.strOpen = CHAR_NULL;
  st.strClose = CHAR_NULL;
  st.val = '';
}

function stAssignChar(st, stype, pos, value) {
  st.type = stype;
  st.pos = pos;
  st.len = 1;
  st.val = value;
}

/** st_assign(st, stype, pos, len, src + start) */
function stAssign(st, stype, pos, len, src, start) {
  const last = len < TOKEN_SIZE ? len : TOKEN_SIZE - 1;
  st.type = stype;
  st.pos = pos;
  st.len = last;
  st.val = src.substr(start, last);
}

function stCopy(dest, src) {
  dest.pos = src.pos;
  dest.len = src.len;
  dest.count = src.count;
  dest.type = src.type;
  dest.strOpen = src.strOpen;
  dest.strClose = src.strClose;
  dest.val = src.val;
}

function stIsArithmeticOp(st) {
  const ch = st.val[0];
  return st.type === TYPE_OPERATOR && st.len === 1 &&
    (ch === '*' || ch === '/' || ch === '-' || ch === '+' || ch === '%');
}

function stIsUnaryOp(st) {
  const str = st.val;
  if (st.type !== TYPE_OPERATOR) return false;
  switch (st.len) {
    case 1:
      return str[0] === '+' || str[0] === '-' || str[0] === '!' || str[0] === '~';
    case 2:
      return str[0] === '!' && str[1] === '!';
    case 3:
      return cstrcaseeq('NOT', str.slice(0, 3));
    default:
      return false;
  }
}

function flag2delim(flag) {
  if (flag & FLAG_QUOTE_SINGLE) return CHAR_SINGLE;
  if (flag & FLAG_QUOTE_DOUBLE) return CHAR_DOUBLE;
  return CHAR_NULL;
}

/* ---- parsers ------------------------------------------------------------- */

function parseWhite(sf) {
  return sf.pos + 1;
}

function parseOperator1(sf) {
  const pos = sf.pos;
  stAssignChar(sf.current, TYPE_OPERATOR, pos, sf.s[pos]);
  return pos + 1;
}

function parseOther(sf) {
  const pos = sf.pos;
  stAssignChar(sf.current, TYPE_UNKNOWN, pos, sf.s[pos]);
  return pos + 1;
}

function parseChar(sf) {
  const pos = sf.pos;
  const c = sf.s[pos];
  stAssignChar(sf.current, c, pos, c);
  return pos + 1;
}

function parseEolComment(sf) {
  const { s, slen, pos } = sf;
  const endpos = memchr(s, pos, slen - pos, '\n');
  if (endpos === -1) {
    stAssign(sf.current, TYPE_COMMENT, pos, slen - pos, s, pos);
    return slen;
  }
  stAssign(sf.current, TYPE_COMMENT, pos, endpos - pos, s, pos);
  return endpos + 1;
}

/** In ANSI mode, hash is an operator; in MySQL mode it's an EOL comment. */
function parseHash(sf) {
  sf.statsCommentHash += 1;
  if (sf.flags & FLAG_SQL_MYSQL) {
    sf.statsCommentHash += 1;
    return parseEolComment(sf);
  }
  stAssignChar(sf.current, TYPE_OPERATOR, sf.pos, '#');
  return sf.pos + 1;
}

function parseDash(sf) {
  const { s, slen, pos } = sf;
  if (pos + 2 < slen && s[pos + 1] === '-' && charIsWhite(s.charCodeAt(pos + 2))) {
    return parseEolComment(sf);
  } else if (pos + 2 === slen && s[pos + 1] === '-') {
    return parseEolComment(sf);
  } else if (pos + 1 < slen && s[pos + 1] === '-' && (sf.flags & FLAG_SQL_ANSI)) {
    sf.statsCommentDdx += 1;
    return parseEolComment(sf);
  }
  stAssignChar(sf.current, TYPE_OPERATOR, pos, '-');
  return pos + 1;
}

function isMysqlComment(cs, len, pos) {
  if (pos + 2 >= len) return 0;
  if (cs[pos + 2] !== '!') return 0;
  return 1;
}

function parseSlash(sf) {
  const { s, slen, pos } = sf;
  let ctype = TYPE_COMMENT;
  const pos1 = pos + 1;
  if (pos1 === slen || s[pos1] !== '*') return parseOperator1(sf);

  /* skip over initial '/x' */
  const ptr = memchr2(s, pos + 2, slen - (pos + 2), '*', '/');
  const clen = ptr === -1 ? slen - pos : ptr + 2 - pos;

  /* nested comment start or MySQL conditional comment -> evil */
  if (ptr !== -1 && memchr2(s, pos + 2, ptr - (pos + 1), '/', '*') !== -1) {
    ctype = TYPE_EVIL;
  } else if (isMysqlComment(s, slen, pos)) {
    ctype = TYPE_EVIL;
  }

  stAssign(sf.current, ctype, pos, clen, s, pos);
  return pos + clen;
}

function parseBackslash(sf) {
  const { s, slen, pos } = sf;
  /* Weird MySQL alias for NULL, "\N" (capital N only) */
  if (pos + 1 < slen && s[pos + 1] === 'N') {
    stAssign(sf.current, TYPE_NUMBER, pos, 2, s, pos);
    return pos + 2;
  }
  stAssignChar(sf.current, TYPE_BACKSLASH, pos, s[pos]);
  return pos + 1;
}

function parseOperator2(sf) {
  const { s, slen, pos } = sf;
  if (pos + 1 >= slen) return parseOperator1(sf);

  if (pos + 2 < slen && s[pos] === '<' && s[pos + 1] === '=' && s[pos + 2] === '>') {
    /* special 3-char operator */
    stAssign(sf.current, TYPE_OPERATOR, pos, 3, s, pos);
    return pos + 3;
  }

  const ch = lookupWord(sf, LOOKUP_OPERATOR, s.substr(pos, 2));
  if (ch !== CHAR_NULL) {
    stAssign(sf.current, ch, pos, 2, s, pos);
    return pos + 2;
  }

  if (s[pos] === ':') {
    /* ':' is not an operator */
    stAssign(sf.current, TYPE_COLON, pos, 1, s, pos);
    return pos + 1;
  }
  return parseOperator1(sf);
}

/** Odd number of backslashes ending at `end` (and not before `start`) -> escaped. */
function isBackslashEscaped(s, end, start) {
  let ptr = end;
  for (; ptr >= start; ptr--) {
    if (s.charCodeAt(ptr) !== 0x5c) break;
  }
  return (end - ptr) & 1;
}

function isDoubleDelimEscaped(s, cur, end) {
  return cur + 1 < end && s[cur + 1] === s[cur];
}

function parseStringCore(cs, len, pos, st, delim, offset) {
  /* offset is to skip the perhaps first quote char */
  let qpos = memchr(cs, pos + offset, len - pos - offset, delim);

  st.strOpen = offset > 0 ? delim : CHAR_NULL;

  for (;;) {
    if (qpos === -1) {
      /* string ended with no trailing quote */
      stAssign(st, TYPE_STRING, pos + offset, len - pos - offset, cs, pos + offset);
      st.strClose = CHAR_NULL;
      return len;
    } else if (isBackslashEscaped(cs, qpos - 1, pos + offset)) {
      qpos = memchr(cs, qpos + 1, len - (qpos + 1), delim);
    } else if (isDoubleDelimEscaped(cs, qpos, len)) {
      qpos = memchr(cs, qpos + 2, len - (qpos + 2), delim);
    } else {
      stAssign(st, TYPE_STRING, pos + offset, qpos - (pos + offset), cs, pos + offset);
      st.strClose = delim;
      return qpos + 1;
    }
  }
}

/** Used when first char is a ' or " */
function parseString(sf) {
  return parseStringCore(sf.s, sf.slen, sf.pos, sf.current, sf.s[sf.pos], 1);
}

/** N or n: MySQL "National Character set"; E: PostgreSQL "Escaped String" */
function parseEstring(sf) {
  const { s, slen, pos } = sf;
  if (pos + 2 >= slen || s[pos + 1] !== CHAR_SINGLE) return parseWord(sf);
  return parseStringCore(s, slen, pos, sf.current, CHAR_SINGLE, 2);
}

function parseUstring(sf) {
  const { s, slen, pos } = sf;
  if (pos + 2 < slen && s[pos + 1] === '&' && s[pos + 2] === "'") {
    sf.pos += 2;
    const p = parseString(sf);
    sf.current.strOpen = 'u';
    if (sf.current.strClose === "'") sf.current.strClose = 'u';
    return p;
  }
  return parseWord(sf);
}

function parseQstringCore(sf, offset) {
  const { s, slen } = sf;
  const pos = sf.pos + offset;

  if (pos >= slen || (s[pos] !== 'q' && s[pos] !== 'Q') || pos + 2 >= slen || s[pos + 1] !== "'") {
    return parseWord(sf);
  }

  const c = s.charCodeAt(pos + 2);
  /* signed char: bytes >= 0x80 are negative, i.e. < 33 */
  if (c < 33 || c >= 0x80) return parseWord(sf);
  let ch = s[pos + 2];
  switch (ch) {
    case '(': ch = ')'; break;
    case '[': ch = ']'; break;
    case '{': ch = '}'; break;
    case '<': ch = '>'; break;
    default: break;
  }

  const strend = memchr2(s, pos + 3, slen - pos - 3, ch, "'");
  if (strend === -1) {
    stAssign(sf.current, TYPE_STRING, pos + 3, slen - pos - 3, s, pos + 3);
    sf.current.strOpen = 'q';
    sf.current.strClose = CHAR_NULL;
    return slen;
  }
  stAssign(sf.current, TYPE_STRING, pos + 3, strend - pos - 3, s, pos + 3);
  sf.current.strOpen = 'q';
  sf.current.strClose = 'q';
  return strend + 2;
}

/** Oracle's q string */
function parseQstring(sf) {
  return parseQstringCore(sf, 0);
}

/** MySQL's N'STRING' or Oracle's nq string */
function parseNqstring(sf) {
  const { slen, pos } = sf;
  if (pos + 2 < slen && sf.s[pos + 1] === CHAR_SINGLE) return parseEstring(sf);
  return parseQstringCore(sf, 1);
}

/** binary literal string, [bB]'[01]*' */
function parseBstring(sf) {
  const { s, slen, pos } = sf;
  if (pos + 2 >= slen || s[pos + 1] !== "'") return parseWord(sf);
  const wlen = strlenspn(s, pos + 2, slen - pos - 2, SET_BINARY);
  if (pos + 2 + wlen >= slen || s[pos + 2 + wlen] !== "'") return parseWord(sf);
  stAssign(sf.current, TYPE_NUMBER, pos, wlen + 3, s, pos);
  return pos + 2 + wlen + 1;
}

/** hex literal string, [xX]'[0123456789abcdefABCDEF]*' */
function parseXstring(sf) {
  const { s, slen, pos } = sf;
  if (pos + 2 >= slen || s[pos + 1] !== "'") return parseWord(sf);
  const wlen = strlenspn(s, pos + 2, slen - pos - 2, SET_HEX);
  if (pos + 2 + wlen >= slen || s[pos + 2 + wlen] !== "'") return parseWord(sf);
  stAssign(sf.current, TYPE_NUMBER, pos, wlen + 3, s, pos);
  return pos + 2 + wlen + 1;
}

/** MS SQL Server bracket words [foo] */
function parseBword(sf) {
  const { s, slen, pos } = sf;
  const endptr = memchr(s, pos, slen - pos, ']');
  if (endptr === -1) {
    stAssign(sf.current, TYPE_BAREWORD, pos, slen - pos, s, pos);
    return slen;
  }
  stAssign(sf.current, TYPE_BAREWORD, pos, endptr - pos + 1, s, pos);
  return endptr + 1;
}

function parseWord(sf) {
  const { s, pos } = sf;
  const cur = sf.current;
  const wlen = strlencspn(s, pos, sf.slen - pos, SET_WORD_DELIMS);

  stAssign(cur, TYPE_BAREWORD, pos, wlen, s, pos);

  /* look inside the word for "." and "`" and see if what is before is a keyword */
  const val = cur.val;
  for (let i = 0; i < cur.len; ++i) {
    const delim = val[i];
    if (delim === '.' || delim === '`') {
      const ch = lookupWord(sf, LOOKUP_WORD, val.slice(0, i));
      if (ch !== TYPE_NONE && ch !== TYPE_BAREWORD) {
        /* we got something like "SELECT.1" or SELECT`column` */
        stClear(cur);
        stAssign(cur, ch, pos, i, s, pos);
        return pos + i;
      }
    }
  }

  /* do normal lookup with word including '.' */
  if (wlen < TOKEN_SIZE) {
    let ch = lookupWord(sf, LOOKUP_WORD, val);
    if (ch === CHAR_NULL) ch = TYPE_BAREWORD;
    cur.type = ch;
  }
  return pos + wlen;
}

/** MySQL backticks are a cross between string and a bare word. */
function parseTick(sf) {
  const pos = parseStringCore(sf.s, sf.slen, sf.pos, sf.current, CHAR_TICK, 1);
  const ch = lookupWord(sf, LOOKUP_WORD, sf.current.val);
  sf.current.type = ch === TYPE_FUNCTION ? TYPE_FUNCTION : TYPE_BAREWORD;
  return pos;
}

function parseVar(sf) {
  const { s, slen } = sf;
  const cur = sf.current;
  let pos = sf.pos + 1;

  /* move past optional other '@' */
  if (pos < slen && s[pos] === '@') {
    pos += 1;
    cur.count = 2;
  } else {
    cur.count = 1;
  }

  /* MySQL allows @@`version` */
  if (pos < slen) {
    if (s[pos] === '`') {
      sf.pos = pos;
      pos = parseTick(sf);
      cur.type = TYPE_VARIABLE;
      return pos;
    } else if (s[pos] === CHAR_SINGLE || s[pos] === CHAR_DOUBLE) {
      sf.pos = pos;
      pos = parseString(sf);
      cur.type = TYPE_VARIABLE;
      return pos;
    }
  }

  const xlen = strlencspn(s, pos, slen - pos, SET_VAR_DELIMS);
  if (xlen === 0) {
    stAssign(cur, TYPE_VARIABLE, pos, 0, s, pos);
    return pos;
  }
  stAssign(cur, TYPE_VARIABLE, pos, xlen, s, pos);
  return pos + xlen;
}

function parseMoney(sf) {
  const { s, slen, pos } = sf;
  const cur = sf.current;

  if (pos + 1 === slen) {
    /* end of line */
    stAssignChar(cur, TYPE_BAREWORD, pos, '$');
    return slen;
  }

  /* $1,000.00 or $1.000,00 ok! (also $....,,,111) */
  let xlen = strlenspn(s, pos + 1, slen - pos - 1, SET_MONEY);
  if (xlen === 0) {
    if (s[pos + 1] === '$') {
      /* we have $$ .. find ending $$ and make string */
      const strend = memchr2(s, pos + 2, slen - pos - 2, '$', '$');
      if (strend === -1) {
        stAssign(cur, TYPE_STRING, pos + 2, slen - (pos + 2), s, pos + 2);
        cur.strOpen = '$';
        cur.strClose = CHAR_NULL;
        return slen;
      }
      stAssign(cur, TYPE_STRING, pos + 2, strend - (pos + 2), s, pos + 2);
      cur.strOpen = '$';
      cur.strClose = '$';
      return strend + 2;
    }
    /* maybe it's pgsql "$ quoted strings" */
    xlen = strlenspn(s, pos + 1, slen - pos - 1, SET_LETTERS);
    if (xlen === 0) {
      /* hmm it's "$" _something_ .. just add $ and keep going */
      stAssignChar(cur, TYPE_BAREWORD, pos, '$');
      return pos + 1;
    }
    /* we have $foobar????? -- is it $foobar$ */
    if (pos + xlen + 1 === slen || s[pos + xlen + 1] !== '$') {
      stAssignChar(cur, TYPE_BAREWORD, pos, '$');
      return pos + 1;
    }

    /* we have $foobar$ ... find it again */
    const strend = myMemmem(s, pos + xlen + 2, slen - (pos + xlen + 2), s.substr(pos, xlen + 2));
    if (strend === -1) {
      stAssign(cur, TYPE_STRING, pos + xlen + 2, slen - pos - xlen - 2, s, pos + xlen + 2);
      cur.strOpen = '$';
      cur.strClose = CHAR_NULL;
      return slen;
    }
    stAssign(cur, TYPE_STRING, pos + xlen + 2, strend - (pos + xlen + 2), s, pos + xlen + 2);
    cur.strOpen = '$';
    cur.strClose = '$';
    return strend + xlen + 2;
  } else if (xlen === 1 && s[pos + 1] === '.') {
    /* $. should parsed as a word */
    return parseWord(sf);
  }
  stAssign(cur, TYPE_NUMBER, pos, 1 + xlen, s, pos);
  return pos + 1 + xlen;
}

function isDigit(c) {
  return c >= 0x30 && c <= 0x39;
}

function parseNumber(sf) {
  const { s, slen } = sf;
  let pos = sf.pos;
  let digits = null;
  let haveE = 0;
  let haveExp = 0;

  if (s[pos] === '0' && pos + 1 < slen) {
    const c1 = s[pos + 1];
    if (c1 === 'X' || c1 === 'x') digits = SET_HEX;
    else if (c1 === 'B' || c1 === 'b') digits = SET_BINARY;

    if (digits) {
      const xlen = strlenspn(s, pos + 2, slen - pos - 2, digits);
      if (xlen === 0) {
        stAssign(sf.current, TYPE_BAREWORD, pos, 2, s, pos);
        return pos + 2;
      }
      stAssign(sf.current, TYPE_NUMBER, pos, 2 + xlen, s, pos);
      return pos + 2 + xlen;
    }
  }

  const start = pos;
  while (pos < slen && isDigit(s.charCodeAt(pos))) pos += 1;

  if (pos < slen && s[pos] === '.') {
    pos += 1;
    while (pos < slen && isDigit(s.charCodeAt(pos))) pos += 1;
    if (pos - start === 1) {
      /* only one character read so far */
      stAssignChar(sf.current, TYPE_DOT, start, '.');
      return pos;
    }
  }

  if (pos < slen) {
    if (s[pos] === 'E' || s[pos] === 'e') {
      haveE = 1;
      pos += 1;
      if (pos < slen && (s[pos] === '+' || s[pos] === '-')) pos += 1;
      while (pos < slen && isDigit(s.charCodeAt(pos))) {
        haveExp = 1;
        pos += 1;
      }
    }
  }

  /* oracle's ending float or double suffix */
  if (pos < slen && (s[pos] === 'd' || s[pos] === 'D' || s[pos] === 'f' || s[pos] === 'F')) {
    if (pos + 1 === slen) {
      /* line ends evaluate "... 1.2f$" as '1.2f' */
      pos += 1;
    } else if (charIsWhite(s.charCodeAt(pos + 1)) || s[pos + 1] === ';') {
      pos += 1;
    } else if (s[pos + 1] === 'u' || s[pos + 1] === 'U') {
      /* a bit of a hack but makes '1fUNION' parse as '1f UNION' */
      pos += 1;
    }
    /* else: it's like "123FROM", parse as "123" only */
  }

  /* "1.e" / "10.10E" / ".E": no token is emitted (MySQL ignores it) */
  if (!(haveE === 1 && haveExp === 0)) {
    stAssign(sf.current, TYPE_NUMBER, start, pos - start, s, start);
  }
  return pos;
}

const PARSER_FUNCTIONS = {
  parse_backslash: parseBackslash,
  parse_bstring: parseBstring,
  parse_bword: parseBword,
  parse_char: parseChar,
  parse_dash: parseDash,
  parse_estring: parseEstring,
  parse_hash: parseHash,
  parse_money: parseMoney,
  parse_nqstring: parseNqstring,
  parse_number: parseNumber,
  parse_operator1: parseOperator1,
  parse_operator2: parseOperator2,
  parse_other: parseOther,
  parse_qstring: parseQstring,
  parse_slash: parseSlash,
  parse_string: parseString,
  parse_tick: parseTick,
  parse_ustring: parseUstring,
  parse_var: parseVar,
  parse_white: parseWhite,
  parse_word: parseWord,
  parse_xstring: parseXstring,
};

/** char_parse_map[256] */
const CHAR_PARSE_FNS = Array.from({ length: 256 }, (_, i) => {
  const name = CHAR_PARSERS[CHAR_PARSE_MAP.charCodeAt(i) - 65];
  const fn = PARSER_FUNCTIONS[name];
  if (!fn) throw new Error(`libinjection: unknown parser ${name}`);
  return fn;
});

/* ---- state --------------------------------------------------------------- */

/**
 * struct libinjection_sqli_state
 */
export class SqliState {
  /**
   * libinjection_sqli_init()
   * @param {string} s byte string
   * @param {number} [flags]
   */
  constructor(s, flags = 0) {
    this.s = s;
    this.slen = s.length;
    /** MAX TOKENS + 1 since we use one extra token to determine the type of the previous token */
    this.tokenvec = Array.from({ length: 8 }, () => new SqliToken());
    this.init(flags);
  }

  /** (Re)initialise everything but the input (libinjection_sqli_init / _reset). */
  init(flags) {
    if (flags === 0) flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;
    this.flags = flags;
    this.pos = 0;
    for (const t of this.tokenvec) stClear(t);
    this.current = this.tokenvec[0];
    this.fingerprint = '';
    this.reason = 0;
    this.statsCommentDdw = 0;
    this.statsCommentDdx = 0;
    this.statsCommentC = 0;
    this.statsCommentHash = 0;
    this.statsFolds = 0;
    this.statsTokens = 0;
  }
}

/**
 * libinjection_sqli_lookup_word(): keyword / operator lookup, or fingerprint check.
 * @param {SqliState} sf
 * @param {number} lookupType
 * @param {string} str
 * @returns {string}
 */
function lookupWord(sf, lookupType, str) {
  if (lookupType === LOOKUP_FINGERPRINT) {
    return libinjection_sqli_check_fingerprint(sf) ? 'X' : CHAR_NULL;
  }
  return isKeyword(str);
}

/**
 * Streaming tokenizer: sf.current is updated with the next token.
 * @param {SqliState} sf
 * @returns {boolean} true if a token was produced
 */
export function libinjection_sqli_tokenize(sf) {
  const { s, slen } = sf;
  const current = sf.current;

  if (slen === 0) return false;

  stClear(current);

  /* at beginning of string in single/double quote mode: pretend the input starts with a quote */
  if (sf.pos === 0 && (sf.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE))) {
    sf.pos = parseStringCore(s, slen, 0, current, flag2delim(sf.flags), 0);
    sf.statsTokens += 1;
    return true;
  }

  while (sf.pos < slen) {
    const ch = s.charCodeAt(sf.pos);
    sf.pos = CHAR_PARSE_FNS[ch](sf);
    if (current.type !== CHAR_NULL) {
      sf.statsTokens += 1;
      return true;
    }
  }
  return false;
}

/**
 * syntax_merge_words(): "UNION" + "ALL" ==> "UNION ALL" etc.
 */
function syntaxMergeWords(sf, a, b) {
  const at = a.type;
  if (!(at === TYPE_KEYWORD || at === TYPE_BAREWORD || at === TYPE_OPERATOR || at === TYPE_UNION ||
        at === TYPE_FUNCTION || at === TYPE_EXPRESSION || at === TYPE_TSQL || at === TYPE_SQLTYPE)) {
    return false;
  }
  const bt = b.type;
  if (!(bt === TYPE_KEYWORD || bt === TYPE_BAREWORD || bt === TYPE_OPERATOR || bt === TYPE_UNION ||
        bt === TYPE_FUNCTION || bt === TYPE_EXPRESSION || bt === TYPE_TSQL || bt === TYPE_SQLTYPE ||
        bt === TYPE_LOGIC_OPERATOR)) {
    return false;
  }

  const sz1 = a.len;
  const sz2 = b.len;
  const sz3 = sz1 + sz2 + 1; /* +1 for space in the middle */
  if (sz3 >= TOKEN_SIZE) return false;

  const tmp = a.val.slice(0, sz1) + ' ' + b.val.slice(0, sz2);
  const ch = lookupWord(sf, LOOKUP_WORD, tmp);
  if (ch !== CHAR_NULL) {
    stAssign(a, ch, a.pos, sz3, tmp, 0);
    return true;
  }
  return false;
}

/**
 * libinjection_sqli_fold(): tokenize + fold, up to 5 tokens.
 * @param {SqliState} sf
 * @returns {number} number of tokens in sf.tokenvec
 */
export function libinjection_sqli_fold(sf) {
  const lastComment = new SqliToken();
  const vec = sf.tokenvec;

  /* POS is the position of where the NEXT token goes */
  let pos = 0;
  /* LEFT is a count of how many tokens are already folded or processed */
  let left = 0;
  let more = true;

  /* Skip all initial comments, right-parens ( and unary operators */
  sf.current = vec[0];
  while (more) {
    more = libinjection_sqli_tokenize(sf);
    const t = sf.current.type;
    if (!(t === TYPE_COMMENT || t === TYPE_LEFTPARENS || t === TYPE_SQLTYPE || stIsUnaryOp(sf.current))) {
      break;
    }
  }

  if (!more) {
    /* If input was only comments, unary or (, then exit */
    return 0;
  }
  /* it's some other token */
  pos += 1;

  for (;;) {
    /* do we have all the max number of tokens? if so do some special cases for 5 tokens */
    if (pos >= MAX_TOKENS) {
      if ((vec[0].type === TYPE_NUMBER &&
           (vec[1].type === TYPE_OPERATOR || vec[1].type === TYPE_COMMA) &&
           vec[2].type === TYPE_LEFTPARENS &&
           vec[3].type === TYPE_NUMBER &&
           vec[4].type === TYPE_RIGHTPARENS) ||
          (vec[0].type === TYPE_BAREWORD &&
           vec[1].type === TYPE_OPERATOR &&
           vec[2].type === TYPE_LEFTPARENS &&
           (vec[3].type === TYPE_BAREWORD || vec[3].type === TYPE_NUMBER) &&
           vec[4].type === TYPE_RIGHTPARENS) ||
          (vec[0].type === TYPE_NUMBER &&
           vec[1].type === TYPE_RIGHTPARENS &&
           vec[2].type === TYPE_COMMA &&
           vec[3].type === TYPE_LEFTPARENS &&
           vec[4].type === TYPE_NUMBER) ||
          (vec[0].type === TYPE_BAREWORD &&
           vec[1].type === TYPE_RIGHTPARENS &&
           vec[2].type === TYPE_OPERATOR &&
           vec[3].type === TYPE_LEFTPARENS &&
           vec[4].type === TYPE_BAREWORD)) {
        if (pos > MAX_TOKENS) {
          stCopy(vec[1], vec[MAX_TOKENS]);
          pos = 2;
          left = 0;
        } else {
          pos = 1;
          left = 0;
        }
      }
    }

    if (!more || left >= MAX_TOKENS) {
      left = pos;
      break;
    }

    /* get up to two tokens */
    while (more && pos <= MAX_TOKENS && pos - left < 2) {
      sf.current = vec[pos];
      more = libinjection_sqli_tokenize(sf);
      if (more) {
        if (sf.current.type === TYPE_COMMENT) {
          stCopy(lastComment, sf.current);
        } else {
          lastComment.type = CHAR_NULL;
          pos += 1;
        }
      }
    }

    /* did we get 2 tokens? if not then we are done */
    if (pos - left < 2) {
      left = pos;
      continue;
    }

    const a = vec[left];
    const b = vec[left + 1];

    if (a.type === TYPE_STRING && b.type === TYPE_STRING) {
      /* FOLD: "ss" -> "s" */
      pos -= 1;
      sf.statsFolds += 1;
      continue;
    } else if (a.type === TYPE_SEMICOLON && b.type === TYPE_SEMICOLON) {
      /* fold away repeated semicolons */
      pos -= 1;
      sf.statsFolds += 1;
      continue;
    } else if ((a.type === TYPE_OPERATOR || a.type === TYPE_LOGIC_OPERATOR) &&
               (stIsUnaryOp(b) || b.type === TYPE_SQLTYPE)) {
      pos -= 1;
      sf.statsFolds += 1;
      left = 0;
      continue;
    } else if (a.type === TYPE_LEFTPARENS && stIsUnaryOp(b)) {
      pos -= 1;
      sf.statsFolds += 1;
      if (left > 0) left -= 1;
      continue;
    } else if (syntaxMergeWords(sf, a, b)) {
      pos -= 1;
      sf.statsFolds += 1;
      if (left > 0) left -= 1;
      continue;
    } else if (a.type === TYPE_SEMICOLON && b.type === TYPE_FUNCTION &&
               (b.val[0] === 'I' || b.val[0] === 'i') &&
               (b.val[1] === 'F' || b.val[1] === 'f')) {
      /* IF after a semicolon is a T-SQL control flow statement */
      b.type = TYPE_TSQL;
      continue;
    } else if ((a.type === TYPE_BAREWORD || a.type === TYPE_VARIABLE) &&
               b.type === TYPE_LEFTPARENS &&
               (cstrcaseeq('USER_ID', a.val) ||
                cstrcaseeq('USER_NAME', a.val) ||
                cstrcaseeq('DATABASE', a.val) ||
                cstrcaseeq('PASSWORD', a.val) ||
                cstrcaseeq('USER', a.val) ||
                cstrcaseeq('CURRENT_USER', a.val) ||
                cstrcaseeq('CURRENT_DATE', a.val) ||
                cstrcaseeq('CURRENT_TIME', a.val) ||
                cstrcaseeq('CURRENT_TIMESTAMP', a.val) ||
                cstrcaseeq('LOCALTIME', a.val) ||
                cstrcaseeq('LOCALTIMESTAMP', a.val))) {
      /* pos is the same */
      a.type = TYPE_FUNCTION;
      continue;
    } else if (a.type === TYPE_KEYWORD && (cstrcaseeq('IN', a.val) || cstrcaseeq('NOT IN', a.val))) {
      if (b.type === TYPE_LEFTPARENS) {
        /* got .... IN ( ...  (or 'NOT IN'): it's an operator */
        a.type = TYPE_OPERATOR;
      } else {
        a.type = TYPE_BAREWORD;
      }
      continue;
    } else if (a.type === TYPE_OPERATOR && (cstrcaseeq('LIKE', a.val) || cstrcaseeq('NOT LIKE', a.val))) {
      if (b.type === TYPE_LEFTPARENS) {
        /* SELECT LIKE(... it's a function */
        a.type = TYPE_FUNCTION;
      }
    } else if (a.type === TYPE_SQLTYPE &&
               (b.type === TYPE_BAREWORD || b.type === TYPE_NUMBER || b.type === TYPE_SQLTYPE ||
                b.type === TYPE_LEFTPARENS || b.type === TYPE_FUNCTION || b.type === TYPE_VARIABLE ||
                b.type === TYPE_STRING)) {
      stCopy(a, b);
      pos -= 1;
      sf.statsFolds += 1;
      left = 0;
      continue;
    } else if (a.type === TYPE_COLLATE && b.type === TYPE_BAREWORD) {
      /* if the bareword has a "_" then it's TYPE_SQLTYPE */
      if (cstr(b.val).includes('_')) {
        b.type = TYPE_SQLTYPE;
        left = 0;
      }
    } else if (a.type === TYPE_BACKSLASH) {
      if (stIsArithmeticOp(b)) {
        /* very weird case in TSQL where '\%1' is parsed as '0 % 1', etc */
        a.type = TYPE_NUMBER;
      } else {
        /* just ignore it.. Again T-SQL seems to parse \1 as "1" */
        stCopy(a, b);
        pos -= 1;
        sf.statsFolds += 1;
      }
      left = 0;
      continue;
    } else if (a.type === TYPE_LEFTPARENS && b.type === TYPE_LEFTPARENS) {
      pos -= 1;
      left = 0;
      sf.statsFolds += 1;
      continue;
    } else if (a.type === TYPE_RIGHTPARENS && b.type === TYPE_RIGHTPARENS) {
      pos -= 1;
      left = 0;
      sf.statsFolds += 1;
      continue;
    } else if (a.type === TYPE_LEFTBRACE && b.type === TYPE_BAREWORD) {
      /* MySQL degenerate case { ``.``.id } -- blacklisted */
      if (b.len === 0) {
        b.type = TYPE_EVIL;
        return left + 2;
      }
      /* weird ODBC / MYSQL {foo expr} --> expr: strip away the "{ foo" part */
      left = 0;
      pos -= 2;
      sf.statsFolds += 2;
      continue;
    } else if (b.type === TYPE_RIGHTBRACE) {
      pos -= 1;
      left = 0;
      sf.statsFolds += 1;
      continue;
    }

    /* all cases of handling 2 tokens is done and nothing matched. Get one more token */
    while (more && pos <= MAX_TOKENS && pos - left < 3) {
      sf.current = vec[pos];
      more = libinjection_sqli_tokenize(sf);
      if (more) {
        if (sf.current.type === TYPE_COMMENT) {
          stCopy(lastComment, sf.current);
        } else {
          lastComment.type = CHAR_NULL;
          pos += 1;
        }
      }
    }

    /* do we have three tokens? If not then we are done */
    if (pos - left < 3) {
      left = pos;
      continue;
    }

    /* now look for three token folding */
    const t0 = vec[left];
    const t1 = vec[left + 1];
    const t2 = vec[left + 2];
    if (t0.type === TYPE_NUMBER && t1.type === TYPE_OPERATOR && t2.type === TYPE_NUMBER) {
      pos -= 2;
      left = 0;
      continue;
    } else if (t0.type === TYPE_OPERATOR && t1.type !== TYPE_LEFTPARENS && t2.type === TYPE_OPERATOR) {
      left = 0;
      pos -= 2;
      continue;
    } else if (t0.type === TYPE_LOGIC_OPERATOR && t2.type === TYPE_LOGIC_OPERATOR) {
      pos -= 2;
      left = 0;
      continue;
    } else if (t0.type === TYPE_VARIABLE && t1.type === TYPE_OPERATOR &&
               (t2.type === TYPE_VARIABLE || t2.type === TYPE_NUMBER || t2.type === TYPE_BAREWORD)) {
      pos -= 2;
      left = 0;
      continue;
    } else if ((t0.type === TYPE_BAREWORD || t0.type === TYPE_NUMBER) && t1.type === TYPE_OPERATOR &&
               (t2.type === TYPE_NUMBER || t2.type === TYPE_BAREWORD)) {
      pos -= 2;
      left = 0;
      continue;
    } else if ((t0.type === TYPE_BAREWORD || t0.type === TYPE_NUMBER || t0.type === TYPE_VARIABLE ||
                t0.type === TYPE_STRING) &&
               t1.type === TYPE_OPERATOR && cstr(t1.val) === '::' && t2.type === TYPE_SQLTYPE) {
      pos -= 2;
      left = 0;
      sf.statsFolds += 2;
      continue;
    } else if ((t0.type === TYPE_BAREWORD || t0.type === TYPE_NUMBER || t0.type === TYPE_STRING ||
                t0.type === TYPE_VARIABLE) &&
               t1.type === TYPE_COMMA &&
               (t2.type === TYPE_NUMBER || t2.type === TYPE_BAREWORD || t2.type === TYPE_STRING ||
                t2.type === TYPE_VARIABLE)) {
      pos -= 2;
      left = 0;
      continue;
    } else if ((t0.type === TYPE_EXPRESSION || t0.type === TYPE_GROUP || t0.type === TYPE_COMMA) &&
               stIsUnaryOp(t1) && t2.type === TYPE_LEFTPARENS) {
      /* got something like SELECT + (, LIMIT + ( -- remove unary operator */
      stCopy(t1, t2);
      pos -= 1;
      left = 0;
      continue;
    } else if ((t0.type === TYPE_KEYWORD || t0.type === TYPE_EXPRESSION || t0.type === TYPE_GROUP) &&
               stIsUnaryOp(t1) &&
               (t2.type === TYPE_NUMBER || t2.type === TYPE_BAREWORD || t2.type === TYPE_VARIABLE ||
                t2.type === TYPE_STRING || t2.type === TYPE_FUNCTION)) {
      /* remove unary operators: select - 1 */
      stCopy(t1, t2);
      pos -= 1;
      left = 0;
      continue;
    } else if (t0.type === TYPE_COMMA && stIsUnaryOp(t1) &&
               (t2.type === TYPE_NUMBER || t2.type === TYPE_BAREWORD || t2.type === TYPE_VARIABLE ||
                t2.type === TYPE_STRING)) {
      /* ", -1" -> ",1" and back up one token: "1,-1" --> "1" */
      stCopy(t1, t2);
      left = 0;
      pos -= 3; /* pos is >= 3 here */
      continue;
    } else if (t0.type === TYPE_COMMA && stIsUnaryOp(t1) && t2.type === TYPE_FUNCTION) {
      /* 1,-sin(1) --> 1,sin(1) */
      stCopy(t1, t2);
      pos -= 1;
      left = 0;
      continue;
    } else if (t0.type === TYPE_BAREWORD && t1.type === TYPE_DOT && t2.type === TYPE_BAREWORD) {
      /* ignore the '.n', typically databasename.table */
      pos -= 2;
      left = 0;
      continue;
    } else if (t0.type === TYPE_EXPRESSION && t1.type === TYPE_DOT && t2.type === TYPE_BAREWORD) {
      /* select . `foo` --> select `foo` */
      stCopy(t1, t2);
      pos -= 1;
      left = 0;
      continue;
    } else if (t0.type === TYPE_FUNCTION && t1.type === TYPE_LEFTPARENS && t2.type !== TYPE_RIGHTPARENS) {
      /* USER() has 0 args; if we get User(foo), then User is not a function */
      if (cstrcaseeq('USER', t0.val)) {
        t0.type = TYPE_BAREWORD;
      }
    }

    /* no folding -- assume left-most token is good, now use the existing 2 tokens */
    left += 1;
  }

  /* if we have 4 or less tokens, and we had a comment token at the end, add it back */
  if (left < MAX_TOKENS && lastComment.type === TYPE_COMMENT) {
    stCopy(vec[left], lastComment);
    left += 1;
  }

  /* sometimes we grab a 6th token to help determine the type of token 5. */
  if (left > MAX_TOKENS) left = MAX_TOKENS;

  return left;
}

/**
 * libinjection_sqli_fingerprint(): detects SQLi in a string, given a context.
 * @param {SqliState} sf
 * @param {number} flags
 * @returns {string} the fingerprint (also stored in sf.fingerprint)
 */
export function libinjection_sqli_fingerprint(sf, flags) {
  sf.init(flags);

  const tlen = libinjection_sqli_fold(sf);
  const vec = sf.tokenvec;

  /* magic PHP backquote comment: last token is an empty, unclosed `-quoted bareword */
  if (tlen > 2 && vec[tlen - 1].type === TYPE_BAREWORD && vec[tlen - 1].strOpen === CHAR_TICK &&
      vec[tlen - 1].len === 0 && vec[tlen - 1].strClose === CHAR_NULL) {
    vec[tlen - 1].type = TYPE_COMMENT;
  }

  let fp = '';
  for (let i = 0; i < tlen; ++i) fp += vec[i].type;
  sf.fingerprint = cstr(fp);

  /* 'X' in pattern: parsing could not be done accurately */
  if (sf.fingerprint.includes(TYPE_EVIL)) {
    sf.fingerprint = TYPE_EVIL;
    vec[0].type = TYPE_EVIL;
    vec[0].val = TYPE_EVIL;
    vec[1].type = CHAR_NULL;
  }
  return sf.fingerprint;
}

/** libinjection_sqli_blacklist(): is the fingerprint in the 'F' table? */
function libinjection_sqli_blacklist(sf) {
  const len = sf.fingerprint.length;
  if (len < 1) {
    sf.reason = 1;
    return false;
  }
  /* convert the v0 fingerprint pattern to v1: '0' + upper case */
  const fp2 = '0' + asciiUpper(sf.fingerprint);
  if (isKeyword(fp2) !== TYPE_FINGERPRINT) {
    sf.reason = 2;
    return false;
  }
  return true;
}

/** libinjection_sqli_not_whitelist(): false-positive reduction. true = SQLi. */
function libinjection_sqli_not_whitelist(sf) {
  const fp = sf.fingerprint;
  const tlen = fp.length;
  const vec = sf.tokenvec;

  if (tlen > 1 && fp[tlen - 1] === TYPE_COMMENT) {
    /* ending comment and 'sp_password' anywhere in the input -> SQLi (MS audit log evasion) */
    if (myMemmem(sf.s, 0, sf.slen, 'sp_password') !== -1) {
      sf.reason = 3;
      return true;
    }
  }

  switch (tlen) {
    case 2: {
      /* "very small SQLi" are hard to tell from normal input */
      if (fp[1] === TYPE_UNION) {
        if (sf.statsTokens === 2) {
          /* it really is a number and 'union', other wise it has folding or comments */
          sf.reason = 4;
          return false;
        }
        sf.reason = 5;
        return true;
      }
      /* if 'comment' is '#' ignore.. too many FP */
      if (vec[1].val[0] === '#') {
        sf.reason = 6;
        return false;
      }
      /* for fingerprint like 'nc', only comments of /x are treated as SQL */
      if (vec[0].type === TYPE_BAREWORD && vec[1].type === TYPE_COMMENT && vec[1].val[0] !== '/') {
        sf.reason = 7;
        return false;
      }
      /* if '1c' ends with '/x' then it's SQLi */
      if (vec[0].type === TYPE_NUMBER && vec[1].type === TYPE_COMMENT && vec[1].val[0] === '/') {
        return true;
      }
      /* make sure the "1" in "1c" is actually a true decimal number */
      if (vec[0].type === TYPE_NUMBER && vec[1].type === TYPE_COMMENT) {
        if (sf.statsTokens > 2) {
          /* we have some folding going on, highly likely SQLi */
          sf.reason = 8;
          return true;
        }
        /* next character after the number is either whitespace, or '/' or a '-' ==> SQLi */
        const ch = sf.s.charCodeAt(vec[0].len);
        /* signed char: bytes >= 0x80 are negative, i.e. <= 32 */
        if (ch <= 32 || ch >= 0x80) return true;
        if (ch === 0x2f && sf.s[vec[0].len + 1] === '*') return true;
        if (ch === 0x2d && sf.s[vec[0].len + 1] === '-') return true;
        sf.reason = 9;
        return false;
      }
      /* only detect if input ends with '--', e.g. 1-- but not 1-- foo */
      if (vec[1].len > 2 && vec[1].val[0] === '-') {
        sf.reason = 10;
        return false;
      }
      break;
    }
    case 3: {
      if (fp === 'sos' || fp === 's&s') {
        if (vec[0].strOpen === CHAR_NULL && vec[2].strClose === CHAR_NULL &&
            vec[0].strClose === vec[2].strOpen) {
          /* if ....foo" + "bar.... */
          sf.reason = 11;
          return true;
        }
        if (sf.statsTokens === 3) {
          sf.reason = 12;
          return false;
        }
        /* not SQLi */
        sf.reason = 13;
        return false;
      } else if (fp === 's&n' || fp === 'n&1' || fp === '1&1' || fp === '1&v' || fp === '1&s') {
        /* 'sexy and 17' not SQLi, 'sexy and 17<18' SQLi */
        if (sf.statsTokens === 3) {
          sf.reason = 14;
          return false;
        }
      } else if (vec[1].type === TYPE_KEYWORD) {
        if (vec[1].len < 5 || !cstrcaseeq('INTO', vec[1].val.slice(0, 4))) {
          /* if it's not "INTO OUTFILE", or "INTO DUMPFILE" (MySQL) then treat as safe */
          sf.reason = 15;
          return false;
        }
      }
      break;
    }
    default:
      break;
  }
  return true;
}

/**
 * libinjection_sqli_check_fingerprint(): blacklist && not_whitelist.
 * @param {SqliState} sf (after libinjection_sqli_fingerprint)
 * @returns {boolean}
 */
export function libinjection_sqli_check_fingerprint(sf) {
  return libinjection_sqli_blacklist(sf) && libinjection_sqli_not_whitelist(sf);
}

function reparseAsMysql(sf) {
  return sf.statsCommentDdx || sf.statsCommentHash;
}

/**
 * libinjection_is_sqli(): tests the input as-is, in single-quote and in
 * double-quote context, with ANSI and MySQL comment rules.
 * @param {SqliState} sf
 * @returns {boolean}
 */
export function libinjection_is_sqli(sf) {
  const { s, slen } = sf;

  /* no input? not SQLi */
  if (slen === 0) return false;

  /* test input "as-is" */
  libinjection_sqli_fingerprint(sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
  if (lookupWord(sf, LOOKUP_FINGERPRINT, sf.fingerprint) !== CHAR_NULL) {
    return true;
  } else if (reparseAsMysql(sf)) {
    libinjection_sqli_fingerprint(sf, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
    if (lookupWord(sf, LOOKUP_FINGERPRINT, sf.fingerprint) !== CHAR_NULL) return true;
  }

  /* if input has a single_quote, then test as if input was actually ' */
  if (s.indexOf(CHAR_SINGLE) !== -1) {
    libinjection_sqli_fingerprint(sf, FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
    if (lookupWord(sf, LOOKUP_FINGERPRINT, sf.fingerprint) !== CHAR_NULL) {
      return true;
    } else if (reparseAsMysql(sf)) {
      libinjection_sqli_fingerprint(sf, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
      if (lookupWord(sf, LOOKUP_FINGERPRINT, sf.fingerprint) !== CHAR_NULL) return true;
    }
  }

  /* same as above but with a double-quote " */
  if (s.indexOf(CHAR_DOUBLE) !== -1) {
    libinjection_sqli_fingerprint(sf, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
    if (lookupWord(sf, LOOKUP_FINGERPRINT, sf.fingerprint) !== CHAR_NULL) return true;
  }

  /* Hurray, input is not SQLi */
  return false;
}

/* ========================================================================== */
/* HTML5 tokenizer                                                            */
/* ========================================================================== */

/** enum html5_type */
export const H5_DATA_TEXT = 0;
export const H5_TAG_NAME_OPEN = 1;
export const H5_TAG_NAME_CLOSE = 2;
export const H5_TAG_NAME_SELFCLOSE = 3;
export const H5_TAG_DATA = 4;
export const H5_TAG_CLOSE = 5;
export const H5_ATTR_NAME = 6;
export const H5_ATTR_VALUE = 7;
export const H5_TAG_COMMENT = 8;
export const H5_DOCTYPE = 9;
export const H5_TYPE_NAMES = [
  'DATA_TEXT', 'TAG_NAME_OPEN', 'TAG_NAME_CLOSE', 'TAG_NAME_SELFCLOSE', 'TAG_DATA',
  'TAG_CLOSE', 'ATTR_NAME', 'ATTR_VALUE', 'TAG_COMMENT', 'DOCTYPE',
];

/** enum html5_flags */
export const H5_DATA_STATE = 0;
export const H5_VALUE_NO_QUOTE = 1;
export const H5_VALUE_SINGLE_QUOTE = 2;
export const H5_VALUE_DOUBLE_QUOTE = 3;
export const H5_VALUE_BACK_QUOTE = 4;

const H5_CHAR_EOF = -1;
const CH_BANG = 33;
const CH_DOUBLE = 34;
const CH_PERCENT = 37;
const CH_SINGLE = 39;
const CH_DASH = 45;
const CH_SLASH = 47;
const CH_LT = 60;
const CH_EQUALS = 61;
const CH_GT = 62;
const CH_QUESTION = 63;
const CH_RIGHTB = 93;
const CH_TICK = 96;

/**
 * struct h5_state. `tokenStart` is an index into `s`.
 */
export class H5State {
  /**
   * libinjection_h5_init()
   * @param {string} s byte string
   * @param {number} flags one of the H5_*_STATE / H5_VALUE_* constants
   */
  constructor(s, flags = H5_DATA_STATE) {
    this.s = s;
    this.len = s.length;
    this.pos = 0;
    this.isClose = 0;
    this.state = null;
    this.tokenStart = 0;
    this.tokenLen = 0;
    this.tokenType = H5_DATA_TEXT;
    switch (flags) {
      case H5_DATA_STATE: this.state = h5StateData; break;
      case H5_VALUE_NO_QUOTE: this.state = h5StateBeforeAttributeName; break;
      case H5_VALUE_SINGLE_QUOTE: this.state = h5StateAttributeValueSingleQuote; break;
      case H5_VALUE_DOUBLE_QUOTE: this.state = h5StateAttributeValueDoubleQuote; break;
      case H5_VALUE_BACK_QUOTE: this.state = h5StateAttributeValueBackQuote; break;
      default: break;
    }
  }

  /** Current token text. */
  get token() {
    return this.s.substr(this.tokenStart, this.tokenLen);
  }
}

/**
 * libinjection_h5_next()
 * @param {H5State} hs
 * @returns {number} 1 = token available, 0 = done, -1 = error
 */
export function libinjection_h5_next(hs) {
  if (hs == null || hs.state == null) return -1;
  return hs.state(hs);
}

/* h5_is_white(): strchr(" \t\n\v\f\r", ch) -- includes NUL */
function h5IsWhite(c) {
  return c === 0x20 || (c >= 0x09 && c <= 0x0d) || c === 0x00;
}

/** Returns the next non-white char as a *signed char* (0xFF == CHAR_EOF), or CHAR_EOF. */
function h5SkipWhite(hs) {
  while (hs.pos < hs.len) {
    const ch = hs.s.charCodeAt(hs.pos);
    switch (ch) {
      case 0x00: /* IE only */
      case 0x20:
      case 0x09:
      case 0x0a:
      case 0x0b: /* IE only */
      case 0x0c:
      case 0x0d: /* IE only */
        hs.pos += 1;
        break;
      default:
        return ch >= 0x80 ? ch - 256 : ch; /* signed char */
    }
  }
  return H5_CHAR_EOF;
}

function h5StateEof() {
  return 0;
}

function h5StateData(hs) {
  if (hs == null || hs.len < hs.pos) return -1;
  const idx = memchr(hs.s, hs.pos, hs.len - hs.pos, '<');
  if (idx === -1) {
    hs.tokenStart = hs.pos;
    hs.tokenLen = hs.len - hs.pos;
    hs.tokenType = H5_DATA_TEXT;
    hs.state = h5StateEof;
    if (hs.tokenLen === 0) return 0;
  } else {
    hs.tokenStart = hs.pos;
    hs.tokenType = H5_DATA_TEXT;
    hs.tokenLen = idx - hs.pos;
    hs.pos = idx + 1;
    hs.state = h5StateTagOpen;
    if (hs.tokenLen === 0) return h5StateTagOpen(hs);
  }
  return 1;
}

/* 12 2.4.8 */
function h5StateTagOpen(hs) {
  if (hs.pos >= hs.len) return 0;
  const ch = hs.s.charCodeAt(hs.pos);
  if (ch === CH_BANG) {
    hs.pos += 1;
    return h5StateMarkupDeclarationOpen(hs);
  } else if (ch === CH_SLASH) {
    hs.pos += 1;
    hs.isClose = 1;
    return h5StateEndTagOpen(hs);
  } else if (ch === CH_QUESTION) {
    hs.pos += 1;
    return h5StateBogusComment(hs);
  } else if (ch === CH_PERCENT) {
    /* not in spec: alternative comment format used by IE <= 9 and Safari < 4.0.3 */
    hs.pos += 1;
    return h5StateBogusComment2(hs);
  } else if ((ch >= 0x61 && ch <= 0x7a) || (ch >= 0x41 && ch <= 0x5a)) {
    return h5StateTagName(hs);
  } else if (ch === 0) {
    /* IE-ism  NULL characters are ignored */
    return h5StateTagName(hs);
  }
  /* user input mistake in configuring state */
  if (hs.pos === 0) return h5StateData(hs);
  hs.tokenStart = hs.pos - 1;
  hs.tokenLen = 1;
  hs.tokenType = H5_DATA_TEXT;
  hs.state = h5StateData;
  return 1;
}

/* 12.2.4.9 */
function h5StateEndTagOpen(hs) {
  if (hs.pos >= hs.len) return 0;
  const ch = hs.s.charCodeAt(hs.pos);
  if (ch === CH_GT) {
    return h5StateData(hs);
  } else if ((ch >= 0x61 && ch <= 0x7a) || (ch >= 0x41 && ch <= 0x5a)) {
    return h5StateTagName(hs);
  }
  hs.isClose = 0;
  return h5StateBogusComment(hs);
}

function h5StateTagNameClose(hs) {
  hs.isClose = 0;
  hs.tokenStart = hs.pos;
  hs.tokenLen = 1;
  hs.tokenType = H5_TAG_NAME_CLOSE;
  hs.pos += 1;
  hs.state = hs.pos < hs.len ? h5StateData : h5StateEof;
  return 1;
}

/* 12.2.4.10 */
function h5StateTagName(hs) {
  let pos = hs.pos;
  while (pos < hs.len) {
    const ch = hs.s.charCodeAt(pos);
    if (ch === 0) {
      /* special non-standard case: allow nulls in tag name */
      pos += 1;
    } else if (h5IsWhite(ch)) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_TAG_NAME_OPEN;
      hs.pos = pos + 1;
      hs.state = h5StateBeforeAttributeName;
      return 1;
    } else if (ch === CH_SLASH) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_TAG_NAME_OPEN;
      hs.pos = pos + 1;
      hs.state = h5StateSelfClosingStartTag;
      return 1;
    } else if (ch === CH_GT) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      if (hs.isClose) {
        hs.pos = pos + 1;
        hs.isClose = 0;
        hs.tokenType = H5_TAG_CLOSE;
        hs.state = h5StateData;
      } else {
        hs.pos = pos;
        hs.tokenType = H5_TAG_NAME_OPEN;
        hs.state = h5StateTagNameClose;
      }
      return 1;
    } else {
      pos += 1;
    }
  }

  hs.tokenStart = hs.pos;
  hs.tokenLen = hs.len - hs.pos;
  hs.tokenType = H5_TAG_NAME_OPEN;
  hs.state = h5StateEof;
  return 1;
}

/* 12.2.4.34 */
function h5StateBeforeAttributeName(hs) {
  for (;;) {
    const ch = h5SkipWhite(hs);
    switch (ch) {
      case H5_CHAR_EOF:
        return 0;
      case CH_SLASH:
        hs.pos += 1;
        /* manual tail call of h5_state_self_closing_start_tag() */
        if (hs.pos < hs.len && hs.s.charCodeAt(hs.pos) !== CH_GT) continue;
        return h5StateSelfClosingStartTag(hs);
      case CH_GT:
        hs.state = h5StateData;
        hs.tokenStart = hs.pos;
        hs.tokenLen = 1;
        hs.tokenType = H5_TAG_NAME_CLOSE;
        hs.pos += 1;
        return 1;
      default:
        return h5StateAttributeName(hs);
    }
  }
}

function h5StateAttributeName(hs) {
  let pos = hs.pos + 1;
  while (pos < hs.len) {
    const ch = hs.s.charCodeAt(pos);
    if (h5IsWhite(ch)) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_ATTR_NAME;
      hs.state = h5StateAfterAttributeName;
      hs.pos = pos + 1;
      return 1;
    } else if (ch === CH_SLASH) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_ATTR_NAME;
      hs.state = h5StateSelfClosingStartTag;
      hs.pos = pos + 1;
      return 1;
    } else if (ch === CH_EQUALS) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_ATTR_NAME;
      hs.state = h5StateBeforeAttributeValue;
      hs.pos = pos + 1;
      return 1;
    } else if (ch === CH_GT) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.tokenType = H5_ATTR_NAME;
      hs.state = h5StateTagNameClose;
      hs.pos = pos;
      return 1;
    } else {
      pos += 1;
    }
  }
  /* EOF */
  hs.tokenStart = hs.pos;
  hs.tokenLen = hs.len - hs.pos;
  hs.tokenType = H5_ATTR_NAME;
  hs.state = h5StateEof;
  hs.pos = hs.len;
  return 1;
}

/* 12.2.4.36 */
function h5StateAfterAttributeName(hs) {
  const c = h5SkipWhite(hs);
  switch (c) {
    case H5_CHAR_EOF:
      return 0;
    case CH_SLASH:
      hs.pos += 1;
      return h5StateSelfClosingStartTag(hs);
    case CH_EQUALS:
      hs.pos += 1;
      return h5StateBeforeAttributeValue(hs);
    case CH_GT:
      return h5StateTagNameClose(hs);
    default:
      return h5StateAttributeName(hs);
  }
}

/* 12.2.4.37 */
function h5StateBeforeAttributeValue(hs) {
  const c = h5SkipWhite(hs);
  if (c === H5_CHAR_EOF) {
    hs.state = h5StateEof;
    return 0;
  }
  if (c === CH_DOUBLE) return h5StateAttributeValueDoubleQuote(hs);
  if (c === CH_SINGLE) return h5StateAttributeValueSingleQuote(hs);
  if (c === CH_TICK) return h5StateAttributeValueBackQuote(hs); /* NON STANDARD IE */
  return h5StateAttributeValueNoQuote(hs);
}

function h5StateAttributeValueQuote(hs, qchar) {
  /* skip initial quote in normal case (pos == 0 means we started in a value state) */
  if (hs.pos > 0) hs.pos += 1;

  const idx = memchr(hs.s, hs.pos, hs.len - hs.pos, qchar);
  if (idx === -1) {
    hs.tokenStart = hs.pos;
    hs.tokenLen = hs.len - hs.pos;
    hs.tokenType = H5_ATTR_VALUE;
    hs.state = h5StateEof;
  } else {
    hs.tokenStart = hs.pos;
    hs.tokenLen = idx - hs.pos;
    hs.tokenType = H5_ATTR_VALUE;
    hs.state = h5StateAfterAttributeValueQuotedState;
    hs.pos += hs.tokenLen + 1;
  }
  return 1;
}

function h5StateAttributeValueDoubleQuote(hs) {
  return h5StateAttributeValueQuote(hs, '"');
}

function h5StateAttributeValueSingleQuote(hs) {
  return h5StateAttributeValueQuote(hs, "'");
}

function h5StateAttributeValueBackQuote(hs) {
  return h5StateAttributeValueQuote(hs, '`');
}

function h5StateAttributeValueNoQuote(hs) {
  let pos = hs.pos;
  while (pos < hs.len) {
    const ch = hs.s.charCodeAt(pos);
    if (h5IsWhite(ch)) {
      hs.tokenType = H5_ATTR_VALUE;
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.pos = pos + 1;
      hs.state = h5StateBeforeAttributeName;
      return 1;
    } else if (ch === CH_GT) {
      hs.tokenType = H5_ATTR_VALUE;
      hs.tokenStart = hs.pos;
      hs.tokenLen = pos - hs.pos;
      hs.pos = pos;
      hs.state = h5StateTagNameClose;
      return 1;
    }
    pos += 1;
  }
  /* EOF */
  hs.state = h5StateEof;
  hs.tokenStart = hs.pos;
  hs.tokenLen = hs.len - hs.pos;
  hs.tokenType = H5_ATTR_VALUE;
  return 1;
}

/* 12.2.4.41 */
function h5StateAfterAttributeValueQuotedState(hs) {
  if (hs.pos >= hs.len) return 0;
  const ch = hs.s.charCodeAt(hs.pos);
  if (h5IsWhite(ch)) {
    hs.pos += 1;
    return h5StateBeforeAttributeName(hs);
  } else if (ch === CH_SLASH) {
    hs.pos += 1;
    return h5StateSelfClosingStartTag(hs);
  } else if (ch === CH_GT) {
    hs.tokenStart = hs.pos;
    hs.tokenLen = 1;
    hs.tokenType = H5_TAG_NAME_CLOSE;
    hs.pos += 1;
    hs.state = h5StateData;
    return 1;
  }
  return h5StateBeforeAttributeName(hs);
}

/* 12.2.4.43 */
function h5StateSelfClosingStartTag(hs) {
  if (hs.pos >= hs.len) return 0;
  const ch = hs.s.charCodeAt(hs.pos);
  if (ch === CH_GT) {
    hs.tokenStart = hs.pos - 1;
    hs.tokenLen = 2;
    hs.tokenType = H5_TAG_NAME_SELFCLOSE;
    hs.state = h5StateData;
    hs.pos += 1;
    return 1;
  }
  return h5StateBeforeAttributeName(hs);
}

/* 12.2.4.44 */
function h5StateBogusComment(hs) {
  const idx = memchr(hs.s, hs.pos, hs.len - hs.pos, '>');
  if (idx === -1) {
    hs.tokenStart = hs.pos;
    hs.tokenLen = hs.len - hs.pos;
    hs.pos = hs.len;
    hs.state = h5StateEof;
  } else {
    hs.tokenStart = hs.pos;
    hs.tokenLen = idx - hs.pos;
    hs.pos = idx + 1;
    hs.state = h5StateData;
  }
  hs.tokenType = H5_TAG_COMMENT;
  return 1;
}

/* 12.2.4.44 ALT */
function h5StateBogusComment2(hs) {
  let pos = hs.pos;
  for (;;) {
    const idx = memchr(hs.s, pos, hs.len - pos, '%');
    if (idx === -1 || idx + 1 >= hs.len) {
      hs.tokenStart = hs.pos;
      hs.tokenLen = hs.len - hs.pos;
      hs.pos = hs.len;
      hs.tokenType = H5_TAG_COMMENT;
      hs.state = h5StateEof;
      return 1;
    }
    if (hs.s.charCodeAt(idx + 1) !== CH_GT) {
      pos = idx + 1;
      continue;
    }
    /* ends in %> */
    hs.tokenStart = hs.pos;
    hs.tokenLen = idx - hs.pos;
    hs.pos = idx + 2;
    hs.state = h5StateData;
    hs.tokenType = H5_TAG_COMMENT;
    return 1;
  }
}

/* 8.2.4.45 */
function h5StateMarkupDeclarationOpen(hs) {
  const { s, pos } = hs;
  const remaining = hs.len - pos;
  if (remaining >= 7 &&
      /* case insensitive */
      (s[pos] === 'D' || s[pos] === 'd') &&
      (s[pos + 1] === 'O' || s[pos + 1] === 'o') &&
      (s[pos + 2] === 'C' || s[pos + 2] === 'c') &&
      (s[pos + 3] === 'T' || s[pos + 3] === 't') &&
      (s[pos + 4] === 'Y' || s[pos + 4] === 'y') &&
      (s[pos + 5] === 'P' || s[pos + 5] === 'p') &&
      (s[pos + 6] === 'E' || s[pos + 6] === 'e')) {
    return h5StateDoctype(hs);
  } else if (remaining >= 7 && s.startsWith('[CDATA[', pos) /* upper case required */) {
    hs.pos += 7;
    return h5StateCdata(hs);
  } else if (remaining >= 2 && s[pos] === '-' && s[pos + 1] === '-') {
    hs.pos += 2;
    return h5StateComment(hs);
  }
  return h5StateBogusComment(hs);
}

/*
 * 12.2.4.48 - 12.2.4.51: comments end by EOF, "-->" or "-!>"
 * (NUL bytes between the first dash and the second char are skipped).
 */
function h5StateComment(hs) {
  const { s } = hs;
  const end = hs.len;
  let pos = hs.pos;
  for (;;) {
    const idx = memchr(s, pos, hs.len - pos, '-');

    /* did not find anything or has less than 3 chars left */
    if (idx === -1 || idx > hs.len - 3) {
      hs.state = h5StateEof;
      hs.tokenStart = hs.pos;
      hs.tokenLen = hs.len - hs.pos;
      hs.tokenType = H5_TAG_COMMENT;
      return 1;
    }
    let offset = 1;

    /* skip all nulls */
    while (idx + offset < end && s.charCodeAt(idx + offset) === 0) offset += 1;
    if (idx + offset === end) {
      hs.state = h5StateEof;
      hs.tokenStart = hs.pos;
      hs.tokenLen = hs.len - hs.pos;
      hs.tokenType = H5_TAG_COMMENT;
      return 1;
    }

    let ch = s.charCodeAt(idx + offset);
    if (ch !== CH_DASH && ch !== CH_BANG) {
      pos = idx + 1;
      continue;
    }

    offset += 1;
    if (idx + offset === end) {
      hs.state = h5StateEof;
      hs.tokenStart = hs.pos;
      hs.tokenLen = hs.len - hs.pos;
      hs.tokenType = H5_TAG_COMMENT;
      return 1;
    }

    ch = s.charCodeAt(idx + offset);
    if (ch !== CH_GT) {
      pos = idx + 1;
      continue;
    }
    offset += 1;

    /* ends in --> or -!> */
    hs.tokenStart = hs.pos;
    hs.tokenLen = idx - hs.pos;
    hs.pos = idx + offset;
    hs.state = h5StateData;
    hs.tokenType = H5_TAG_COMMENT;
    return 1;
  }
}

function h5StateCdata(hs) {
  const { s } = hs;
  let pos = hs.pos;
  for (;;) {
    const idx = memchr(s, pos, hs.len - pos, ']');

    /* did not find anything or has less than 3 chars left */
    if (idx === -1 || idx > hs.len - 3) {
      hs.state = h5StateEof;
      hs.tokenStart = hs.pos;
      hs.tokenLen = hs.len - hs.pos;
      hs.tokenType = H5_DATA_TEXT;
      return 1;
    } else if (s.charCodeAt(idx + 1) === CH_RIGHTB && s.charCodeAt(idx + 2) === CH_GT) {
      hs.state = h5StateData;
      hs.tokenStart = hs.pos;
      hs.tokenLen = idx - hs.pos;
      hs.pos = idx + 3;
      hs.tokenType = H5_DATA_TEXT;
      return 1;
    } else {
      pos = idx + 1;
    }
  }
}

/* 8.2.4.52 */
function h5StateDoctype(hs) {
  hs.tokenStart = hs.pos;
  hs.tokenType = H5_DOCTYPE;
  const idx = memchr(hs.s, hs.pos, hs.len - hs.pos, '>');
  if (idx === -1) {
    hs.state = h5StateEof;
    hs.tokenLen = hs.len - hs.pos;
  } else {
    hs.state = h5StateData;
    hs.tokenLen = idx - hs.pos;
    hs.pos = idx + 1;
  }
  return 1;
}

/* ========================================================================== */
/* XSS                                                                        */
/* ========================================================================== */

const ATTR_TYPE_NONE = 0;
const ATTR_TYPE_BLACK = 1; /* ban always */
const ATTR_TYPE_ATTR_URL = 2; /* attribute value takes a URL-like object */
const ATTR_TYPE_STYLE = 3;
const ATTR_TYPE_ATTR_INDIRECT = 4; /* attribute *name* is given in *value* */

const ATTR_TYPES = {
  TYPE_NONE: ATTR_TYPE_NONE,
  TYPE_BLACK: ATTR_TYPE_BLACK,
  TYPE_ATTR_URL: ATTR_TYPE_ATTR_URL,
  TYPE_STYLE: ATTR_TYPE_STYLE,
  TYPE_ATTR_INDIRECT: ATTR_TYPE_ATTR_INDIRECT,
};

const BLACKATTR = XSS_BLACK_ATTRS.map(([name, type]) => {
  if (!(type in ATTR_TYPES)) throw new Error(`libinjection: unknown attribute type ${type}`);
  return [name, ATTR_TYPES[type]];
});

/** gsHexDecodeMap: hex digit value, 256 for "not a hex digit" */
function hexDecode(ch) {
  if (ch >= 0x30 && ch <= 0x39) return ch - 0x30;
  if (ch >= 0x41 && ch <= 0x46) return ch - 0x41 + 10;
  if (ch >= 0x61 && ch <= 0x66) return ch - 0x61 + 10;
  return 256;
}

/**
 * html_decode_char_at(): decodes one (numeric entity) character at s[pos].
 * Sets HTML_CONSUMED[0] to the number of input bytes consumed.
 * @returns {number} decoded character code, or -1
 */
const HTML_CONSUMED = [0];
function htmlDecodeCharAt(s, pos, len) {
  if (len === 0) {
    HTML_CONSUMED[0] = 0;
    return -1;
  }
  HTML_CONSUMED[0] = 1;
  const c0 = s.charCodeAt(pos);
  if (c0 !== 0x26 /* & */ || len < 3) return c0;
  const isHex = s[pos + 2] === 'x' || s[pos + 2] === 'X';
  if (isHex && len < 4) return c0;

  /* not '&#': we don't handle named entities here */
  if (s[pos + 1] !== '#') return 0x26;

  let val;
  let i;
  if (isHex) {
    let ch = hexDecode(s.charCodeAt(pos + 3));
    if (ch === 256) return 0x26; /* degenerate case '&#[?]' */
    val = ch;
    i = 4;
    while (i < len) {
      ch = s.charCodeAt(pos + i);
      if (ch === 0x3b /* ; */) {
        HTML_CONSUMED[0] = i + 1;
        return val;
      }
      ch = hexDecode(ch);
      if (ch === 256) {
        HTML_CONSUMED[0] = i;
        return val;
      }
      val = val * 16 + ch;
      if (val > 0x1000ff) return 0x26;
      ++i;
    }
    HTML_CONSUMED[0] = i;
    return val;
  }
  i = 2;
  let ch = s.charCodeAt(pos + i);
  if (ch < 0x30 || ch > 0x39) return 0x26;
  val = ch - 0x30;
  i += 1;
  while (i < len) {
    ch = s.charCodeAt(pos + i);
    if (ch === 0x3b) {
      HTML_CONSUMED[0] = i + 1;
      return val;
    }
    if (ch < 0x30 || ch > 0x39) {
      HTML_CONSUMED[0] = i;
      return val;
    }
    val = val * 10 + (ch - 0x30);
    if (val > 0x1000ff) return 0x26;
    ++i;
  }
  HTML_CONSUMED[0] = i;
  return val;
}

/**
 * cstrcasecmp_with_null(a, b, n): compare upper case `a` with b[pos, pos+n),
 * ignoring NUL bytes in b and ASCII case. Returns 0 on match.
 */
function cstrcasecmpWithNull(a, s, pos, n) {
  let ai = 0;
  for (let bi = 0; bi < n; bi++) {
    let cb = s.charCodeAt(pos + bi);
    if (cb === 0) continue;
    const ca = ai < a.length ? a.charCodeAt(ai) : 0;
    ai++;
    if (cb >= 0x61 && cb <= 0x7a) cb -= 0x20;
    if (ca !== cb) return 1;
  }
  return ai === a.length ? 0 : 1;
}

/**
 * htmlencode_startswith(a, b, n): does the HTML encoded byte string b[pos, pos+n)
 * start with the upper case prefix a (case insensitive, ignoring NULs, newlines
 * and leading whitespace / control chars)?
 */
function htmlencodeStartswith(a, s, pos, n) {
  let ai = 0;
  let first = true;
  while (n > 0) {
    if (ai === a.length) return 1;
    let cb = htmlDecodeCharAt(s, pos, n);
    const consumed = HTML_CONSUMED[0];
    pos += consumed;
    n -= consumed;

    if (first && cb <= 32) continue; /* ignore all leading whitespace and control characters */
    first = false;

    if (cb === 0) continue; /* always ignore null characters in user input */
    if (cb === 10) continue; /* always ignore vertical tab characters in user input */

    if (cb >= 0x61 && cb <= 0x7a) cb -= 0x20; /* upcase */

    if (a.charCodeAt(ai) !== (cb & 0xff) /* (char)cb */) return 0;
    ai++;
  }
  return ai === a.length ? 1 : 0;
}

function isBlackTag(s, pos, len) {
  if (len < 3) return 0;
  for (const black of XSS_BLACK_TAGS) {
    if (cstrcasecmpWithNull(black, s, pos, len) === 0) return 1;
  }
  const c0 = s[pos];
  const c1 = s[pos + 1];
  const c2 = s[pos + 2];
  /* anything SVG related */
  if ((c0 === 's' || c0 === 'S') && (c1 === 'v' || c1 === 'V') && (c2 === 'g' || c2 === 'G')) return 1;
  /* Anything XSL(t) related */
  if ((c0 === 'x' || c0 === 'X') && (c1 === 's' || c1 === 'S') && (c2 === 'l' || c2 === 'L')) return 1;
  return 0;
}

function isBlackAttr(s, pos, len) {
  if (len < 2) return ATTR_TYPE_NONE;

  if (len >= 5) {
    /* JavaScript on.* event handlers */
    const c0 = s[pos];
    const c1 = s[pos + 1];
    if ((c0 === 'o' || c0 === 'O') && (c1 === 'n' || c1 === 'N')) {
      const withoutOnLen = len - 2;
      for (const name of XSS_BLACK_ATTR_EVENTS) {
        const maxLen = withoutOnLen < name.length ? withoutOnLen : name.length;
        if (cstrcasecmpWithNull(name, s, pos + 2, maxLen) === 0) return ATTR_TYPE_BLACK;
      }
    }

    /* XMLNS can be used to create arbitrary tags */
    if (cstrcasecmpWithNull('XMLNS', s, pos, 5) === 0 || cstrcasecmpWithNull('XLINK', s, pos, 5) === 0) {
      return ATTR_TYPE_BLACK;
    }
  }

  for (const [name, type] of BLACKATTR) {
    if (cstrcasecmpWithNull(name, s, pos, len) === 0) return type;
  }
  return ATTR_TYPE_NONE;
}

function isBlackUrl(s, pos, len) {
  /* skip whitespace, control chars and (signed char) high-bit bytes */
  while (len > 0) {
    const c = s.charCodeAt(pos);
    if (!(c <= 32 || c >= 127)) break;
    ++pos;
    --len;
  }
  if (htmlencodeStartswith('DATA', s, pos, len)) return 1;
  if (htmlencodeStartswith('VIEW-SOURCE', s, pos, len)) return 1;
  /* covers JAVA, JAVASCRIPT, + colon */
  if (htmlencodeStartswith('JAVA', s, pos, len)) return 1;
  /* obsolete but interesting signal */
  if (htmlencodeStartswith('VBSCRIPT', s, pos, len)) return 1;
  return 0;
}

/**
 * libinjection_is_xss(): XSS check in one HTML5 starting context.
 * @param {string} s byte string
 * @param {number} flags H5_DATA_STATE / H5_VALUE_*
 * @returns {number} 1 = XSS, 0 = benign, -1 = parser error
 */
export function libinjection_is_xss(s, flags) {
  const h5 = new H5State(s, flags);
  let attr = ATTR_TYPE_NONE;
  let parserResult;

  while ((parserResult = libinjection_h5_next(h5)) === 1) {
    const type = h5.tokenType;
    if (type !== H5_ATTR_VALUE) attr = ATTR_TYPE_NONE;

    if (type === H5_DOCTYPE) {
      return 1;
    } else if (type === H5_TAG_NAME_OPEN) {
      if (isBlackTag(s, h5.tokenStart, h5.tokenLen)) return 1;
    } else if (type === H5_ATTR_NAME) {
      attr = isBlackAttr(s, h5.tokenStart, h5.tokenLen);
    } else if (type === H5_ATTR_VALUE) {
      switch (attr) {
        case ATTR_TYPE_NONE:
          break;
        case ATTR_TYPE_BLACK:
          return 1;
        case ATTR_TYPE_ATTR_URL:
          if (isBlackUrl(s, h5.tokenStart, h5.tokenLen)) return 1;
          break;
        case ATTR_TYPE_STYLE:
          return 1;
        case ATTR_TYPE_ATTR_INDIRECT:
          /* an attribute name is specified in a _value_ */
          if (isBlackAttr(s, h5.tokenStart, h5.tokenLen)) return 1;
          break;
        default:
          break;
      }
      attr = ATTR_TYPE_NONE;
    } else if (type === H5_TAG_COMMENT) {
      const start = h5.tokenStart;
      const tlen = h5.tokenLen;
      /* IE uses a "`" as a tag ending char */
      if (memchr(s, start, tlen, '`') !== -1) return 1;

      /* IE conditional comment */
      if (tlen > 3) {
        const c0 = s[start];
        const c1 = s[start + 1];
        const c2 = s[start + 2];
        if (c0 === '[' && (c1 === 'i' || c1 === 'I') && (c2 === 'f' || c2 === 'F')) return 1;
        if ((c0 === 'x' || c0 === 'X') && (c1 === 'm' || c1 === 'M') && (c2 === 'l' || c2 === 'L')) return 1;
      }

      if (tlen > 5) {
        /* IE <?import pseudo-tag */
        if (cstrcasecmpWithNull('IMPORT', s, start, 6) === 0) return 1;
        /* XML Entity definition */
        if (cstrcasecmpWithNull('ENTITY', s, start, 6) === 0) return 1;
      }
    }
  }
  return parserResult;
}

/**
 * libinjection_xss(): XSS check in all five HTML5 contexts.
 * @param {string} s byte string
 * @returns {number} 1 = XSS, 0 = benign, -1 = parser error
 */
export function libinjection_xss(s) {
  let result;
  if ((result = libinjection_is_xss(s, H5_DATA_STATE)) !== 0) return result;
  if ((result = libinjection_is_xss(s, H5_VALUE_NO_QUOTE)) !== 0) return result;
  if ((result = libinjection_is_xss(s, H5_VALUE_SINGLE_QUOTE)) !== 0) return result;
  if ((result = libinjection_is_xss(s, H5_VALUE_DOUBLE_QUOTE)) !== 0) return result;
  if ((result = libinjection_is_xss(s, H5_VALUE_BACK_QUOTE)) !== 0) return result;
  return 0;
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

const NON_BYTE_RE = /[^\x00-\xff]/;
const utf8Encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;

/**
 * Safety net: inputs must be byte strings. A string containing chars > 0xFF
 * cannot be one, so it is UTF-8 encoded first.
 * @param {string} input
 */
function toByteString(input) {
  const s = typeof input === 'string' ? input : String(input ?? '');
  if (!NON_BYTE_RE.test(s) || !utf8Encoder) return s;
  const bytes = utf8Encoder.encode(s);
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return out;
}

/**
 * libinjection_sqli(s, len, fingerprint): SQLi detection with the default
 * contexts (as-is, single quote, double quote; ANSI and MySQL comments).
 * @param {string} input byte string
 * @returns {{isSqli: boolean, fingerprint: string}} fingerprint is '' when not SQLi
 */
export function detectSQLi(input) {
  const s = toByteString(input);
  const state = new SqliState(s, 0);
  const isSqli = libinjection_is_sqli(state);
  return { isSqli, fingerprint: isSqli ? state.fingerprint : '' };
}

/**
 * libinjection_xss(s, len): XSS detection. A parser error (never expected; the
 * C API returns -1 for it) is reported as a detection, like any non-zero result.
 * @param {string} input byte string
 * @returns {boolean}
 */
export function detectXSS(input) {
  return libinjection_xss(toByteString(input)) !== 0;
}

/**
 * Debug helper: SQLi tokens like the upstream testdriver ("tokens" test type),
 * tokenizing with FLAG_QUOTE_NONE | FLAG_SQL_ANSI unless flags are given.
 * @param {string} input byte string
 * @param {number} [flags]
 * @returns {SqliToken[]} copies of the tokens
 */
export function sqliTokenize(input, flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI) {
  const sf = new SqliState(toByteString(input), flags);
  const out = [];
  while (libinjection_sqli_tokenize(sf)) {
    const t = new SqliToken();
    stCopy(t, sf.current);
    out.push(t);
  }
  return out;
}

/**
 * Debug helper: folded SQLi tokens ("folding" test type).
 * @param {string} input byte string
 * @param {number} [flags]
 * @returns {SqliToken[]} copies of the folded tokens
 */
export function sqliFold(input, flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI) {
  const sf = new SqliState(toByteString(input), flags);
  const n = libinjection_sqli_fold(sf);
  const out = [];
  for (let i = 0; i < n; i++) {
    const t = new SqliToken();
    stCopy(t, sf.tokenvec[i]);
    out.push(t);
  }
  return out;
}

/**
 * Debug helper: fingerprint of the input in one context (libinjection_sqli_fingerprint)
 * and whether that fingerprint is considered SQLi (libinjection_sqli_check_fingerprint).
 * @param {string} input byte string
 * @param {number} [flags]
 * @returns {{fingerprint: string, isSqli: boolean}}
 */
export function sqliFingerprint(input, flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI) {
  const sf = new SqliState(toByteString(input), flags);
  const fingerprint = libinjection_sqli_fingerprint(sf, flags);
  return { fingerprint, isSqli: libinjection_sqli_check_fingerprint(sf) };
}

/**
 * Debug helper: HTML5 tokens of the input ("html5" test type).
 * @param {string} input byte string
 * @param {number} [flags] H5_DATA_STATE (default) or H5_VALUE_*
 * @returns {{type: string, start: number, len: number, value: string}[]}
 */
export function html5Tokenize(input, flags = H5_DATA_STATE) {
  const hs = new H5State(toByteString(input), flags);
  const out = [];
  while (libinjection_h5_next(hs) === 1) {
    out.push({ type: H5_TYPE_NAMES[hs.tokenType], start: hs.tokenStart, len: hs.tokenLen, value: hs.token });
  }
  return out;
}
