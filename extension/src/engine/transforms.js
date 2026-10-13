// ModSecurity transformation functions (t:...), ported from ModSecurity v2 (msre_tfns.c)
// semantics. All functions take and return byte strings (see bytes.js).

import { isHex, hexVal, isSpace, asciiLower, asciiUpper } from './bytes.js';
import { sha1Binary, md5Binary } from './hash.js';
import { UNICODE_MAP } from './unicode-map.js';

const NBSP = 0xa0;
const x2c = (s, i) => (hexVal(s.charCodeAt(i)) << 4) | hexVal(s.charCodeAt(i + 1));
const isOctal = (c) => c >= 48 && c <= 55;
const isDigit = (c) => c >= 48 && c <= 57;
const isAlnum = (c) => isDigit(c) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);

function fullWidth(s, hiIndex, lowByte) {
  // Full width ASCII (U+FF01 - U+FF5E) needs 0x20 added to the low byte.
  const a = s[hiIndex], b = s[hiIndex + 1];
  if (lowByte > 0x00 && lowByte < 0x5f && (a === 'f' || a === 'F') && (b === 'f' || b === 'F')) return lowByte + 0x20;
  return lowByte;
}

function urlDecode(s) {
  if (s.indexOf('%') < 0 && s.indexOf('+') < 0) return s;
  let out = '';
  const n = s.length;
  for (let i = 0; i < n; ) {
    const c = s.charCodeAt(i);
    if (c === 37 /* % */ && i + 2 < n && isHex(s.charCodeAt(i + 1)) && isHex(s.charCodeAt(i + 2))) {
      out += String.fromCharCode(x2c(s, i + 1));
      i += 3;
    } else if (c === 43 /* + */) {
      out += ' ';
      i++;
    } else {
      out += s[i++];
    }
  }
  return out;
}

function urlDecodeUni(s) {
  if (s.indexOf('%') < 0 && s.indexOf('+') < 0) return s;
  let out = '';
  const n = s.length;
  for (let i = 0; i < n; ) {
    const c = s.charCodeAt(i);
    if (c === 37) {
      const c1 = s.charCodeAt(i + 1);
      if ((c1 === 117 || c1 === 85) /* u U */) {
        if (i + 5 < n && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3)) && isHex(s.charCodeAt(i + 4)) && isHex(s.charCodeAt(i + 5))) {
          // SecUnicodeMapFile unicode.mapping 20127: best-fit mapping, else the low byte.
          const code = parseInt(s.slice(i + 2, i + 6), 16);
          const mapped = UNICODE_MAP.get(code);
          out += String.fromCharCode(mapped !== undefined ? mapped : fullWidth(s, i + 2, x2c(s, i + 4)));
          i += 6;
        } else {
          out += '%';
          i++;
        }
      } else if (i + 2 < n && isHex(c1) && isHex(s.charCodeAt(i + 2))) {
        out += String.fromCharCode(x2c(s, i + 1));
        i += 3;
      } else {
        out += '%';
        i++;
      }
    } else if (c === 43) {
      out += ' ';
      i++;
    } else {
      out += s[i++];
    }
  }
  return out;
}

const ENTITIES = { quot: '"', amp: '&', lt: '<', gt: '>', nbsp: '\xa0' };

function htmlEntityDecode(s) {
  if (s.indexOf('&') < 0) return s;
  let out = '';
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (s.charCodeAt(i) === 38 /* & */ && i + 1 < n) {
      let j = i + 1;
      if (s[j] === '#') {
        j++;
        if (j < n && (s[j] === 'x' || s[j] === 'X')) {
          j++;
          const k = j;
          while (j < n && isHex(s.charCodeAt(j))) j++;
          if (j > k) {
            out += String.fromCharCode(parseInt(s.slice(k, j).slice(-8), 16) & 0xff);
            if (j < n && s[j] === ';') j++;
            i = j;
            continue;
          }
        } else {
          const k = j;
          while (j < n && isDigit(s.charCodeAt(j))) j++;
          if (j > k) {
            out += String.fromCharCode(parseInt(s.slice(k, j).slice(-10), 10) & 0xff);
            if (j < n && s[j] === ';') j++;
            i = j;
            continue;
          }
        }
      } else {
        const k = j;
        while (j < n && isAlnum(s.charCodeAt(j))) j++;
        if (j > k) {
          const name = s.slice(k, j).toLowerCase();
          const rep = ENTITIES[name];
          if (rep !== undefined) {
            out += rep;
            if (j < n && s[j] === ';') j++;
            i = j;
            continue;
          }
        }
      }
    }
    out += s[i++];
  }
  return out;
}

function jsDecode(s) {
  if (s.indexOf('\\') < 0) return s;
  let out = '';
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (s.charCodeAt(i) === 92 /* \ */) {
      const c1 = s[i + 1];
      if (i + 5 < n && c1 === 'u' && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3)) && isHex(s.charCodeAt(i + 4)) && isHex(s.charCodeAt(i + 5))) {
        out += String.fromCharCode(fullWidth(s, i + 2, x2c(s, i + 4)));
        i += 6;
      } else if (i + 3 < n && c1 === 'x' && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3))) {
        out += String.fromCharCode(x2c(s, i + 2));
        i += 4;
      } else if (i + 1 < n && isOctal(s.charCodeAt(i + 1))) {
        let j = 0;
        let buf = '';
        while (i + 1 + j < n && j < 3 && isOctal(s.charCodeAt(i + 1 + j))) {
          buf += s[i + 1 + j];
          j++;
        }
        if (j === 3 && buf.charCodeAt(0) > 51 /* '3' */) {
          buf = buf.slice(0, 2);
          j = 2;
        }
        out += String.fromCharCode(parseInt(buf, 8) & 0xff);
        i += 1 + j;
      } else if (i + 1 < n) {
        const map = { a: '\x07', b: '\x08', f: '\x0c', n: '\x0a', r: '\x0d', t: '\x09', v: '\x0b' };
        out += map[c1] ?? c1;
        i += 2;
      } else {
        out += '\\';
        i++;
      }
    } else {
      out += s[i++];
    }
  }
  return out;
}

function cssDecode(s) {
  if (s.indexOf('\\') < 0) return s;
  let out = '';
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (s.charCodeAt(i) === 92) {
      if (i + 1 < n) {
        i++;
        let j = 0;
        while (j < 6 && i + j < n && isHex(s.charCodeAt(i + j))) j++;
        if (j > 0) {
          let c;
          let fullcheck = false;
          switch (j) {
            case 1:
              c = hexVal(s.charCodeAt(i));
              break;
            case 2:
            case 3:
              c = x2c(s, i + j - 2);
              break;
            case 4:
              c = x2c(s, i + j - 2);
              fullcheck = true;
              break;
            case 5:
              c = x2c(s, i + j - 2);
              if (s[i] === '0') fullcheck = true;
              break;
            case 6:
              c = x2c(s, i + j - 2);
              if (s[i] === '0' && s[i + 1] === '0') fullcheck = true;
              break;
          }
          if (fullcheck && c > 0x00 && c < 0x5f && (s[i + j - 3] === 'f' || s[i + j - 3] === 'F') && (s[i + j - 4] === 'f' || s[i + j - 4] === 'F')) c += 0x20;
          out += String.fromCharCode(c);
          i += j;
          if (i < n && isSpace(s.charCodeAt(i))) i++;
        } else if (s[i] === '\n') {
          i++;
        } else {
          out += s[i++];
        }
      } else {
        i++; // trailing backslash is dropped
      }
    } else {
      out += s[i++];
    }
  }
  return out;
}

function cmdLine(s) {
  let out = '';
  let space = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    switch (ch) {
      case '"':
      case "'":
      case '\\':
      case '^':
        break;
      case ' ':
      case ',':
      case ';':
      case '\t':
      case '\r':
      case '\n':
        if (!space) {
          out += ' ';
          space = true;
        }
        break;
      case '/':
      case '(':
        if (space) out = out.slice(0, -1);
        space = false;
        out += ch;
        break;
      default:
        out += asciiLower(ch);
        space = false;
    }
  }
  return out;
}

function compressWhitespace(s) {
  let out = '';
  let inWs = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (isSpace(c) || c === NBSP) {
      if (!inWs) out += ' ';
      inWs = true;
    } else {
      out += s[i];
      inWs = false;
    }
  }
  return out;
}

function removeWhitespace(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!(isSpace(c) || c === NBSP)) out += s[i];
  }
  return out;
}

function replaceComments(s) {
  if (s.indexOf('/*') < 0) return s;
  let out = '';
  let inComment = false;
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (!inComment) {
      if (s[i] === '/' && i + 1 < n && s[i + 1] === '*') {
        inComment = true;
        i += 2;
      } else out += s[i++];
    } else if (s[i] === '*' && i + 1 < n && s[i + 1] === '/') {
      inComment = false;
      i += 2;
      out += ' ';
    } else i++;
  }
  if (inComment) out += ' ';
  return out;
}

function removeComments(s) {
  let out = '';
  let inComment = false;
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (!inComment) {
      if (s[i] === '/' && i + 1 < n && s[i + 1] === '*') {
        inComment = true;
        i += 2;
      } else if (s[i] === '<' && s.startsWith('<!--', i)) {
        inComment = true;
        i += 4;
      } else if (s[i] === '-' && i + 1 < n && s[i + 1] === '-') {
        // SQL comment: drop the rest of the input
        break;
      } else if (s[i] === '#') {
        break;
      } else out += s[i++];
    } else if (s[i] === '*' && i + 1 < n && s[i + 1] === '/') {
      inComment = false;
      i += 2;
      out += s[i] ?? '';
      i++;
    } else if (s[i] === '-' && s.startsWith('-->', i)) {
      inComment = false;
      i += 3;
      out += s[i] ?? '';
      i++;
    } else i++;
  }
  if (inComment) out += ' ';
  return out;
}

function removeCommentsChar(s) {
  let out = '';
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (s.startsWith('/*', i) || s.startsWith('*/', i) || s.startsWith('--', i)) {
      if (s.startsWith('-->', i)) i += 3;
      else i += 2;
    } else if (s.startsWith('<!--', i)) i += 4;
    else if (s[i] === '#') i++;
    else out += s[i++];
  }
  return out;
}

function normalizePath(s, win) {
  if (win) s = s.replace(/\\/g, '/');
  if (!s) return s;
  const absolute = s[0] === '/';
  const trailing = s.length > 1 && (s.endsWith('/') || s.endsWith('/.') || s.endsWith('/..'));
  const parts = s.split('/');
  const stack = [];
  for (const p of parts) {
    if (p === '' || p === '.') continue;
    if (p === '..') {
      if (stack.length && stack[stack.length - 1] !== '..') stack.pop();
      else if (!absolute) stack.push('..');
      continue;
    }
    stack.push(p);
  }
  let out = (absolute ? '/' : '') + stack.join('/');
  if (trailing && stack.length) out += '/';
  return out;
}

function utf8toUnicode(s) {
  if (!/[\x80-\xff]/.test(s)) return s;
  let out = '';
  const n = s.length;
  let i = 0;
  const hex = (cp) => '%u' + cp.toString(16).padStart(4, '0');
  while (i < n) {
    const c = s.charCodeAt(i);
    if (c < 0x80) {
      out += s[i++];
      continue;
    }
    const cont = (k) => i + k < n && (s.charCodeAt(i + k) & 0xc0) === 0x80;
    if ((c & 0xe0) === 0xc0 && cont(1)) {
      const cp = ((c & 0x1f) << 6) | (s.charCodeAt(i + 1) & 0x3f);
      out += hex(cp);
      i += 2;
    } else if ((c & 0xf0) === 0xe0 && cont(1) && cont(2)) {
      const cp = ((c & 0x0f) << 12) | ((s.charCodeAt(i + 1) & 0x3f) << 6) | (s.charCodeAt(i + 2) & 0x3f);
      out += hex(cp);
      i += 3;
    } else if ((c & 0xf8) === 0xf0 && cont(1) && cont(2) && cont(3)) {
      const cp = ((c & 0x07) << 18) | ((s.charCodeAt(i + 1) & 0x3f) << 12) | ((s.charCodeAt(i + 2) & 0x3f) << 6) | (s.charCodeAt(i + 3) & 0x3f);
      out += hex(cp);
      i += 4;
    } else {
      out += s[i++];
    }
  }
  return out;
}

function escapeSeqDecode(s) {
  if (s.indexOf('\\') < 0) return s;
  let out = '';
  const n = s.length;
  let i = 0;
  const simple = { a: '\x07', b: '\x08', f: '\x0c', n: '\x0a', r: '\x0d', t: '\x09', v: '\x0b', '\\': '\\', '?': '?', "'": "'", '"': '"' };
  while (i < n) {
    if (s[i] === '\\' && i + 1 < n) {
      const c = s[i + 1];
      if (simple[c] !== undefined) {
        out += simple[c];
        i += 2;
        continue;
      }
      if ((c === 'x' || c === 'X') && i + 3 < n && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3))) {
        out += String.fromCharCode(x2c(s, i + 2));
        i += 4;
        continue;
      }
      if (isOctal(s.charCodeAt(i + 1))) {
        let j = 1;
        while (j < 4 && i + j < n && isOctal(s.charCodeAt(i + j))) j++;
        out += String.fromCharCode(parseInt(s.slice(i + 1, i + j), 8) & 0xff);
        i += j;
        continue;
      }
      out += s[i] + c;
      i += 2;
      continue;
    }
    out += s[i++];
  }
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64MAP = new Int16Array(256).fill(-1);
for (let k = 0; k < 64; k++) B64MAP[B64.charCodeAt(k)] = k;

function base64DecodeCore(s, skipInvalid) {
  let out = '';
  let acc = 0, bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64MAP[s.charCodeAt(i) & 0xff];
    if (v < 0) {
      if (skipInvalid) continue;
      break; // apr_base64_decode stops at the first non-alphabet char (incl. '=')
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((acc >> bits) & 0xff);
    }
  }
  return out;
}

function base64Encode(s) {
  try {
    return btoa(s);
  } catch {
    return '';
  }
}

function hexEncode(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) out += s.charCodeAt(i).toString(16).padStart(2, '0');
  return out;
}

function hexDecode(s) {
  let out = '';
  for (let i = 0; i + 1 < s.length; i += 2) {
    const a = s.charCodeAt(i), b = s.charCodeAt(i + 1);
    out += String.fromCharCode(((isHex(a) ? hexVal(a) : 0) << 4) | (isHex(b) ? hexVal(b) : 0));
  }
  return out;
}

function sqlHexDecode(s) {
  return s.replace(/0x((?:[0-9a-fA-F]{2})+)/g, (_, hex) => hexDecode(hex));
}

function urlEncode(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 32) out += '+';
    else if (isAlnum(c) || c === 42 || c === 45 || c === 46 || c === 95) out += s[i];
    else out += '%' + c.toString(16).padStart(2, '0');
  }
  return out;
}

const trimLeft = (s) => s.replace(/^[\t\n\v\f\r ]+/, '');
const trimRight = (s) => s.replace(/[\t\n\v\f\r ]+$/, '');

function parity(s, mode) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i) & 0x7f;
    if (mode !== 'zero') {
      let bits = 0;
      for (let b = c; b; b >>= 1) bits += b & 1;
      if ((mode === 'even' && bits % 2) || (mode === 'odd' && bits % 2 === 0)) c |= 0x80;
    }
    out += String.fromCharCode(c);
  }
  return out;
}

/** name (lowercase) -> function */
export const TRANSFORMS = {
  none: (s) => s,
  lowercase: asciiLower,
  uppercase: asciiUpper,
  urldecode: urlDecode,
  urldecodeuni: urlDecodeUni,
  urlencode: urlEncode,
  htmlentitydecode: htmlEntityDecode,
  jsdecode: jsDecode,
  cssdecode: cssDecode,
  cmdline: cmdLine,
  compresswhitespace: compressWhitespace,
  removewhitespace: removeWhitespace,
  removenulls: (s) => (s.indexOf('\0') < 0 ? s : s.replace(/\0/g, '')),
  replacenulls: (s) => (s.indexOf('\0') < 0 ? s : s.replace(/\0/g, ' ')),
  replacecomments: replaceComments,
  removecomments: removeComments,
  removecommentschar: removeCommentsChar,
  normalisepath: (s) => normalizePath(s, false),
  normalizepath: (s) => normalizePath(s, false),
  normalisepathwin: (s) => normalizePath(s, true),
  normalizepathwin: (s) => normalizePath(s, true),
  utf8tounicode: utf8toUnicode,
  escapeseqdecode: escapeSeqDecode,
  base64decode: (s) => base64DecodeCore(s, false),
  base64decodeext: (s) => base64DecodeCore(s, true),
  base64encode: base64Encode,
  hexencode: hexEncode,
  hexdecode: hexDecode,
  sqlhexdecode: sqlHexDecode,
  sha1: sha1Binary,
  md5: md5Binary,
  length: (s) => String(s.length),
  trim: (s) => trimRight(trimLeft(s)),
  trimleft: trimLeft,
  trimright: trimRight,
  parityeven7bit: (s) => parity(s, 'even'),
  parityodd7bit: (s) => parity(s, 'odd'),
  parityzero7bit: (s) => parity(s, 'zero'),
};

/** Canonical display names. */
export const TRANSFORM_NAMES = Object.fromEntries(
  [
    'none', 'lowercase', 'uppercase', 'urlDecode', 'urlDecodeUni', 'urlEncode', 'htmlEntityDecode', 'jsDecode', 'cssDecode',
    'cmdLine', 'compressWhitespace', 'removeWhitespace', 'removeNulls', 'replaceNulls', 'replaceComments', 'removeComments',
    'removeCommentsChar', 'normalisePath', 'normalizePath', 'normalisePathWin', 'normalizePathWin', 'utf8toUnicode',
    'escapeSeqDecode', 'base64Decode', 'base64DecodeExt', 'base64Encode', 'hexEncode', 'hexDecode', 'sqlHexDecode', 'sha1',
    'md5', 'length', 'trim', 'trimLeft', 'trimRight', 'parityEven7bit', 'parityOdd7bit', 'parityZero7bit',
  ].map((n) => [n.toLowerCase(), n])
);

export function getTransform(name) {
  return TRANSFORMS[String(name).toLowerCase()] || null;
}
