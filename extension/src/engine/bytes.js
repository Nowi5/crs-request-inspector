// Byte-string helpers.
//
// ModSecurity works on raw bytes. To reproduce its behaviour, the engine represents
// every value as a "byte string": a JS string whose char codes are all 0..255, one
// char per byte (UTF-8 text is first encoded to bytes). Rule files are read the same
// way, so regexes, phrases and inputs all live in the same byte space, like PCRE in
// non-UTF mode.

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });
const lenientDecoder = new TextDecoder('utf-8');

/** Convert a Uint8Array/ArrayBuffer to a byte string. */
export function bytesToBinary(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return out;
}

/** Convert a byte string to a Uint8Array. */
export function binaryToBytes(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/** Encode a normal (unicode) JS string as UTF-8 bytes -> byte string. */
export function utf8ToBinary(str) {
  if (str == null) return '';
  str = String(str);
  // Fast path: pure ASCII.
  if (!/[^\x00-\x7f]/.test(str)) return str;
  return bytesToBinary(encoder.encode(str));
}

/** Decode a byte string as UTF-8 for display. Invalid sequences become U+FFFD. */
export function binaryToUtf8(bin, { strict = false } = {}) {
  if (bin == null) return '';
  if (!/[^\x00-\x7f]/.test(bin)) return bin;
  const bytes = binaryToBytes(bin);
  if (strict) return strictDecoder.decode(bytes);
  return lenientDecoder.decode(bytes);
}

/** True when the byte string is valid UTF-8. */
export function isValidUtf8(bin) {
  try {
    binaryToUtf8(bin, { strict: true });
    return true;
  } catch {
    return false;
  }
}

/** Base64 (standard alphabet) -> byte string; returns '' on failure. */
export function base64ToBinary(b64) {
  try {
    return atob(String(b64).replace(/\s+/g, ''));
  } catch {
    return '';
  }
}

/** Byte string -> printable representation for UI (UTF-8 decode, escape control chars). */
export function displayBinary(bin, max = Infinity) {
  let s = binaryToUtf8(bin);
  if (s.length > max) s = s.slice(0, max) + '…';
  return s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

export const isHex = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
export const hexVal = (c) => (c <= 57 ? c - 48 : (c | 0x20) - 87);
/** ModSecurity's isspace(): space, \t, \n, \v, \f, \r */
export const isSpace = (c) => c === 32 || (c >= 9 && c <= 13);

/** ASCII-only lowercase (C tolower in the "C" locale). */
export function asciiLower(s) {
  if (!/[A-Z]/.test(s)) return s;
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

export function asciiUpper(s) {
  if (!/[a-z]/.test(s)) return s;
  return s.replace(/[a-z]+/g, (m) => m.toUpperCase());
}

/** C atoi(): optional leading whitespace, optional sign, digits; anything else -> stops. */
export function atoi(s) {
  const m = /^[\t\n\v\f\r ]*([+-]?\d+)/.exec(String(s));
  return m ? parseInt(m[1], 10) : 0;
}
