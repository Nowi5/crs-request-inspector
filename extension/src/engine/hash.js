// Synchronous SHA-1 and MD5 over byte strings (WebCrypto is async, transformations are not).
// Both return the raw digest as a byte string, like ModSecurity's t:sha1 / t:md5.

function toWords(s, bigEndian) {
  const n = s.length;
  const words = new Array((((n + 8) >> 6) + 1) * 16).fill(0);
  for (let i = 0; i < n; i++) {
    const shift = bigEndian ? 24 - (i % 4) * 8 : (i % 4) * 8;
    words[i >> 2] |= (s.charCodeAt(i) & 0xff) << shift;
  }
  const shift = bigEndian ? 24 - (n % 4) * 8 : (n % 4) * 8;
  words[n >> 2] |= 0x80 << shift;
  const bitLen = n * 8;
  if (bigEndian) {
    words[words.length - 1] = bitLen >>> 0;
    words[words.length - 2] = Math.floor(bitLen / 0x100000000);
  } else {
    words[words.length - 2] = bitLen >>> 0;
    words[words.length - 1] = Math.floor(bitLen / 0x100000000);
  }
  return words;
}

function wordsToBinary(words, bigEndian) {
  let out = '';
  for (const w of words) {
    for (let b = 0; b < 4; b++) {
      const shift = bigEndian ? 24 - b * 8 : b * 8;
      out += String.fromCharCode((w >>> shift) & 0xff);
    }
  }
  return out;
}

const rol = (x, n) => (x << n) | (x >>> (32 - n));

export function sha1Binary(s) {
  const w = toWords(s, true);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const W = new Int32Array(80);
  for (let blk = 0; blk < w.length; blk += 16) {
    for (let t = 0; t < 16; t++) W[t] = w[blk + t];
    for (let t = 16; t < 80; t++) W[t] = rol(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const tmp = (rol(a, 5) + f + e + k + W[t]) | 0;
      e = d; d = c; c = rol(b, 30); b = a; a = tmp;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  return wordsToBinary([h0, h1, h2, h3, h4], true);
}

const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) | 0);

export function md5Binary(s) {
  const w = toWords(s, false);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  for (let blk = 0; blk < w.length; blk += 16) {
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c;
      c = b;
      b = (b + rol((a + f + MD5_K[i] + w[blk + g]) | 0, MD5_S[i])) | 0;
      a = tmp;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  return wordsToBinary([a0, b0, c0, d0], false);
}
