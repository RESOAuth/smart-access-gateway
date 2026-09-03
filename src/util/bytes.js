// Byte, base64url, and constant-time helpers. No dependencies beyond Web APIs.

const TE = new TextEncoder();
const TD = new TextDecoder();

export const utf8 = (s) => TE.encode(s);
export const fromUtf8 = (b) => TD.decode(b);

const B64_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Encode bytes as base64url without padding. */
export function b64u(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    // eslint-disable-next-line security/detect-object-injection -- integer index into Uint8Array
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64_ALPHA[b0 >> 2];
    out += B64_ALPHA[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += B64_ALPHA[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += B64_ALPHA[b2 & 63];
  }
  return out.replaceAll('+', '-').replaceAll('/', '_');
}

/** Decode base64url (padding optional) to bytes. Throws on invalid input. */
export function unb64u(str) {
  if (typeof str !== 'string') throw new TypeError('expected string');
  const norm = str.replaceAll('-', '+').replaceAll('_', '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(norm)) throw new Error('invalid base64url');
  const out = new Uint8Array(Math.floor((norm.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of norm) {
    acc = (acc << 6) | B64_ALPHA.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

export const b64uText = (s) => b64u(utf8(s));
export const unb64uText = (s) => fromUtf8(unb64u(s));
export const b64uJson = (o) => b64uText(JSON.stringify(o));
export const unb64uJson = (s) => JSON.parse(unb64uText(s));

/** Standard base64 (padded) - needed for HTTP Basic and some provider APIs. */
export function b64(input) {
  const s = b64u(input).replaceAll('-', '+').replaceAll('_', '/');
  return s + '='.repeat((4 - (s.length % 4)) % 4);
}
export function unb64(str) {
  return unb64u(str.replaceAll('+', '-').replaceAll('/', '_'));
}
export const b64Text = (s) => b64(utf8(s));

export function concat(...parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** URL-safe random token of roughly `n` bytes of entropy. */
export const randomToken = (n = 32) => b64u(randomBytes(n));

/** Constant-time comparison of two byte arrays or two strings. */
export function timingSafeEqual(a, b) {
  const ba = typeof a === 'string' ? utf8(a) : a;
  const bb = typeof b === 'string' ? utf8(b) : b;
  // Length is not secret in our uses, but keep the loop fixed-cost anyway.
  let diff = ba.length ^ bb.length;
  const n = Math.max(ba.length, bb.length);
  // eslint-disable-next-line security/detect-object-injection -- integer index into Uint8Array
  for (let i = 0; i < n; i++) diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) throw new Error('invalid hex');
  const out = new Uint8Array(clean.length / 2);
  // eslint-disable-next-line security/detect-object-injection -- integer index into Uint8Array
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);
